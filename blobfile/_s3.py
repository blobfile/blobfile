"""AWS S3 backend for general-purpose buckets."""

from __future__ import annotations

import io
import os
import re
import time
from functools import lru_cache
from typing import Any, Callable, Iterator

import urllib3

from blobfile import _common as common
from blobfile._common import Config, DirEntry, Error, RequestFailure, Stat

DEFAULT_WRITE_CHUNK_SIZE = 8 * 2**20


def split_path(path: str) -> tuple[str, str]:
    bucket, _, key = path.removeprefix("s3://").partition("/")
    if not path.startswith("s3://") or not bucket:
        raise Error(f"Invalid S3 path: '{path}'")
    return bucket, key


def combine_path(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def dirname(conf: Config, path: str) -> str:
    bucket, key = split_path(path)
    parent = key.rstrip("/").rpartition("/")[0]
    return combine_path(bucket, parent) if parent else f"s3://{bucket}"


def join_paths(conf: Config, path: str, child: str) -> str:
    bucket, key = split_path(path)
    key = common.path_join(_dir_prefix(key), child).removeprefix("/")
    return combine_path(bucket, key)


@lru_cache(maxsize=32)
def _make_client(conf: Config, pid: int, region: str | None) -> Any:
    # A botocore connection pool must not be shared across a fork.
    try:
        import boto3  # pyright: ignore[reportMissingTypeStubs]
        from botocore.config import Config as AWSConfig  # pyright: ignore[reportMissingTypeStubs]
    except ImportError as exc:
        raise Error("S3 support requires pip install 'blobfile[s3]'") from exc

    retries: dict[str, Any] = {"mode": "standard"}
    if conf.retry_limit is not None:
        retries["max_attempts"] = conf.retry_limit
    return boto3.Session().client(
        "s3",
        region_name=region,
        config=AWSConfig(
            signature_version="s3v4",
            connect_timeout=conf.connect_timeout,
            read_timeout=conf.read_timeout,
            max_pool_connections=conf.connection_pool_max_size,
            retries=retries,
        ),
    )


def _client(conf: Config, region: str | None = None) -> Any:
    return _make_client(conf, os.getpid(), region)


def _call(operation: Callable[..., Any], path: str, **kwargs: Any) -> Any:
    from botocore.exceptions import ClientError  # pyright: ignore[reportMissingTypeStubs]

    try:
        return operation(**kwargs)
    except ClientError as exc:
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        if status == 404:
            raise FileNotFoundError(f"No such file or bucket: '{path}'") from exc
        detail = exc.response["Error"]
        raise RequestFailure(
            exc.operation_name, path, status, detail.get("Code"), detail.get("Message")
        ) from exc


def _make_stat(item: dict[str, Any], size: int) -> Stat:
    timestamp = item["LastModified"].timestamp()
    # SSE-KMS and multipart objects can have ETags unrelated to their content MD5.
    return Stat(size=size, mtime=timestamp, ctime=timestamp, md5=None, version=item["ETag"])


def maybe_stat(conf: Config, path: str) -> Stat | None:
    bucket, key = split_path(path)
    if not key:
        return None
    try:
        item = _call(_client(conf).head_object, path, Bucket=bucket, Key=key)
    except FileNotFoundError:
        return None
    st = _make_stat(item, item["ContentLength"])
    etag = item["ETag"].strip('"')
    if (
        item.get("ServerSideEncryption") in (None, "AES256")
        and "SSECustomerAlgorithm" not in item
        and re.fullmatch("[0-9a-f]{32}", etag)
    ):
        return st._replace(md5=etag)
    return st


def isdir(conf: Config, path: str) -> bool:
    bucket, key = split_path(path)
    try:
        if not key:
            _call(_client(conf).head_bucket, path, Bucket=bucket)
            return True
        page = _call(
            _client(conf).list_objects_v2, path, Bucket=bucket, Prefix=_dir_prefix(key), MaxKeys=1
        )
        return bool(page.get("Contents"))
    except FileNotFoundError:
        return False


def _dir_prefix(key: str) -> str:
    return key if key.endswith("/") else key + "/"


def mkdirfile(conf: Config, path: str) -> None:
    bucket, key = split_path(path)
    if key:
        _call(_client(conf).put_object, path, Bucket=bucket, Key=_dir_prefix(key), Body=b"")
    else:
        _call(_client(conf).head_bucket, path, Bucket=bucket)


def delete_object(conf: Config, path: str) -> None:
    bucket, key = split_path(path)
    _call(_client(conf).delete_object, path, Bucket=bucket, Key=key)


def remove(conf: Config, path: str) -> bool:
    # S3 returns success even if the object being deleted does not exist.
    if maybe_stat(conf, path) is None:
        return False
    delete_object(conf, path)
    return True


def entry_from_dirpath(path: str) -> DirEntry:
    path = path.removesuffix("/")
    _, key = split_path(path)
    return DirEntry(path=path, name=key.rpartition("/")[2], is_dir=True, is_file=False, stat=None)


def entry_from_path_stat(path: str, stat: Stat) -> DirEntry:
    return DirEntry(path=path, name=path.rpartition("/")[2], is_dir=False, is_file=True, stat=stat)


def list_blobs(conf: Config, path: str, delimiter: str | None = None) -> Iterator[DirEntry]:
    bucket, prefix = split_path(path)
    params = {"Bucket": bucket, "Prefix": prefix}
    if delimiter is not None:
        params["Delimiter"] = delimiter
    while True:
        page = _call(_client(conf).list_objects_v2, path, **params)
        for item in page.get("CommonPrefixes", ()):
            yield entry_from_dirpath(combine_path(bucket, item["Prefix"]))
        for item in page.get("Contents", ()):
            obj = combine_path(bucket, item["Key"])
            if obj.endswith("/"):
                yield entry_from_dirpath(obj)
            else:
                yield entry_from_path_stat(obj, _make_stat(item, item["Size"]))
        if not page["IsTruncated"]:
            return
        params["ContinuationToken"] = page["NextContinuationToken"]


class StreamingReadFile(common.BaseStreamingReadFile):
    def __init__(self, conf: Config, path: str, size: int | None):
        if size is None:
            st = maybe_stat(conf, path)
            if st is None:
                raise FileNotFoundError(f"No such file: '{path}'")
            size = st.size
        super().__init__(conf, path, size)

    def _request_chunk(
        self, streaming: bool, start: int, end: int | None = None
    ) -> urllib3.BaseHTTPResponse:
        bucket, key = split_path(self._path)
        try:
            resp = _call(
                _client(self._conf).get_object,
                self._path,
                Bucket=bucket,
                Key=key,
                Range=common.calc_range(start, end),
            )
        except RequestFailure as exc:
            if exc.response_status == 416:
                return urllib3.response.HTTPResponse(status=416)
            raise
        body = resp["Body"]
        if streaming:
            return urllib3.response.HTTPResponse(body=body, preload_content=False, status=206)
        try:
            return urllib3.response.HTTPResponse(body=body.read(), status=206)
        finally:
            body.close()


class StreamingWriteFile(common.BaseStreamingWriteFile):
    def __init__(self, conf: Config, path: str, partial_writes_on_exc: bool):
        self._path = path
        bucket, key = split_path(path)
        self._object = {"Bucket": bucket, "Key": key}
        self._upload_id: str | None = None
        self._parts: list[dict[str, Any]] = []
        super().__init__(conf, conf.s3_write_chunk_size, partial_writes_on_exc)

    def _discard(self) -> None:
        try:
            if self._upload_id is not None:
                _call(
                    _client(self._conf).abort_multipart_upload,
                    self._path,
                    **self._object,
                    UploadId=self._upload_id,
                )
        finally:
            self._buf = bytearray()
            io.BufferedIOBase.close(self)

    def _upload_chunk(self, chunk: memoryview, finalize: bool) -> None:
        try:
            client = _client(self._conf)
            if self._upload_id is None:
                if finalize:
                    _call(client.put_object, self._path, **self._object, Body=bytes(chunk))
                    return
                upload = _call(
                    client.create_multipart_upload,
                    self._path,
                    **self._object,
                    ChecksumAlgorithm="CRC32",
                )
                self._upload_id = upload["UploadId"]

            for offset in range(0, len(chunk), self._chunk_size):
                number = len(self._parts) + 1
                part = _call(
                    client.upload_part,
                    self._path,
                    **self._object,
                    UploadId=self._upload_id,
                    PartNumber=number,
                    ChecksumAlgorithm="CRC32",
                    Body=bytes(chunk[offset : offset + self._chunk_size]),
                )
                self._parts.append(
                    {
                        "PartNumber": number,
                        "ETag": part["ETag"],
                        "ChecksumCRC32": part["ChecksumCRC32"],
                    }
                )
            if finalize:
                _call(
                    client.complete_multipart_upload,
                    self._path,
                    **self._object,
                    UploadId=self._upload_id,
                    MultipartUpload={"Parts": self._parts},
                )
                self._upload_id = None
        except BaseException:
            # Never publish a truncated object if a part or the final commit failed.
            self._discard()
            raise

    def close(self) -> None:
        if not self.closed and self.had_exception and not self.partial_writes_on_exc:
            self._discard()
        else:
            super().close()


def md5(conf: Config, path: str) -> str:
    st = maybe_stat(conf, path)
    if st is None:
        raise FileNotFoundError(f"No such file: '{path}'")
    if st.md5 is not None:
        return st.md5
    with io.BufferedReader(StreamingReadFile(conf, path, st.size), conf.default_buffer_size) as f:
        return common.block_md5(f).hex()


def remote_copy(conf: Config, src: str, dst: str, return_md5: bool) -> str | None:
    src_bucket, src_key = split_path(src)
    dst_bucket, dst_key = split_path(dst)
    _call(
        _client(conf).copy,
        src,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        Bucket=dst_bucket,
        Key=dst_key,
    )
    return md5(conf, dst) if return_md5 else None


def get_url(conf: Config, path: str) -> tuple[str, float]:
    bucket, key = split_path(path)
    # Presigning is local, so it cannot follow S3's cross-region redirects.
    head = _call(_client(conf).head_bucket, path, Bucket=bucket)
    region = head["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region")
    lifetime = 3600
    url = _client(conf, region).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=lifetime
    )
    return url, time.time() + lifetime
