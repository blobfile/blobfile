import threading
import os
import tempfile
import shutil
import hashlib
import base64
import binascii
import io
import functools
from urllib.request import urlopen, Request
import urllib.parse
import urllib.error
import time
import json
import socket

from . import google


DEFAULT_TIMEOUT = 60
HASH_CHUNK_SIZE = 65536
STREAMING_CHUNK_SIZE = 2 ** 20
# https://cloud.google.com/storage/docs/json_api/v1/how-tos/resumable-upload
assert STREAMING_CHUNK_SIZE % (256 * 1024) == 0


def __log_callback(msg):
    print(msg)


# pytest can't figure this out when it's a def
_log_callback = __log_callback


def set_log_callback(fn):
    global _log_callback
    _log_callback = fn


class AccessTokenManager:
    """
    Automatically refresh a google access token when it expires
    """

    def __init__(self, scopes):
        self._scopes = scopes
        self._access_token = None
        self._lock = threading.Lock()
        self._expiration = None

    def get_token(self):
        with self._lock:
            now = time.time()
            if self._expiration is None or now > self._expiration:
                self._access_token = None

            if self._access_token is None:
                req = google.create_access_token_request(self._scopes)
                with _execute_request(req) as resp:
                    assert resp.code == 200
                    result = json.load(resp)
                    self._access_token = result["access_token"]
                    self._expiration = now + result["expires_in"]
        return self._access_token


global_access_token_manager = AccessTokenManager(
    ["https://www.googleapis.com/auth/devstorage.full_control"]
)


def _exponential_sleep_generator(initial, maximum, multiplier=2):
    value = initial
    while True:
        yield value
        value *= multiplier
        if value > maximum:
            value = maximum


def _execute_request(req, retry_codes=(500,), timeout=DEFAULT_TIMEOUT):
    for attempt, backoff in enumerate(_exponential_sleep_generator(1.0, maximum=60.0)):
        err = None
        try:
            return urlopen(req, timeout=timeout)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            err = e
            if isinstance(e, urllib.error.HTTPError):
                if e.code not in retry_codes:
                    return e
            else:
                raise
        except socket.timeout as e:
            err = e
        if attempt > 3:
            _log_callback(f"error {err} when executing http request {req}")
        time.sleep(backoff)


def _is_local_path(path):
    return not _is_gcs_path(path) and not _is_http_path(path)


def _is_gcs_path(path):
    url = urllib.parse.urlparse(path)
    return url.scheme == "gs"


def _is_http_path(path):
    url = urllib.parse.urlparse(path)
    return url.scheme in ["http", "https"]


def _split_url(path):
    url = urllib.parse.urlparse(path)
    return url.scheme, url.netloc, url.path[1:]


def _get_head(path):
    req = urllib.request.Request(url=path, method="HEAD")
    with _execute_request(req) as resp:
        return resp


def copy(src, dst, overwrite=False):
    if not overwrite:
        if exists(dst):
            raise FileExistsError(
                f"destination '{dst}' already exists and overwrite is disabled"
            )

    # special case gcs to gcs copy, don't download the file
    if _is_gcs_path(src) and _is_gcs_path(dst):
        _scheme, srcbucket, srcname = _split_url(src)
        _scheme, dstbucket, dstname = _split_url(dst)
        token = None
        while True:
            params = None
            if token is not None:
                params = {"rewriteToken": token}
            req = google.create_api_request(
                access_token=global_access_token_manager.get_token(),
                url=google.build_url(
                    "/storage/v1/b/{sourceBucket}/o/{sourceObject}/rewriteTo/b/{destinationBucket}/o/{destinationObject}",
                    sourceBucket=srcbucket,
                    sourceObject=srcname,
                    destinationBucket=dstbucket,
                    destinationObject=dstname,
                ),
                method="POST",
                params=params,
            )
            with _execute_request(req) as resp:
                if resp.code == 404:
                    raise FileNotFoundError(f"src file '{src}' not found")
                assert resp.code == 200
                result = json.load(resp)
                if result["done"]:
                    break
                token = result["rewriteToken"]
        return

    with BlobFile(src, "rb", streaming=True) as src_f, BlobFile(
        dst, "wb", streaming=True
    ) as dst_f:
        shutil.copyfileobj(src_f, dst_f, length=STREAMING_CHUNK_SIZE)


def _create_google_api_request(**kwargs):
    kwargs["access_token"] = global_access_token_manager.get_token()
    return google.create_api_request(**kwargs)


def _gcs_get_blob_metadata(path):
    _scheme, bucket, blob = _split_url(path)
    req = _create_google_api_request(
        url=google.build_url(
            "/storage/v1/b/{bucket}/o/{object}", bucket=bucket, object=blob
        ),
        method="GET",
    )
    with _execute_request(req) as resp:
        assert resp.code in (200, 404)
        return resp, json.load(resp)


def _gcs_exists(path):
    resp, _metadata = _gcs_get_blob_metadata(path)
    assert resp.code in (200, 404)
    return resp.code == 200


def exists(path):
    if _is_local_path(path):
        return os.path.exists(path)
    elif _is_gcs_path(path):
        if _gcs_exists(path):
            return True
        # this should check for any object that exists with this prefix
        if not path.endswith("/"):
            return _gcs_exists(path + "/")
        return False
    elif _is_http_path(path):
        code = _get_head(path).code
        assert code in (200, 404)
        return code == 200
    else:
        raise Exception("unrecognized path")


def glob(pattern):
    raise NotImplementedError


def isdir(path):
    raise NotImplementedError


def _create_google_page_iterator(url, method, data=None, params=None):
    if params is not None:
        params = params.copy()
        msg = params
    if data is not None:
        data = data.copy()
        msg = data
    while True:
        req = _create_google_api_request(
            url=url, method=method, params=params, data=data
        )
        with _execute_request(req) as resp:
            result = json.load(resp)
            yield result
            if "nextPageToken" not in result:
                break
        msg["pageToken"] = result["nextPageToken"]


def listdir(path):
    if _is_local_path(path):
        for d in os.listdir(path):
            yield d
    elif _is_gcs_path(path):
        assert path.endswith("/"), "directories must always end with a slash"
        _scheme, bucket, blob = _split_url(path)
        it = _create_google_page_iterator(
            url=google.build_url("/storage/v1/b/{bucket}/o", bucket=bucket),
            method="GET",
            params=dict(delimiter="/", prefix=blob),
        )
        for result in it:
            if "prefixes" in result:
                for p in result["prefixes"]:
                    yield p[len(blob) :]
            if "items" in result:
                for item in result["items"]:
                    yield item["name"][len(blob) :]
    else:
        raise Exception("unrecognized path")


def makedirs(path):
    raise NotImplementedError


def mkdir(path):
    raise NotImplementedError


def remove(path):
    raise NotImplementedError


def rename(src, dst, overwrite=False):
    raise NotImplementedError


def rmtree(path):
    raise NotImplementedError


def stat(path):
    raise NotImplementedError


def walk(top, topdown=True, onerror=None):
    raise NotImplementedError


def basename(path):
    """
    Get the filename component of the path

    For GCS, this is the part after the bucket
    """
    if _is_gcs_path(path) or _is_http_path(path):
        _scheme, _netloc, path = _split_url(path)
        return path.split("/")[-1]
    else:
        return os.path.basename(path)


def dirname(path):
    """
    Get the directory name of the path

    If this is a GCS path, the root directory is gs://<bucket name>/
    """
    if _is_gcs_path(path) or _is_http_path(path):
        scheme, netloc, urlpath = _split_url(path)
        if urlpath.endswith("/"):
            urlpath = urlpath[:-1]

        if "/" in urlpath:
            urlpath = "/".join(urlpath.split("/")[:-1]) + "/"
        else:
            urlpath = ""
        return f"{scheme}://{netloc}/{urlpath}"
    else:
        return os.path.dirname(path)


def join(a, b):
    """
    Join two file paths, if path `b` is an absolute path, it will replace the entire path component of a
    """
    if _is_gcs_path(a) or _is_http_path(a):
        if not a.endswith("/"):
            a += "/"
        assert "://" not in b
        parsed_a = urllib.parse.urlparse(a)
        newpath = urllib.parse.urljoin(parsed_a.path, b)
        return f"{parsed_a.scheme}://{parsed_a.netloc}" + newpath
    else:
        return os.path.join(a, b)


def cache_key(path):
    """
    Get a cache key for a file
    """
    if _is_local_path(path):
        key_parts = [path, os.path.getmtime(path), os.path.getsize(path)]
    elif _is_gcs_path(path):
        return md5(path)
    elif _is_http_path(path):
        head = _get_head(path)
        if head.code != 200:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        key_parts = [path]
        for header in ["Last-Modified", "Content-Length", "ETag", "Content-MD5"]:
            if header in head.headers:
                key_parts.append(head.headers[header])
    else:
        raise Exception("unrecognized path")
    return hashlib.md5(
        "|".join(
            hashlib.md5(str(p).encode("utf8")).hexdigest() for p in key_parts
        ).encode("utf8")
    ).hexdigest()


def get_url(path):
    """
    Get a URL for the given path that a browser could open
    """
    if _is_gcs_path(path):
        _scheme, bucket, blob = _split_url(path)
        return google.generate_signed_url(
            bucket, blob, expiration=google.MAX_EXPIRATION
        )
    elif _is_http_path(path):
        return path
    elif _is_local_path(path):
        return f"file://{path}"
    else:
        raise Exception("unrecognized path")


def md5(path):
    """
    Get the MD5 hash for a file
    """
    if _is_gcs_path(path):
        resp, metadata = _gcs_get_blob_metadata(path)
        assert resp.code == 200
        return binascii.hexlify(base64.b64decode(metadata["md5Hash"])).decode("utf8")
    else:
        m = hashlib.md5()
        with BlobFile(path, "rb") as f:
            while True:
                block = f.read(HASH_CHUNK_SIZE)
                if block == b"":
                    break
                m.update(block)
        return m.hexdigest()


class _LocalFile:
    def __init__(self, path, mode):
        print(f"create LocalFile {path}")
        self._mode = mode
        self._remote_path = path
        self._local_dir = tempfile.mkdtemp()
        self._local_path = join(self._local_dir, basename(path))
        if self._mode in ("r", "rb"):
            if not exists(path):
                raise FileNotFoundError(f"file '{path}' not found")
            with open(self._local_path, "wb") as f:
                with BlobFile(self._remote_path, "rb", streaming=True) as src_f:
                    shutil.copyfileobj(src_f, f, length=STREAMING_CHUNK_SIZE)
        self._f = open(self._local_path, self._mode)
        self._closed = False

    def __getattr__(self, attr):
        if attr == "_f":
            raise AttributeError(attr)
        return getattr(self._f, attr)

    def __enter__(self):
        return self._f

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        if not hasattr(self, "_closed") or self._closed:
            return

        self._f.close()
        if self._mode in ("w", "wb"):
            with open(self._local_path, "rb") as f:
                with BlobFile(self._remote_path, "wb", streaming=True) as dst_f:
                    shutil.copyfileobj(f, dst_f, length=STREAMING_CHUNK_SIZE)
        os.remove(self._local_path)
        os.rmdir(self._local_dir)
        self._closed = True


def _check_closed(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return method(self, *args, **kwargs)

    return wrapped


# https://docs.python.org/3/library/io.html#io.IOBase
class _BaseFile:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if not hasattr(self, "closed") or self.closed:
            return

        self.closed = True

    @_check_closed
    def read(self, size=-1):
        raise io.UnsupportedOperation("not readable")

    @_check_closed
    def readall(self):
        raise io.UnsupportedOperation("not readable")

    @_check_closed
    def readinto(self, b):
        raise io.UnsupportedOperation("not readable")

    @_check_closed
    def fileno(self):
        raise io.UnsupportedOperation("operation not supported")

    @_check_closed
    def flush(self):
        # none of the objects support flushing
        pass

    @_check_closed
    def isatty(self):
        return False

    @_check_closed
    def readable(self):
        return False

    @_check_closed
    def readline(self, size=-1):
        raise io.UnsupportedOperation("not readable")

    @_check_closed
    def readlines(self, hint=-1):
        raise io.UnsupportedOperation("not readable")

    @_check_closed
    def seek(self, offset, whence=io.SEEK_SET):
        raise io.UnsupportedOperation("operation not supported")

    @_check_closed
    def seekable(self):
        return False

    @_check_closed
    def tell(self):
        raise io.UnsupportedOperation("operation not supported")

    @_check_closed
    def truncate(self):
        raise io.UnsupportedOperation("File not open for writing")

    @_check_closed
    def writable(self):
        return False

    @_check_closed
    def write(self, b):
        raise io.UnsupportedOperation("not writable")

    @_check_closed
    def writelines(self, lines):
        raise io.UnsupportedOperation("not writable")

    def __del__(self):
        self.close()


class _StreamingReadFile(_BaseFile):
    def __init__(self, path, mode, size):
        self._size = size
        self._path = path
        self._text_mode = "b" not in mode
        if "b" in mode:
            self._newline = b"\n"
            self._empty = b""
        else:
            self._newline = "\n"
            self._empty = ""
        # current reading byte offset in the file
        self._offset = 0
        self._f = None
        super().__init__()

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration
        return line

    def _get_fp(self, offset):
        raise NotImplementedError

    def _call_fp_method(self, method, *args):
        # this should catch exceptions and get a new file pointer, but it's not clear what recoverable exceptions will occur here
        if self._f is None:
            self._f = self._get_fp(self._offset)
        return getattr(self._f, method)(*args)

    # according to https://docs.python.org/3/library/io.html#io.RawIOBase.read this should be size=-1, but that doesn't work with HTTPResponse files
    @_check_closed
    def read(self, size=None):
        if self._size == self._offset:
            return self._empty
        buf = self._call_fp_method("read", size)
        self._offset += len(buf)
        if self._text_mode:
            buf = buf.decode("utf8")
        return buf

    @_check_closed
    def readall(self):
        return self.read()

    @_check_closed
    def readinto(self, b):
        if self._text_mode:
            raise io.UnsupportedOperation("operation not supported")
        if self._size == self._offset:
            return 0
        n = self._call_fp_method("readinto", b)
        self._offset += n
        return n

    @_check_closed
    def readable(self):
        return True

    @_check_closed
    def readline(self, size=-1):
        if self._size == self._offset:
            return self._empty
        buf = self._call_fp_method("readline", size)
        self._offset += len(buf)
        if self._text_mode:
            buf = buf.decode("utf8")
        return buf

    @_check_closed
    def readlines(self, hint=-1):
        if self._size == self._offset:
            return []
        lines = self._call_fp_method("readlines", hint)
        self._offset += sum([len(l) for l in lines])
        if self._text_mode:
            lines = [l.decode("utf8") for l in lines]
        return lines

    @_check_closed
    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            new_offset = offset
        elif whence == io.SEEK_CUR:
            new_offset = self._offset + offset
        elif whence == io.SEEK_END:
            new_offset = self._size + offset
        else:
            raise ValueError(f"invalid whence")
        if new_offset != self._offset:
            self._offset = new_offset
            self._f = None

    @_check_closed
    def seekable(self):
        return True

    @_check_closed
    def tell(self):
        return self._offset

    def close(self):
        super().close()
        if hasattr(self, "_f") and self._f is not None:
            self._f.close()


class _GCSStreamingReadFile(_StreamingReadFile):
    def __init__(self, path, mode):
        resp, self._metadata = _gcs_get_blob_metadata(path)
        if resp.code == 404:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        assert resp.code == 200
        super().__init__(path, mode, int(self._metadata["size"]))

    def _get_fp(self, offset):
        req = google.create_read_blob_request(
            access_token=global_access_token_manager.get_token(),
            bucket=self._metadata["bucket"],
            name=self._metadata["name"],
            start=offset,
        )
        resp = _execute_request(req)
        assert resp.code == 206
        return resp


class _HTTPStreamingReadFile(_StreamingReadFile):
    def __init__(self, path, mode):
        self._path = path
        head = _get_head(path)
        if head.code != 200:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        assert head.headers["Accept-Ranges"] == "bytes"
        size = int(head.headers["Content-Length"])
        super().__init__(path, mode, size)

    def _get_fp(self, offset):
        req = Request(
            url=self._path, headers={"Range": f"bytes={offset}-"}, method="GET"
        )
        resp = _execute_request(req)
        assert resp.code == 206
        return resp


class _StreamingWriteFile(_BaseFile):
    def __init__(self, mode):
        self._text_mode = "b" not in mode
        self._newline = b"\n"
        self._empty = b""
        # current writing byte offset in the file
        self._offset = 0
        # contents waiting to be uploaded
        self._buf = self._empty
        super().__init__()

    def _upload_chunk(self, chunk, start, end, finalize):
        raise NotImplementedError

    def _upload_buf(self, finalize=False):
        if finalize:
            size = len(self._buf)
        else:
            size = (len(self._buf) // STREAMING_CHUNK_SIZE) * STREAMING_CHUNK_SIZE
            assert size > 0
        chunk = self._buf[:size]
        self._buf = self._buf[size:]

        start = self._offset
        end = self._offset + len(chunk) - 1
        self._upload_chunk(chunk, start, end, finalize)
        self._offset += len(chunk)

    def close(self):
        if not hasattr(self, "closed") or self.closed:
            return

        # we will have a partial remaining buffer at this point
        self._upload_buf(finalize=True)
        self.closed = True

    @_check_closed
    def tell(self):
        return self._offset

    @_check_closed
    def truncate(self):
        raise io.UnsupportedOperation("operation not supported")

    @_check_closed
    def writable(self):
        return True

    @_check_closed
    def write(self, b):
        if self._text_mode:
            b = b.encode("utf8")

        self._buf += b
        while len(self._buf) > STREAMING_CHUNK_SIZE:
            self._upload_buf()

    @_check_closed
    def writelines(self, lines):
        for line in lines:
            self.write(line)


class _GCSStreamingWriteFile(_StreamingWriteFile):
    def __init__(self, path, mode):
        _scheme, bucket, name = _split_url(path)
        req = google.create_resumable_upload_request(
            access_token=global_access_token_manager.get_token(),
            bucket=bucket,
            name=name,
        )
        with _execute_request(req) as resp:
            assert resp.code == 200
            self._upload_url = resp.headers["Location"]
        super().__init__(mode)

    def _upload_chunk(self, chunk, start, end, finalize):
        total_size = "*"
        if finalize:
            total_size = self._offset + len(chunk)
            assert len(self._buf) == 0
        content_range = f"bytes {start}-{end}/{total_size}"

        req = Request(
            url=self._upload_url,
            data=chunk,
            headers={"Content-Type": "application/octet-stream"},
            method="PUT",
        )

        if not (finalize and len(chunk) == 0):
            # not clear what the correct content-range is for a zero length file, so just don't include the header
            req.headers["Content-Range"] = content_range

        with _execute_request(req) as resp:
            if finalize:
                assert resp.code in (200, 201)
            else:
                # 308 is the expected response
                assert resp.code == 308


class _HTTPStreamingWriteFile(_StreamingWriteFile):
    # this is a fake streaming write file since we don't support range uploads yet
    # instead we store all buffers and then upload all of them on finalize
    def __init__(self, path, mode):
        super().__init__(mode)
        self._upload_buffer = self._empty
        self._path = path

    def _upload_chunk(self, chunk, start, end, finalize):
        self._upload_buffer += chunk

        if not finalize:
            return

        req = urllib.request.Request(
            url=self._path, data=self._upload_buffer, method="POST"
        )
        resp = _execute_request(req)
        assert resp.code == 200
        self._upload_buffer = None


class BlobFile:
    """
    Open a local or remote file for reading or writing

    Args:
        streaming: set to False to do a single copy instead of streaming reads/writes
    """

    def __init__(self, path, mode="r", streaming=False):
        assert not path.endswith("/")
        self._mode = mode
        if _is_gcs_path(path):
            if self._mode in ("w", "wb"):
                if streaming:
                    self._f = _GCSStreamingWriteFile(path, self._mode)
                else:
                    self._f = _LocalFile(path, self._mode)
            elif self._mode in ("r", "rb"):
                if streaming:
                    self._f = _GCSStreamingReadFile(path, self._mode)
                else:
                    self._f = _LocalFile(path, self._mode)
            else:
                raise Exception(f"unsupported mode {self._mode}")
        elif _is_http_path(path):
            if self._mode in ("w", "wb"):
                if streaming:
                    self._f = _HTTPStreamingWriteFile(path, self._mode)
                else:
                    self._f = _LocalFile(path, self._mode)
            elif self._mode in ("r", "rb"):
                if streaming:
                    self._f = _HTTPStreamingReadFile(path, self._mode)
                else:
                    self._f = _LocalFile(path, self._mode)
            else:
                raise Exception(f"unsupported mode {self._mode}")
        elif _is_local_path(path):
            self._f = open(file=path, mode=self._mode)
        else:
            raise Exception("unrecognized path")

    def __enter__(self):
        return self._f.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._f.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, attr):
        if attr == "_f":
            raise AttributeError(attr)
        return getattr(self._f, attr)
