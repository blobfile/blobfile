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
import datetime
import time

from google.cloud.storage import Client
import google.api_core.exceptions


HASH_CHUNK_SIZE = 65536
STREAMING_CHUNK_SIZE = 2 ** 20
# https://cloud.google.com/storage/docs/json_api/v1/how-tos/resumable-upload
assert STREAMING_CHUNK_SIZE % (256 * 1024) == 0

gcs_client = None
# it sounds like the client is threadsafe but not fork safe https://github.com/googleapis/google-cloud-python/issues/3272
gcs_client_pid = None
gcs_client_lock = threading.Lock()


def retry(fn, attempts=None, min_backoff=1, max_backoff=60):
    """
    Call `fn` `attempts` times, performing exponential backoff if it fails.
    """
    backoff = min_backoff
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except Exception:  # pylint: disable=broad-except
            if attempts is not None and attempt >= attempts:
                raise
        time.sleep(backoff)
        backoff *= 2
        backoff = min(backoff, max_backoff)


def _get_gcs_client():
    global gcs_client, gcs_client_pid
    with gcs_client_lock:
        pid = os.getpid()
        if gcs_client_pid is None or gcs_client_pid != pid:
            gcs_client = Client()
            gcs_client_pid = pid
    return gcs_client


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


def _make_gcs(path):
    _scheme, bucket_path, blob_path = _split_url(path)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_path)
    return bucket, bucket.blob(blob_path)


def _get_head(path):
    req = urllib.request.Request(url=path, method="HEAD")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp
    except urllib.error.HTTPError as resp:
        return resp


def _download_to_file(src, f):
    if _is_local_path(src):
        with open(src, "rb") as in_f:
            shutil.copyfileobj(in_f, f)
    elif _is_gcs_path(src):
        _bucket, srcblob = _make_gcs(src)
        srcblob.download_to_file(f)
    elif _is_http_path(src):
        req = urllib.request.Request(url=src, method="GET")
        with urllib.request.urlopen(req) as resp:
            assert resp.getcode() == 200
            shutil.copyfileobj(resp, f)
    else:
        raise Exception("unrecognized path")


def _upload_from_file(f, dst):
    if _is_local_path(dst):
        with open(dst, "wb") as dst_f:
            shutil.copyfileobj(f, dst_f)
    elif _is_gcs_path(dst):
        _bucket, dstblob = _make_gcs(dst)
        dstblob.upload_from_file(f)
    elif _is_http_path(dst):
        req = urllib.request.Request(url=dst, data=f, method="POST")
        with urllib.request.urlopen(req) as resp:
            assert resp.getcode() == 200
    else:
        raise Exception("unrecognized path")


def copy(src, dst, overwrite=False):
    if not overwrite:
        if exists(dst):
            raise FileExistsError(
                f"destination '{dst}' already exists and overwrite is disabled"
            )

    # special case gcs to gcs copy, don't download the file
    if _is_gcs_path(src) and _is_gcs_path(dst):
        _bucket, srcblob = _make_gcs(src)
        _bucket, dstblob = _make_gcs(dst)
        token = None
        while True:
            try:
                token, _bytes_rewritten, _total_bytes = dstblob.rewrite(
                    srcblob, token=token
                )
            except google.api_core.exceptions.NotFound:
                raise FileNotFoundError(f"src file '{src}' not found")
            if token is None:
                break
        return

    with BlobFile(src, "rb") as src_f, BlobFile(dst, "wb") as dst_f:
        shutil.copyfileobj(src_f, dst_f)


def exists(path):
    if _is_local_path(path):
        return os.path.exists(path)
    elif _is_gcs_path(path):
        _bucket, blob = _make_gcs(path)
        if path.endswith("/"):
            dirblob = blob
        else:
            _bucket, dirblob = _make_gcs(path + "/")
        return blob.exists() or dirblob.exists()
    elif _is_http_path(path):
        return _get_head(path).getcode() == 200
    else:
        raise Exception("unrecognized path")


def glob(pattern):
    raise NotImplementedError


def isdir(path):
    raise NotImplementedError


def listdir(path):
    raise NotImplementedError


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


def _reload_blob(blob):
    try:
        blob.reload()
    except google.api_core.exceptions.NotFound:
        raise FileNotFoundError(
            f"No such file or directory: 'gs://{blob.bucket.name}/{blob.name}'"
        )


def _assert_blob_exists(path):
    _bucket, blob = _make_gcs(path)
    _reload_blob(blob)


def cache_key(path):
    """
    Get a cache key for a file
    """
    if _is_local_path(path):
        key_parts = [path, os.path.getmtime(path), os.path.getsize(path)]
    elif _is_gcs_path(path):
        _bucket, blob = _make_gcs(path)
        _reload_blob(blob)
        return binascii.hexlify(base64.b64decode(blob.md5_hash)).decode("utf8")
    elif _is_http_path(path):
        head = _get_head(path)
        if head.getcode() != 200:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        key_parts = [path]
        for header in ["Last-Modified", "Content-Length", "ETag"]:
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
        _bucket, blob = _make_gcs(path)
        return blob.generate_signed_url(expiration=datetime.timedelta(days=365))
    elif _is_http_path(path):
        return path
    elif _is_local_path(path):
        return f"file://{path}"
    else:
        raise Exception("unrecognized path")


class _LocalFile:
    def __init__(self, path, mode):
        self._mode = mode
        self._remote_path = path
        self._local_dir = tempfile.mkdtemp()
        self._local_path = join(self._local_dir, basename(path))
        if self._mode in ("r", "rb"):
            if not exists(path):
                raise FileNotFoundError(f"file '{path}' not found")
            with open(self._local_path, "wb") as f:
                _download_to_file(self._remote_path, f)
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
                _upload_from_file(f, self._remote_path)
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
        # a local chunk of the file that we have downloaded
        self._buf = self._empty
        super().__init__()

    def __iter__(self):
        return self

    def __next__(self):
        line, eof = self._readline()
        if len(line) == 0 and eof:
            raise StopIteration
        return line

    def _download_range(self, start, end):
        raise NotImplementedError

    def _read_into_buf(self, size=STREAMING_CHUNK_SIZE):
        start = self._offset + len(self._buf)
        end = min(start + size, self._size)
        if start == end:
            return True
        b = self._download_range(start, end)
        if self._text_mode:
            b = b.decode("utf8")
        self._buf += b
        return False

    def _read_from_buf(self, size=None):
        if size is None:
            size = len(self._buf)
        assert len(self._buf) >= size
        result = self._buf[:size]
        self._buf = self._buf[size:]
        self._offset += size
        return result

    def _readline(self, size=-1):
        eof = False
        while True:
            newline_index = self._buf.find(self._newline)
            if newline_index != -1:
                end = newline_index + 1
                break
            if size > -1 and len(self._buf) >= size:
                end = size
                break
            if eof:
                end = len(self._buf)
                break
            eof = self._read_into_buf()

        result = self._read_from_buf(end)
        return result, len(result) == 0 and eof

    @_check_closed
    def read(self, size=-1):
        if size == -1:
            return self.readall()
        while True:
            if len(self._buf) >= size:
                end = size
                break
            eof = self._read_into_buf()
            if eof:
                end = len(self._buf)
                break
        result = self._read_from_buf(end)
        return result

    @_check_closed
    def readall(self):
        self._read_into_buf(size=self._size - self._offset)
        return self._read_from_buf()

    @_check_closed
    def readinto(self, b):
        b[:] = self.read(len(b))

    @_check_closed
    def readable(self):
        return True

    @_check_closed
    def readline(self, size=-1):
        result, _eof = self._readline(size=size)
        return result

    @_check_closed
    def readlines(self, hint=-1):
        total_bytes = 0
        lines = []
        while True:
            line, eof = self._readline()
            if eof:
                break
            lines.append(line)
            total_bytes += len(line)
            if hint > -1 and total_bytes > hint:
                break
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
            self._buf = self._empty

    @_check_closed
    def seekable(self):
        return True

    @_check_closed
    def tell(self):
        return self._offset


class _GCSStreamingReadFile(_StreamingReadFile):
    def __init__(self, path, mode):
        _bucket, self._blob = _make_gcs(path)
        _reload_blob(self._blob)
        super().__init__(path, mode, self._blob.size)

    def _download_range(self, start, end):
        return self._blob.download_as_string(start=start, end=end)


class _HTTPStreamingReadFile(_StreamingReadFile):
    def __init__(self, path, mode):
        self._path = path
        head = _get_head(path)
        if head.getcode() != 200:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        assert head.headers["Accept-Ranges"] == "bytes"
        size = int(head.headers["Content-Length"])
        super().__init__(path, mode, size)

    def _download_range(self, start, end):
        req = Request(
            url=self._path, headers={"Range": f"bytes={start}-{end-1}"}, method="GET"
        )
        resp = urlopen(req)
        assert resp.getcode() == 206
        return resp.read()


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
        size = STREAMING_CHUNK_SIZE
        if not finalize:
            assert len(self._buf) > size
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
        _bucket, self._blob = _make_gcs(path)
        self._upload_url = self._blob.create_resumable_upload_session()
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

        try:
            resp = urlopen(req)
        except urllib.error.HTTPError as e:
            if finalize:
                raise
            # 308 is the expected response
            if e.getcode() != 308:
                raise
        if finalize:
            assert resp.getcode() in (200, 201)


class BlobFile:
    """
    Open a local or remote file for reading or writing

    Args:
        streaming: set to False to do a single copy instead of streaming reads/writes
    """

    def __init__(self, path, mode="r", streaming=True):
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
                self._f = _LocalFile(path, self._mode)
            elif self._mode in ("r", "rb"):
                if streaming:
                    self._f = _HTTPStreamingReadFile(path, self._mode)
                else:
                    self._f = _LocalFile(path, self._mode)
            else:
                raise Exception(f"unsupported mode {self._mode}")
        else:
            self._f = open(file=path, mode=self._mode)

    def __enter__(self):
        return self._f.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._f.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, attr):
        if attr == "_f":
            raise AttributeError(attr)
        return getattr(self._f, attr)
