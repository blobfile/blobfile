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


def _get_client():
    global gcs_client, gcs_client_pid
    with gcs_client_lock:
        pid = os.getpid()
        if gcs_client_pid is None or gcs_client_pid != pid:
            gcs_client = Client()
            gcs_client_pid = pid
    return gcs_client


def _is_local_path(path):
    return not _is_gcs_path(path)


def _is_gcs_path(path):
    url = urllib.parse.urlparse(path)
    return url.scheme == "gs"


def _split_gcs_path(path):
    url = urllib.parse.urlparse(path)
    return url.netloc, url.path[1:]


def _make_gcs(path):
    bucket_path, blob_path = _split_gcs_path(path)
    client = _get_client()
    bucket = client.bucket(bucket_path)
    return bucket, bucket.blob(blob_path)


def copy(src, dst, overwrite=False):
    if not overwrite:
        if exists(dst):
            raise FileExistsError(
                f"destination '{dst}' already exists and overwrite is disabled"
            )
    if _is_local_path(src):
        # local src
        if _is_local_path(dst):
            # local dst
            shutil.copyfile(src, dst)
        else:
            # remote dst
            _bucket, dstblob = _make_gcs(dst)
            dstblob.upload_from_filename(src)
    else:
        # remote src
        _bucket, srcblob = _make_gcs(src)
        if _is_local_path(dst):
            # local dst
            srcblob.download_to_filename(dst)
        else:
            # remote dst
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


def exists(path):
    if not _is_gcs_path(path):
        return os.path.exists(path)

    _bucket, blob = _make_gcs(path)
    if path.endswith("/"):
        dirblob = blob
    else:
        _bucket, dirblob = _make_gcs(path + "/")
    return blob.exists() or dirblob.exists()


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
    if _is_gcs_path(path):
        _bucket, path = _split_gcs_path(path)
        return path.split("/")[-1]
    else:
        return os.path.basename(path)


def dirname(path):
    """
    Get the directory name of the path

    If this is a GCS path, the root directory is gs://<bucket name>/
    """
    if _is_gcs_path(path):
        bucket, path = _split_gcs_path(path)
        return "/".join(f"gs://{bucket}/{path}".split("/")[:-1])
    else:
        return os.path.dirname(path)


def join(a, b):
    """
    Join two file paths, if path `b` is an absolute path, use it

    For GCS, the bucket is treated as the root of the filesystem, and `b` must not have a bucket
    """
    if _is_gcs_path(a):
        assert not _is_gcs_path(b), "second path must not be a gcs path"
        assert ".." not in b, "parent directory not handled"
        a_url = urllib.parse.urlparse(a)
        if b.startswith("/"):
            return f"gs://{a_url.netloc}{b}"
        if not a.endswith("/"):
            a = a + "/"
        return a + b
    else:
        return os.path.join(a, b)


def _reload_blob(blob):
    try:
        blob.reload()
    except google.api_core.exceptions.NotFound:
        raise FileNotFoundError(
            f"No such file or directory: 'gs://{blob.bucket.name}/{blob.name}'"
        )


def _assert_file_exists(path):
    _bucket, blob = _make_gcs(path)
    _reload_blob(blob)


def md5(path):
    """
    Get the MD5 hash for a file
    """
    if _is_gcs_path(path):
        _bucket, blob = _make_gcs(path)
        _reload_blob(blob)
        return binascii.hexlify(base64.b64decode(blob.md5_hash)).decode("utf8")
    else:
        m = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                block = f.read(HASH_CHUNK_SIZE)
                if block == b"":
                    break
                m.update(block)
        return m.hexdigest()


class _GCSWriteFile:
    def __init__(self, path, mode):
        self._remote_path = path
        self._local_dir = tempfile.mkdtemp()
        self._local_path = os.path.join(self._local_dir, basename(path))
        self._f = open(self._local_path, mode)
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
        copy(self._local_path, self._remote_path)
        os.remove(self._local_path)
        os.rmdir(self._local_dir)
        self._closed = True


class _GCSReadFile:
    def __init__(self, path, mode):
        self._remote_path = path
        _assert_file_exists(path)
        self._local_dir = tempfile.mkdtemp()
        copy(self._remote_path, join(self._local_dir, basename(path)))
        self._local_path = os.path.join(self._local_dir, path.split("/")[-1])
        self._f = open(self._local_path, mode)
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
        os.remove(self._local_path)
        os.rmdir(self._local_dir)
        self._closed = True


# https://docs.python.org/3/library/io.html#io.IOBase
def _check_closed(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return method(self, *args, **kwargs)

    return wrapped


class _GCSFile:
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
        raise NotImplementedError

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
        raise NotImplementedError

    @_check_closed
    def seekable(self):
        return False

    @_check_closed
    def tell(self):
        raise NotImplementedError

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


class _GCSStreamingReadFile(_GCSFile):
    def __init__(self, path, mode):
        self._remote_path = path
        _bucket, self._blob = _make_gcs(path)
        _reload_blob(self._blob)
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

    def _read_into_buf(self, size=STREAMING_CHUNK_SIZE):
        start = self._offset + len(self._buf)
        end = min(start + size, self._blob.size)
        if start == end:
            return True
        b = self._blob.download_as_string(start=start, end=end)
        self._buf += b
        return False

    def _read_from_buf(self, size=None):
        if size is None:
            size = len(self._buf)
        assert len(self._buf) >= size
        result = self._buf[:size]
        self._buf = self._buf[size:]
        self._offset += size
        if self._text_mode:
            return result.decode("utf8")
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
        self._read_into_buf(size=self._blob.size - self._offset)
        return self._read_from_buf()

    @_check_closed
    def readinto(self, b):
        raise NotImplementedError

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
            new_offset = self._blob.size + offset
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


class _GCSStreamingWriteFile(_GCSFile):
    def __init__(self, path, mode):
        self._remote_path = path
        _bucket, self._blob = _make_gcs(path)
        self._text_mode = "b" not in mode
        if "b" in mode:
            self._newline = b"\n"
            self._empty = b""
        else:
            self._newline = "\n"
            self._empty = ""
        # current writing byte offset in the file
        self._offset = 0
        # contents waiting to be uploaded
        self._buf = self._empty
        self._upload_url = self._blob.create_resumable_upload_session()
        super().__init__()

    def _upload_buf(self, finalize=False):
        size = STREAMING_CHUNK_SIZE
        if not finalize:
            assert len(self._buf) > size
        chunk = self._buf[:size]
        self._buf = self._buf[size:]
        total_size = "*"
        if finalize:
            total_size = self._offset + len(chunk)
            assert len(self._buf) == 0
        req = Request(
            url=self._upload_url,
            data=chunk,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Range": f"bytes {self._offset}-{self._offset + len(chunk)-1}/{total_size}",
            },
            method="PUT",
        )
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
        raise NotImplementedError

    @_check_closed
    def writable(self):
        return True

    @_check_closed
    def write(self, b):
        self._buf += b
        while len(self._buf) > STREAMING_CHUNK_SIZE:
            self._upload_buf()

    @_check_closed
    def writelines(self, lines):
        for line in lines:
            self.write(line)


class BlobFile:
    """
    Open a local or remote file for reading or writing

    Args:
        streaming: set to False to do a single copy instead of streaming reads/writes
    """

    def __init__(self, name, mode="r", streaming=True):
        assert not name.endswith("/")
        self._mode = mode
        if _is_gcs_path(name):
            if self._mode in ("w", "wb"):
                if streaming:
                    self._f = _GCSStreamingWriteFile(name, self._mode)
                else:
                    self._f = _GCSWriteFile(name, self._mode)
            elif self._mode in ("r", "rb"):
                if streaming:
                    self._f = _GCSStreamingReadFile(name, self._mode)
                else:
                    self._f = _GCSReadFile(name, self._mode)
            else:
                raise Exception(f"unsupported mode {self._mode}")
        else:
            self._f = open(file=name, mode=self._mode)

    def __enter__(self):
        return self._f.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._f.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, attr):
        if attr == "_f":
            raise AttributeError(attr)
        return getattr(self._f, attr)
