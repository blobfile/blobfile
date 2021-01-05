import io
import json
import random
import time
import urllib
import os
import threading
import ssl
import socket
import platform
from typing import (
    Callable,
    Iterator,
    Mapping,
    NamedTuple,
    Optional,
    Any,
    Sequence,
    Tuple,
)

import urllib3
import xmltodict

EARLY_EXPIRATION_SECONDS = 5 * 60

INVALID_HOSTNAME_STATUS = 600  # fake status for invalid hostname

DEFAULT_CONNECTION_POOL_MAX_SIZE = 32
DEFAULT_MAX_CONNECTION_POOL_COUNT = 10
DEFAULT_AZURE_WRITE_CHUNK_SIZE = 8 * 2 ** 20
DEFAULT_GOOGLE_WRITE_CHUNK_SIZE = 8 * 2 ** 20
DEFAULT_RETRY_LOG_THRESHOLD = 0
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 30

BACKOFF_INITIAL = 0.1
BACKOFF_MAX = 60.0
BACKOFF_JITTER_FRACTION = 0.5

HOSTNAME_EXISTS = 0
HOSTNAME_DOES_NOT_EXIST = 1
HOSTNAME_STATUS_UNKNOWN = 2

GCP_BASE_URL = "https://storage.googleapis.com"


def exponential_sleep_generator(
    initial: float = BACKOFF_INITIAL,
    maximum: float = BACKOFF_MAX,
    multiplier: float = 2,
) -> Iterator[float]:
    base = initial
    while True:
        # https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
        sleep = (
            base * (1 - BACKOFF_JITTER_FRACTION)
            + base * random.random() * BACKOFF_JITTER_FRACTION
        )
        yield sleep
        base *= multiplier
        if base > maximum:
            base = maximum


class Request:
    """
    A struct representing an HTTP request
    """

    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        data: Any = None,
        preload_content: bool = True,
        success_codes: Sequence[int] = (200,),
        # https://cloud.google.com/storage/docs/resumable-uploads#practices
        retry_codes: Sequence[int] = (408, 429, 500, 502, 503, 504),
    ) -> None:
        self.method: str = method
        self.url: str = url
        self.params: Optional[Mapping[str, str]] = params
        self.headers: Optional[Mapping[str, str]] = headers
        self.data: Any = data
        self.preload_content: bool = preload_content
        self.success_codes: Sequence[int] = success_codes
        self.retry_codes: Sequence[int] = retry_codes

    def __repr__(self) -> str:
        return f"<Request method={self.method} url={self.url} params={self.params}>"


class FileBody:
    """
    A struct for referencing a section of a file on disk to be used as the `data` property
    on a Request
    """

    def __init__(self, path: str, start: int, end: int) -> None:
        self.path: str = path
        self.start: int = start
        self.end: int = end

    def __repr__(self):
        return f"<FileBody path={self.path} start={self.start} end={self.end}>"


def build_url(base_url: str, template: str, **data: str) -> str:
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote(v, safe="")
    return base_url + template.format(**escaped_data)


class Error(Exception):
    """Base class for blobfile exceptions."""

    def __init__(self, message: str, *args: Any):
        self.message: str = message
        super().__init__(message, *args)


def _extract_error(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    if data.startswith(b"\xef\xbb\xbf<?xml"):
        try:
            result = xmltodict.parse(data)
            return result["Error"]["Code"], result["Error"].get("Message")
        except Exception:
            pass
    elif data.startswith(b"{"):
        try:
            result = json.loads(data)
            return str(result["error"]), result.get("error_description")
        except Exception:
            pass
    return None, None


class RequestFailure(Error):
    """
    A request failed, possibly after some number of retries
    """

    def __init__(
        self,
        message: str,
        request_string: str,
        response_status: int,
        error: Optional[str],
        error_description: Optional[str],
    ):
        self.request_string: str = request_string
        self.response_status: int = response_status
        self.error: Optional[str] = error
        self.error_description: Optional[str] = error_description
        super().__init__(
            message,
            self.request_string,
            self.response_status,
            self.error,
            self.error_description,
        )

    def __str__(self) -> str:
        return f"message={self.message}, request={self.request_string}, status={self.response_status}, error={self.error} error_description={self.error_description}"

    @classmethod
    def create_from_request_response(
        cls, message: str, request: Request, response: urllib3.HTTPResponse
    ) -> Any:
        # this helper function exists because if you make a custom Exception subclass it cannot
        # be unpickled easily: https://stackoverflow.com/questions/41808912/cannot-unpickle-exception-subclass

        err = None
        err_desc = None
        if response.data is not None:
            err, err_desc = _extract_error(response.data)
        # use string representation since request may not be serializable
        # exceptions need to be serializable when raised from subprocesses
        return cls(
            message=message,
            request_string=str(request),
            response_status=response.status,
            error=err,
            error_description=err_desc,
        )


class RestartableStreamingWriteFailure(RequestFailure):
    """
    A streaming write failed in a permanent way that requires restarting from the beginning of the stream
    """

    pass


class ConcurrentWriteFailure(RequestFailure):
    """
    A write failed due to another concurrent writer
    """

    pass


class Stat(NamedTuple):
    size: int
    mtime: float
    ctime: float
    md5: Optional[str]
    version: Optional[str]


class DirEntry(NamedTuple):
    path: str
    name: str
    is_dir: bool
    is_file: bool
    stat: Optional[Stat]


def default_log_fn(msg: str) -> None:
    print(f"blobfile: {msg}")


class Context:
    def __init__(
        self,
        log_callback: Callable[[str], None] = default_log_fn,
        connection_pool_max_size: int = DEFAULT_CONNECTION_POOL_MAX_SIZE,
        max_connection_pool_count: int = DEFAULT_MAX_CONNECTION_POOL_COUNT,
        # https://docs.microsoft.com/en-us/rest/api/storageservices/understanding-block-blobs--append-blobs--and-page-blobs#about-block-blobs
        # the chunk size determines the maximum size of an individual blob
        azure_write_chunk_size: int = DEFAULT_AZURE_WRITE_CHUNK_SIZE,
        google_write_chunk_size: int = DEFAULT_GOOGLE_WRITE_CHUNK_SIZE,
        retry_log_threshold: int = DEFAULT_RETRY_LOG_THRESHOLD,
        retry_limit: Optional[int] = None,
        connect_timeout: Optional[int] = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: Optional[int] = DEFAULT_READ_TIMEOUT,
        output_az_paths: bool = False,
        use_azure_storage_account_key_fallback: bool = True,
    ) -> None:
        self.log_callback = log_callback
        self.connection_pool_max_size = connection_pool_max_size
        self.max_connection_pool_count = max_connection_pool_count
        self.azure_write_chunk_size = azure_write_chunk_size
        self.retry_log_threshold = retry_log_threshold
        self.retry_limit = retry_limit
        self.google_write_chunk_size = google_write_chunk_size
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.output_az_paths = output_az_paths
        self.use_azure_storage_account_key_fallback = (
            use_azure_storage_account_key_fallback
        )

        self.http = None
        self.http_pid = None
        self.http_lock = threading.Lock()

    def get_http_pool(self) -> urllib3.PoolManager:
        # ssl is not fork safe https://docs.python.org/2/library/ssl.html#multi-processing
        # urllib3 may not be fork safe https://github.com/urllib3/urllib3/issues/1179
        # both are supposedly threadsafe though, so we shouldn't need a thread-local pool
        with self.http_lock:
            if self.http is None or self.http_pid != os.getpid():
                # tensorflow imports requests which calls
                #   import urllib3.contrib.pyopenssl
                #   urllib3.contrib.pyopenssl.inject_into_urllib3()
                # which will monkey patch urllib3 to use pyopenssl and sometimes break things
                # with errors such as "certificate verify failed"
                # https://github.com/pyca/pyopenssl/issues/823
                # https://github.com/psf/requests/issues/5238
                # in order to fix this here are a couple of options:

                # method 1
                # from urllib3.util import ssl_

                # if ssl_.IS_PYOPENSSL:
                #     import urllib3.contrib.pyopenssl

                #     urllib3.contrib.pyopenssl.extract_from_urllib3()
                # http = urllib3.PoolManager()

                # method 2
                # build a context based on https://github.com/urllib3/urllib3/blob/edc3ddb3d1cbc5871df4a17a53ca53be7b37facc/src/urllib3/util/ssl_.py#L220
                # this exists because there's no obvious way to cause that function to use the ssl.SSLContext except for un-monkey-patching urllib3
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.verify_mode = ssl.CERT_REQUIRED
                context.options |= (
                    ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
                )
                context.load_default_certs()
                self.http_pid = os.getpid()
                self.http = urllib3.PoolManager(
                    ssl_context=context,
                    maxsize=self.connection_pool_max_size,
                    num_pools=self.max_connection_pool_count,
                )
                # for debugging with mitmproxy
                # self.http = urllib3.ProxyManager('http://localhost:8080/', ssl_context=context)
        return self.http


class WindowedFile:
    """
    A file object that reads from a window into a file
    """

    def __init__(self, f: Any, start: int, end: int) -> None:
        self._f = f
        self._start = start
        self._end = end
        self._pos = -1
        self.seek(0)

    def tell(self) -> int:
        return self._pos - self._start

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> None:
        new_pos = self._start + offset
        assert whence == io.SEEK_SET and self._start <= new_pos < self._end
        self._f.seek(new_pos, whence)
        self._pos = new_pos

    def read(self, n: Optional[int] = None) -> Any:
        assert self._pos <= self._end
        if n is None:
            n = self._end - self._pos
        n = min(n, self._end - self._pos)
        buf = self._f.read(n)
        self._pos += len(buf)
        if n > 0 and len(buf) == 0:
            raise Error("failed to read expected amount of data from file")
        assert self._pos <= self._end
        return buf


def _check_hostname(hostname: str) -> int:
    try:
        socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            if platform.system() == "Linux":
                # on linux we appear to get EAI_NONAME if the host does not exist
                # and EAI_AGAIN if there is a temporary failure in resolution
                return HOSTNAME_DOES_NOT_EXIST
            else:
                # it's not clear on other platforms how to differentiate a temporary
                # name resolution failure from a permanent one, EAI_NONAME seems to be
                # returned for either case
                # if we cannot look up the hostname, but we
                # can look up google, then it's likely the hostname does not exist
                try:
                    socket.getaddrinfo("www.google.com", None, family=socket.AF_INET)
                except socket.gaierror:
                    # if we can't resolve google, then the network is likely down and
                    # we don't know if the hostname exists or not
                    return HOSTNAME_STATUS_UNKNOWN
                # in this case, we could resolve google, but not the original hostname
                # likely the hostname does not exist (though this is definitely not a foolproof check)
                return HOSTNAME_DOES_NOT_EXIST
        else:
            # we got some sort of other socket error, so it's unclear if the host exists or not
            return HOSTNAME_STATUS_UNKNOWN
    # no errors encountered, the hostname exists
    return HOSTNAME_EXISTS


def execute_request(
    ctx: Context, build_req: Callable[[], Request]
) -> urllib3.HTTPResponse:
    for attempt, backoff in enumerate(exponential_sleep_generator()):
        req = build_req()
        url = req.url
        if req.params is not None:
            if len(req.params) > 0:
                url += "?" + urllib.parse.urlencode(req.params)

        f = None
        if isinstance(req.data, FileBody):
            f = open(req.data.path, "rb")
            body = WindowedFile(f, start=req.data.start, end=req.data.end)
        else:
            body = req.data

        err = None
        try:
            resp = ctx.get_http_pool().request(
                method=req.method,
                url=url,
                headers=req.headers,
                body=body,
                timeout=urllib3.Timeout(
                    connect=ctx.connect_timeout, read=ctx.read_timeout
                ),
                preload_content=req.preload_content,
                retries=False,
                redirect=False,
            )
            if resp.status in req.success_codes:
                return resp
            else:
                message = f"unexpected status {resp.status}"
                if url.startswith(GCP_BASE_URL) and resp.status in (429, 503):
                    message += ": if you are writing a blob this error may be due to multiple concurrent writers - make sure you are not writing to the same blob from multiple processes simultaneously"
                err = RequestFailure.create_from_request_response(
                    message=message, request=req, response=resp
                )
                if resp.status not in req.retry_codes:
                    raise err
        except (
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.ReadTimeoutError,
            urllib3.exceptions.ProtocolError,
            # we should probably only catch SSLErrors matching `DECRYPTION_FAILED_OR_BAD_RECORD_MAC`
            # but it's not obvious what the error code will be from the logs
            # and because we are connecting to known servers, it's likely that non-transient
            # SSL errors will be rare, so for now catch all SSLErrors
            urllib3.exceptions.SSLError,
            # urllib3 wraps all errors in its own exception classes
            # but seems to miss ssl.SSLError
            # https://github.com/urllib3/urllib3/blob/9971e27e83a891ba7b832fa9e5d2f04bbcb1e65f/src/urllib3/response.py#L415
            # https://github.com/urllib3/urllib3/blame/9971e27e83a891ba7b832fa9e5d2f04bbcb1e65f/src/urllib3/response.py#L437
            # https://github.com/urllib3/urllib3/issues/1764
            ssl.SSLError,
        ) as e:
            if isinstance(e, urllib3.exceptions.NewConnectionError):
                # azure accounts have unique urls and it's hard to tell apart
                # an invalid hostname from a network error
                url = urllib.parse.urlparse(req.url)
                assert url.hostname is not None
                if (
                    url.hostname.endswith(".blob.core.windows.net")
                    and _check_hostname(url.hostname) == HOSTNAME_DOES_NOT_EXIST
                ):
                    # in order to handle the azure failures in some sort-of-reasonable way
                    # create a fake response that has a special status code we can
                    # handle just like a 404
                    fake_resp = urllib3.response.HTTPResponse(
                        status=INVALID_HOSTNAME_STATUS,
                        body=io.BytesIO(b""),  # avoid error when using "with resp:"
                    )
                    if fake_resp.status in req.success_codes:
                        return fake_resp
                    else:
                        raise RequestFailure.create_from_request_response(
                            "host does not exist", request=req, response=fake_resp
                        )

            err = RequestFailure.create_from_request_response(
                message=f"request failed with exception {e}",
                request=req,
                response=urllib3.response.HTTPResponse(status=0, body=io.BytesIO(b"")),
            )
        finally:
            if f is not None:
                f.close()

        if ctx.retry_limit is not None and attempt >= ctx.retry_limit:
            raise err

        if attempt >= ctx.retry_log_threshold:
            ctx.log_callback(
                f"error {err} when executing http request {req} attempt {attempt}, sleeping for {backoff:.1f} seconds before retrying"
            )
        time.sleep(backoff)
    assert False, "unreachable"


class TokenManager:
    """
    Automatically refresh tokens when they expire
    """

    def __init__(
        self, get_token_fn: Callable[[Context, Any], Tuple[Any, float]]
    ) -> None:
        self._get_token_fn = get_token_fn
        self._tokens = {}
        self._expirations = {}
        self._lock = threading.Lock()

    def get_token(self, ctx: Context, key: Any) -> Any:
        with self._lock:
            now = time.time()
            expiration = self._expirations.get(key)
            if expiration is None or (now + EARLY_EXPIRATION_SECONDS) > expiration:
                self._tokens[key], self._expirations[key] = self._get_token_fn(ctx, key)
                assert self._expirations[key] is not None

            assert key in self._tokens
            return self._tokens[key]
