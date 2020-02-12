# https://mypy.readthedocs.io/en/stable/common_issues.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
from __future__ import annotations

import calendar
import copy as python_copy
import os
import tempfile
import hashlib
import base64
import io
import urllib.parse
import time
import json
import binascii
import glob as local_glob
import re
import shutil
import collections
import itertools
import random
import ssl
import socket
import threading
import multiprocessing as mp
from typing import (
    overload,
    Optional,
    Tuple,
    Callable,
    Sequence,
    Iterator,
    Mapping,
    Any,
    TextIO,
    BinaryIO,
    cast,
    NamedTuple,
    List,
    Union,
)
from typing_extensions import Literal, Protocol, runtime_checkable


import urllib3
import xmltodict
import filelock

from . import google, azure
from .common import Request, Error, RequestFailure


BACKOFF_INITIAL = 0.1
BACKOFF_MAX = 60.0
BACKOFF_JITTER = 0.1
RETRY_LOG_THRESHOLD = 1
EARLY_EXPIRATION_SECONDS = 5 * 60
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
CHUNK_SIZE = 2 ** 20
GOOGLE_CHUNK_SIZE = 2 ** 20
# https://cloud.google.com/storage/docs/json_api/v1/how-tos/resumable-upload
assert GOOGLE_CHUNK_SIZE % (256 * 1024) == 0
# https://docs.microsoft.com/en-us/rest/api/storageservices/understanding-block-blobs--append-blobs--and-page-blobs#about-append-blobs
# the chunk size determines the maximum size of an individual file for
# append blobs, 4MB x 50,000 blocks = 195GB(?) according to the docs
AZURE_MAX_CHUNK_SIZE = 4 * 2 ** 20
# it looks like azure signed urls cannot exceed the lifetime of the token used
# to create them, so don't keep the key around too long
AZURE_SAS_TOKEN_EXPIRATION_SECONDS = 60 * 60
# these seem to be expired manually, but we don't currently detect that
AZURE_SHARED_KEY_EXPIRATION_SECONDS = 24 * 60 * 60

# https://cloud.google.com/storage/docs/naming
# https://www.w3.org/TR/xml/#charsets
INVALID_CHARS = (
    set().union(range(0x0, 0x9)).union(range(0xB, 0xE)).union(range(0xE, 0x20))
)


class _GoogleResumableUploadFailure(RequestFailure):
    """
    An internal error used to handle the case when a GCS resumable upload
    failed in a recoverable way
    """

    pass


class Stat(NamedTuple):
    size: int
    mtime: float


class ReadStats(NamedTuple):
    bytes_read: int
    requests: int
    failures: int


_http = None
_http_pid = None
_http_lock = threading.Lock()


def _get_http_pool() -> urllib3.PoolManager:
    # ssl is not fork safe https://docs.python.org/2/library/ssl.html#multi-processing
    # urllib3 may not be fork safe https://github.com/urllib3/urllib3/issues/1179
    # both are supposedly threadsafe though, so we shouldn't need a thread-local pool
    global _http, _http_pid
    with _http_lock:
        if _http is None or _http_pid != os.getpid():
            # tensorflow imports requests with calls
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
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
            context.load_default_certs()
            _http_pid = os.getpid()
            _http = urllib3.PoolManager(ssl_context=context)
            # for debugging with mitmproxy
            # _http = urllib3.ProxyManager('http://localhost:8080/', ssl_context=context)

        return _http


def __log_callback(msg: str) -> None:
    print(msg)


# pylint can't figure this out when it's a def
_log_callback = __log_callback


def set_log_callback(fn: Callable[[str], None]) -> None:
    global _log_callback
    _log_callback = fn


class TokenManager:
    """
    Automatically refresh a token when it expires
    """

    def __init__(self, get_token_fn: Callable[[str], Tuple[Any, float]]) -> None:
        self._get_token_fn = get_token_fn
        self._tokens = {}
        self._lock = threading.Lock()
        self._expiration = None

    def get_token(self, key: str) -> Any:
        with self._lock:
            now = time.time()
            if (
                self._expiration is None
                or (now + EARLY_EXPIRATION_SECONDS) > self._expiration
            ):
                if key in self._tokens:
                    del self._tokens[key]

            if key not in self._tokens:
                self._tokens[key], self._expiration = self._get_token_fn(key)
        return self._tokens[key]


def _is_gce_instance() -> bool:
    try:
        socket.getaddrinfo("metadata.google.internal", 80)
    except socket.gaierror:
        return False
    return True


def _google_get_access_token(key: str) -> Tuple[Any, float]:
    now = time.time()

    if google.have_credentials():

        def build_req() -> Request:
            return google.create_access_token_request(
                scopes=["https://www.googleapis.com/auth/devstorage.full_control"]
            )

        with _execute_request(build_req) as resp:
            result = json.load(resp)
            return result["access_token"], now + float(result["expires_in"])
    elif _is_gce_instance():
        # see if the metadata server has a token for us
        def build_req() -> Request:
            return Request(
                method="GET",
                url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                headers={"Metadata-Flavor": "Google"},
            )

        with _execute_request(build_req) as resp:
            result = json.load(resp)
            return result["access_token"], now + float(result["expires_in"])
    else:
        raise Error("No google credentials found")


def _azure_get_access_token(account: str) -> Tuple[Any, float]:
    now = time.time()
    creds = azure.load_credentials()
    if "storageAccountKey" in creds:
        return (
            (azure.SHARED_KEY, creds["storageAccountKey"]),
            now + AZURE_SHARED_KEY_EXPIRATION_SECONDS,
        )
    elif "refreshToken" in creds:
        # we have a refresh token, do a dance to get a shared key
        def build_req() -> Request:
            return azure.create_access_token_request(
                creds=creds, scope="https://management.azure.com/"
            )

        with _execute_request(build_req) as resp:
            result = json.load(resp)
            auth = (azure.OAUTH_TOKEN, result["access_token"])

        # check each subscription for our account
        for subscription_id in creds["subscriptions"]:
            # get a list of storage accounts
            def build_req() -> Request:
                req = Request(
                    method="GET",
                    url=f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts",
                    params={"api-version": "2019-04-01"},
                )
                # return somefunc(auth=auth)
                return azure.make_api_request(req, auth=auth)

            with _execute_request(build_req) as resp:
                out = json.load(resp)
                # check if we found the storage account we are looking for
                for obj in out["value"]:
                    if obj["name"] == account:
                        storage_account_id = obj["id"]
                        break
                else:
                    continue

            def build_req() -> Request:
                req = Request(
                    method="POST",
                    url=f"https://management.azure.com{storage_account_id}/listKeys",
                    params={"api-version": "2019-04-01"},
                )
                return azure.make_api_request(req, auth=auth)

            with _execute_request(build_req) as resp:
                result = json.load(resp)
                for key in result["keys"]:
                    if key["permissions"] == "FULL":
                        return (
                            (azure.SHARED_KEY, key["value"]),
                            now + AZURE_SHARED_KEY_EXPIRATION_SECONDS,
                        )
                else:
                    raise Error(
                        f"Storage account did not have any keys defined: '{account}'"
                    )

        raise Error(f"Storage account ID not found for storage account: '{account}'")
    else:
        # we have a service account, get an oauth token
        def build_req() -> Request:
            return azure.create_access_token_request(
                creds=creds, scope="https://storage.azure.com/"
            )

        with _execute_request(build_req) as resp:
            result = json.load(resp)
            return (
                (azure.OAUTH_TOKEN, result["access_token"]),
                now + float(result["expires_in"]),
            )


def _azure_get_sas_token(account: str) -> Tuple[Any, float]:
    def build_req() -> Request:
        req = azure.create_user_delegation_sas_request(account=account)
        auth = global_azure_access_token_manager.get_token(key=account)
        if auth[0] != azure.OAUTH_TOKEN:
            raise Error("Only oauth tokens can be used to get SAS tokens")
        return azure.make_api_request(req, auth=auth)

    with _execute_request(build_req) as resp:
        out = xmltodict.parse(resp)
        t = time.time() + AZURE_SAS_TOKEN_EXPIRATION_SECONDS
        return out["UserDelegationKey"], t


global_google_access_token_manager = TokenManager(_google_get_access_token)

global_azure_access_token_manager = TokenManager(_azure_get_access_token)

global_azure_sas_token_manager = TokenManager(_azure_get_sas_token)


def _exponential_sleep_generator(
    initial: float, maximum: float, multiplier: float = 2
) -> Iterator[float]:
    value = initial
    while True:
        yield value + random.random() * BACKOFF_JITTER
        value *= multiplier
        if value > maximum:
            value = maximum


def _execute_azure_api_request(req: Request) -> urllib3.HTTPResponse:
    u = urllib.parse.urlparse(req.url)
    account = u.netloc.split(".")[0]

    def build_req() -> Request:
        return azure.make_api_request(
            req, auth=global_azure_access_token_manager.get_token(key=account)
        )

    return _execute_request(build_req)


def _execute_google_api_request(req: Request) -> urllib3.HTTPResponse:
    def build_req() -> Request:
        return google.make_api_request(
            req, access_token=global_google_access_token_manager.get_token(key="")
        )

    return _execute_request(build_req)


def _execute_request(build_req: Callable[[], Request],) -> urllib3.HTTPResponse:
    for attempt, backoff in enumerate(
        _exponential_sleep_generator(initial=BACKOFF_INITIAL, maximum=BACKOFF_MAX)
    ):
        req = build_req()
        url = req.url
        if req.params is not None:
            if len(req.params) > 0:
                url += "?" + urllib.parse.urlencode(req.params)

        err = None
        try:
            resp = _get_http_pool().request(
                method=req.method,
                url=url,
                headers=req.headers,
                body=req.data,
                timeout=urllib3.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
                preload_content=False,
                retries=False,
                redirect=False,
            )
            if resp.status in req.retry_codes:
                err = f"request failed with status {resp.status}"
            elif resp.status in req.success_codes:
                return resp
            else:
                raise RequestFailure(
                    message=f"unexpected status {resp.status}",
                    request=req,
                    response=resp,
                )
        except (
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.ReadTimeoutError,
            urllib3.exceptions.ProtocolError,
        ) as e:
            err = e
        if attempt >= RETRY_LOG_THRESHOLD:
            _log_callback(
                f"blobfile error {err} when executing http request {req}, sleeping for {backoff:.1f} seconds"
            )
        time.sleep(backoff)
    assert False, "unreachable"


def _is_local_path(path: str) -> bool:
    return not _is_google_path(path) and not _is_azure_path(path)


def _is_google_path(path: str) -> bool:
    url = urllib.parse.urlparse(path)
    return url.scheme == "gs"


def _is_azure_path(path: str) -> bool:
    url = urllib.parse.urlparse(path)
    return url.scheme == "https" and url.netloc.endswith(".blob.core.windows.net")


def copy(
    src: str, dst: str, overwrite: bool = False, return_md5: bool = False
) -> Optional[str]:
    """
    Copy a file from one path to another

    If both paths are on GCS, this will perform a remote copy operation without downloading
    the contents locally.

    If `overwrite` is `False` (the default), an exception will be raised if the destination
    path exists.

    If `return_md5` is set to `True`, an md5 will be calculated during the copy and returned.
    """
    # it would be best to check isdir() for remote paths, but that would
    # involve 2 extra network requests, so just do this test instead
    if _guess_isdir(src):
        raise IsADirectoryError(f"Is a directory: '{src}'")
    if _guess_isdir(dst):
        raise IsADirectoryError(f"Is a directory: '{dst}'")

    if not overwrite:
        if exists(dst):
            raise FileExistsError(
                f"Destination '{dst}' already exists and overwrite is disabled"
            )

    # special case cloud to cloud copy, don't download the file
    if _is_google_path(src) and _is_google_path(dst):
        srcbucket, srcname = google.split_url(src)
        dstbucket, dstname = google.split_url(dst)
        while True:
            params = {}
            req = Request(
                url=google.build_url(
                    "/storage/v1/b/{sourceBucket}/o/{sourceObject}/rewriteTo/b/{destinationBucket}/o/{destinationObject}",
                    sourceBucket=srcbucket,
                    sourceObject=srcname,
                    destinationBucket=dstbucket,
                    destinationObject=dstname,
                ),
                method="POST",
                params=params,
                success_codes=(200, 404),
            )
            with _execute_google_api_request(req) as resp:
                if resp.status == 404:
                    raise FileNotFoundError(f"Source file not found: '{src}'")
                result = json.load(resp)
                if result["done"]:
                    if return_md5:
                        return base64.b64decode(result["resource"]["md5Hash"]).hex()
                    else:
                        return
                params["rewriteToken"] = result["rewriteToken"]

    if _is_azure_path(src) and _is_azure_path(dst):
        # https://docs.microsoft.com/en-us/rest/api/storageservices/copy-blob
        dst_account, dst_container, dst_blob = azure.split_url(dst)
        src_account, src_container, src_blob = azure.split_url(src)
        req = Request(
            url=azure.build_url(
                dst_account,
                "/{container}/{blob}",
                container=dst_container,
                blob=dst_blob,
            ),
            method="PUT",
            headers={
                "x-ms-copy-source": azure.build_url(
                    src_account,
                    "/{container}/{blob}",
                    container=src_container,
                    blob=src_blob,
                )
            },
            success_codes=(202, 404),
        )

        with _execute_azure_api_request(req) as resp:
            if resp.status == 404:
                raise FileNotFoundError(f"Source file not found: '{src}'")
            copy_id = resp.headers["x-ms-copy-id"]
            copy_status = resp.headers["x-ms-copy-status"]

        # wait for potentially async copy operation to finish
        # https://docs.microsoft.com/en-us/rest/api/storageservices/get-blob
        # pending, success, aborted failed
        while copy_status == "pending":
            req = Request(
                url=azure.build_url(
                    dst_account,
                    "/{container}/{blob}",
                    container=dst_container,
                    blob=dst_blob,
                ),
                method="GET",
            )
            with _execute_azure_api_request(req) as resp:
                if resp.headers["x-ms-copy-id"] != copy_id:
                    raise Error("Copy id mismatch")
                copy_status = resp.headers["x-ms-copy-status"]
        if copy_status != "success":
            raise Error(f"Invalid copy status: '{copy_status}'")
        if return_md5:
            return md5(dst)
        return

    for attempt, backoff in enumerate(
        _exponential_sleep_generator(initial=BACKOFF_INITIAL, maximum=BACKOFF_MAX)
    ):
        try:
            with BlobFile(src, "rb", streaming=True) as src_f, BlobFile(
                dst, "wb", streaming=True
            ) as dst_f:
                m = hashlib.md5()
                while True:
                    block = src_f.read(CHUNK_SIZE)
                    if block == b"":
                        break
                    if return_md5:
                        m.update(block)
                    dst_f.write(block)
                if return_md5:
                    return m.hexdigest()
                else:
                    return
        except _GoogleResumableUploadFailure as e:
            # currently this is the only type of failure we retry
            # if this failure occurs, the upload must be restarted from the beginning
            # https://cloud.google.com/storage/docs/resumable-uploads#practices
            # https://github.com/googleapis/gcs-resumable-upload/issues/15#issuecomment-249324122
            if attempt >= RETRY_LOG_THRESHOLD:
                _log_callback(
                    f"error {e} when executing a resumable upload to {dst}, sleeping for {backoff:.1f} seconds"
                )
            time.sleep(backoff)


def _calc_range(start: Optional[int] = None, end: Optional[int] = None) -> str:
    # https://cloud.google.com/storage/docs/xml-api/get-object-download
    # oddly range requests are not mentioned in the JSON API, only in the XML api
    if start is not None and end is not None:
        return f"bytes={start}-{end-1}"
    elif start is not None:
        return f"bytes={start}-"
    elif end is not None:
        if end > 0:
            return f"bytes=0-{end-1}"
        else:
            return f"bytes=-{-int(end)}"
    else:
        raise Error("Invalid range")


def _create_google_page_iterator(
    url: str, method: str, params: Mapping[str, str]
) -> Iterator[Mapping[str, Any]]:
    p = dict(params).copy()

    while True:
        req = Request(url=url, method=method, params=p, success_codes=(200, 404))
        with _execute_google_api_request(req) as resp:
            if resp.status == 404:
                return
            result = json.load(resp)
            yield result
            if "nextPageToken" not in result:
                break
        p["pageToken"] = result["nextPageToken"]


def _create_azure_page_iterator(
    url: str,
    method: str,
    data: Optional[Mapping[str, str]] = None,
    params: Optional[Mapping[str, str]] = None,
) -> Iterator[Mapping[str, Any]]:
    if params is None:
        p = {}
    else:
        p = dict(params).copy()
    if data is None:
        d = None
    else:
        d = dict(data).copy()
    while True:
        req = Request(
            url=url, method=method, params=p, data=d, success_codes=(200, 404)
        )
        with _execute_azure_api_request(req) as resp:
            if resp.status == 404:
                return
            result = xmltodict.parse(resp)["EnumerationResults"]
            yield result
            if result["NextMarker"] is None:
                break
        p["marker"] = result["NextMarker"]


def _google_get_names(result: Mapping[str, Any]) -> Iterator[str]:
    if "prefixes" in result:
        for p in result["prefixes"]:
            yield p
    if "items" in result:
        for item in result["items"]:
            yield item["name"]


def _azure_get_names(result: Mapping[str, Any]) -> Iterator[str]:
    blobs = result["Blobs"]
    if blobs is None:
        return
    if "BlobPrefix" in blobs:
        if isinstance(blobs["BlobPrefix"], dict):
            blobs["BlobPrefix"] = [blobs["BlobPrefix"]]
        for bp in blobs["BlobPrefix"]:
            yield bp["Name"]
    if "Blob" in blobs:
        if isinstance(blobs["Blob"], dict):
            blobs["Blob"] = [blobs["Blob"]]
        for b in blobs["Blob"]:
            yield b["Name"]


def _google_isfile(path: str) -> Tuple[bool, Mapping[str, Any]]:
    bucket, blob = google.split_url(path)
    if blob == "":
        return False, {}
    req = Request(
        url=google.build_url(
            "/storage/v1/b/{bucket}/o/{object}", bucket=bucket, object=blob
        ),
        method="GET",
        success_codes=(200, 404),
    )
    with _execute_google_api_request(req) as resp:
        return resp.status == 200, json.load(resp)


def _azure_isfile(path: str) -> Tuple[bool, Mapping[str, Any]]:
    account, container, blob = azure.split_url(path)
    if blob == "":
        return False, {}
    req = Request(
        url=azure.build_url(
            account, "/{container}/{blob}", container=container, blob=blob
        ),
        method="HEAD",
        success_codes=(200, 404),
    )
    with _execute_azure_api_request(req) as resp:
        return resp.status == 200, resp.headers


def exists(path: str) -> bool:
    """
    Return true if that path exists (either as a file or a directory)
    """
    if _is_local_path(path):
        return os.path.exists(path)
    elif _is_google_path(path):
        isfile, _ = _google_isfile(path)
        if isfile:
            return True
        return isdir(path)
    elif _is_azure_path(path):
        isfile, _ = _azure_isfile(path)
        if isfile:
            return True
        return isdir(path)
    else:
        raise Error(f"Unrecognized path: '{path}'")


def _string_overlap(s1: str, s2: str) -> int:
    length = min(len(s1), len(s2))
    for i in range(length):
        if s1[i] != s2[i]:
            return i
    return length


def _split_path(path: str) -> List[str]:
    # a/b/c => a/, b/, c
    # a/b/ => a/, b/
    # /a/b/c => /, a/, b/, c
    parts = []
    part = ""
    for c in path:
        part += c
        if c == "/":
            parts.append(part)
            part = ""
    if part != "":
        parts.append(part)
    return parts


def _expand_implicit_dirs(root: str, it: Iterator[str]) -> Iterator[str]:
    # blob storage does not always have definitions for each intermediate dir
    # if we have a listing like
    #  gs://test/a/b
    #  gs://test/a/b/c/d
    # then we emit an entry "gs://test/a/b/c/" for the implicit dir "c"
    # requires that iterator return objects in sorted order
    previous_item = root
    for item in it:
        # find the overlap between the previous_item and the current
        offset = _string_overlap(previous_item, item)
        relpath = item[offset:]
        cur = item[:offset]
        if len(relpath) == 0:
            yield cur
        else:
            for part in _split_path(relpath):
                cur += part
                yield cur
        assert item >= previous_item
        previous_item = item


def _compile_pattern(s: str):
    tokens = [t for t in re.split("([*]+)", s) if t != ""]
    regexp = ""
    for tok in tokens:
        if tok == "*":
            regexp += r"[^/]*"
        elif tok == "**":
            regexp += r".*"
        else:
            regexp += re.escape(tok)
    return re.compile(regexp + r"/?$")


def _glob_full(pattern: str) -> Iterator[str]:
    prefix, _, _ = pattern.partition("*")

    re_pattern = _compile_pattern(pattern)

    for path in _expand_implicit_dirs(root=prefix, it=_list_blobs(path=prefix)):
        if bool(re_pattern.match(path)):
            if path == prefix and path.endswith("/"):
                # we matched the parent directory
                continue
            yield _strip_slash(path)


class _GlobTask(NamedTuple):
    cur: str
    rem: Sequence[str]


class _GlobEntry(NamedTuple):
    path: str


class _GlobTaskComplete(NamedTuple):
    pass


def _process_glob_task(
    root: str, t: _GlobTask
) -> Iterator[Union[_GlobTask, _GlobEntry]]:
    cur = t.cur + t.rem[0]
    rem = t.rem[1:]
    if "**" in cur:
        for path in _glob_full(root + cur + "".join(rem)):
            yield _GlobEntry(path)
    elif "*" in cur:
        re_pattern = _compile_pattern(root + cur)
        prefix, _, _ = cur.partition("*")
        path = root + prefix
        for blobpath in _list_blobs(path=path, delimiter="/"):
            # in the case of dirname/* we should not return the path dirname/
            if blobpath == path and blobpath.endswith("/"):
                # we matched the parent directory
                continue
            if bool(re_pattern.match(blobpath)):
                if len(rem) == 0:
                    yield _GlobEntry(_strip_slash(blobpath))
                else:
                    assert path.startswith(root)
                    yield _GlobTask(blobpath[len(root) :], rem)
    else:
        if len(rem) == 0:
            path = root + cur
            if exists(path):
                yield _GlobEntry(_strip_slash(path))
        else:
            yield _GlobTask(cur, rem)


def _glob_worker(
    root: str,
    tasks: mp.Queue[_GlobTask],
    results: mp.Queue[Union[_GlobEntry, _GlobTask, _GlobTaskComplete]],
) -> None:
    while True:
        t = tasks.get()
        for r in _process_glob_task(root=root, t=t):
            results.put(r)
        results.put(_GlobTaskComplete())


def glob(pattern: str, parallel: bool = False) -> Iterator[str]:
    """
    Find files and directories matching a pattern. Supports * and **

    For local paths, this function uses glob.glob() which has special handling for * and **
    that is not quite the same as remote paths.  See https://cloud.google.com/storage/docs/gsutil/addlhelp/WildcardNames#different-behavior-for-dot-files-in-local-file-system_1 for more information.

    Globs can have confusing performance, see https://cloud.google.com/storage/docs/gsutil/addlhelp/WildcardNames#efficiency-consideration:-using-wildcards-over-many-objects for more information.

    You can set `parallel=True` to use multiple processes to perform the glob.  It's likely
    that the results will no longer be in order.
    """
    if "?" in pattern or "[" in pattern or "]" in pattern:
        raise Error("Advanced glob queries are not supported")

    if _is_local_path(pattern):
        for filepath in local_glob.iglob(pattern, recursive=True):
            filepath = os.path.normpath(filepath)
            if filepath.endswith(os.sep):
                filepath = filepath[:-1]
            yield filepath
    elif _is_google_path(pattern) or _is_azure_path(pattern):
        if "*" not in pattern:
            if exists(pattern):
                yield _strip_slash(pattern)
            return

        if _is_google_path(pattern):
            bucket, blob_prefix = google.split_url(pattern)
            if "*" in bucket:
                raise Error("Wildcards cannot be used in bucket name")
            root = google.combine_url(bucket, "")
        else:
            account, container, blob_prefix = azure.split_url(pattern)
            if "*" in account or "*" in container:
                raise Error("Wildcards cannot be used in account or container")
            root = azure.combine_url(account, container, "")

        initial_task = _GlobTask("", _split_path(blob_prefix))

        if parallel:
            tasks = mp.Queue()
            tasks.put(initial_task)
            tasks_enqueued = 1
            results = mp.Queue()

            tasks_done = 0
            with mp.Pool(initializer=_glob_worker, initargs=(root, tasks, results)):
                while tasks_done < tasks_enqueued:
                    r = results.get()
                    if isinstance(r, _GlobEntry):
                        yield r.path
                    elif isinstance(r, _GlobTask):
                        tasks.put(r)
                        tasks_enqueued += 1
                    elif isinstance(r, _GlobTaskComplete):
                        tasks_done += 1
                    else:
                        raise Error("Invalid result")
        else:
            dq: collections.deque[_GlobTask] = collections.deque()
            dq.append(initial_task)
            while len(dq) > 0:
                t = dq.popleft()
                for r in _process_glob_task(root=root, t=t):
                    if isinstance(r, _GlobEntry):
                        yield r.path
                    else:
                        dq.append(r)
    else:
        raise Error(f"Unrecognized path '{pattern}'")


def _strip_slash(path: str) -> str:
    if path.endswith("/"):
        return path[:-1]
    else:
        return path


def isdir(path: str) -> bool:
    """
    Return true if a path is an existing directory
    """
    if _is_local_path(path):
        return os.path.isdir(path)
    elif _is_google_path(path):
        if not path.endswith("/"):
            path += "/"
        bucket, blob = google.split_url(path)
        if blob == "":
            req = Request(
                url=google.build_url("/storage/v1/b/{bucket}", bucket=bucket),
                method="GET",
                success_codes=(200, 404),
            )
            with _execute_google_api_request(req) as resp:
                return resp.status == 200
        else:
            params = dict(prefix=blob, delimiter="/", maxResults="1")
            req = Request(
                url=google.build_url("/storage/v1/b/{bucket}/o", bucket=bucket),
                method="GET",
                params=params,
                success_codes=(200, 404),
            )
            with _execute_google_api_request(req) as resp:
                if resp.status == 404:
                    return False
                result = json.load(resp)
                return "items" in result or "prefixes" in result
    elif _is_azure_path(path):
        if not path.endswith("/"):
            path += "/"
        account, container, blob = azure.split_url(path)
        if blob == "":
            req = Request(
                url=azure.build_url(
                    account, "/{container}", container=container, blob=blob
                ),
                method="GET",
                params=dict(restype="container"),
                success_codes=(200, 404),
            )
            with _execute_azure_api_request(req) as resp:
                return resp.status == 200
        else:
            req = Request(
                url=azure.build_url(account, "/{container}", container=container),
                method="GET",
                params=dict(
                    comp="list",
                    restype="container",
                    prefix=blob,
                    delimiter="/",
                    maxresults="1",
                ),
                success_codes=(200, 404),
            )
            with _execute_azure_api_request(req) as resp:
                if resp.status == 404:
                    return False
                result = xmltodict.parse(resp)["EnumerationResults"]
                return result["Blobs"] is not None and (
                    "BlobPrefix" in result["Blobs"] or "Blob" in result["Blobs"]
                )
    else:
        raise Error(f"Unrecognized path: '{path}'")


def _guess_isdir(path: str) -> bool:
    """
    Guess if a path is a directory without performing network requests
    """
    if _is_local_path(path) and os.path.isdir(path):
        return True
    elif (_is_google_path(path) or _is_azure_path(path)) and path.endswith("/"):
        return True
    return False


def _list_blobs(path: str, delimiter: Optional[str] = None) -> Iterator[str]:
    params = {}
    if delimiter is not None:
        params["delimiter"] = delimiter

    if _is_google_path(path):
        bucket, prefix = google.split_url(path)
        it = _create_google_page_iterator(
            url=google.build_url("/storage/v1/b/{bucket}/o", bucket=bucket),
            method="GET",
            params=dict(prefix=prefix, **params),
        )
        get_names = _google_get_names
        root = google.combine_url(bucket, "")
    elif _is_azure_path(path):
        account, container, prefix = azure.split_url(path)
        it = _create_azure_page_iterator(
            url=azure.build_url(account, "/{container}", container=container),
            method="GET",
            params=dict(comp="list", restype="container", prefix=prefix, **params),
        )
        get_names = _azure_get_names
        root = azure.combine_url(account, container, "")
    else:
        raise Error(f"Unrecognized path: '{path}'")

    for result in it:
        for name in get_names(result):
            yield root + name


def _list_blobs_in_dir(dirpath: str, exclude_dirpath: bool) -> Iterator[str]:
    for path in _list_blobs(path=dirpath, delimiter="/"):
        if exclude_dirpath and path == dirpath:
            continue
        yield _strip_slash(path[len(dirpath) :])


def listdir(path: str, shard_prefix_length: int = 0) -> Iterator[str]:
    """
    Returns an iterator of the contents of the directory at `path`

    If your filenames are uniformly distributed (like hashes) then you can use `shard_prefix_length`
    to query them more quickly.  `shard_prefix_length` will do multiple queries in parallel,
    querying each possible prefix independently.

    Using `shard_prefix_length` will only consider prefixes that are not unusual characters
    (mostly these are ascii values < 0x20) some of these could technically show up in a path.
    """
    if (_is_google_path(path) or _is_azure_path(path)) and not path.endswith("/"):
        path += "/"
    if not exists(path):
        raise FileNotFoundError(f"The system cannot find the path specified: '{path}'")
    if not isdir(path):
        raise NotADirectoryError(f"The directory name is invalid: '{path}'")
    if _is_local_path(path):
        for d in sorted(os.listdir(path)):
            yield d
    elif _is_google_path(path) or _is_azure_path(path):
        if shard_prefix_length == 0:
            yield from _list_blobs_in_dir(path, exclude_dirpath=True)
        else:
            prefixes = mp.Queue()
            items = mp.Queue()
            tasks_enqueued = 0

            valid_chars = [
                i for i in range(256) if i not in INVALID_CHARS and i != ord("/")
            ]
            for repeat in range(1, shard_prefix_length + 1):
                for chars in itertools.product(valid_chars, repeat=repeat):
                    prefix = ""
                    for c in chars:
                        prefix += chr(c)
                    # we need to check for exact matches for shorter prefix lengths
                    # if we only searched for prefixes of length `shard_prefix_length`
                    # we would skip shorter names, for instance "a" would be skipped if we
                    # we had `shard_prefix_length=2`
                    # instead we check for an exact match for everything shorter than
                    # our `shard_prefix_length`
                    exact = repeat != shard_prefix_length
                    prefixes.put((path, prefix, exact))
                    tasks_enqueued += 1

            tasks_done = 0
            with mp.Pool(
                initializer=_sharded_listdir_worker, initargs=(prefixes, items)
            ):
                while tasks_done < tasks_enqueued:
                    item = items.get()
                    if item is None:
                        tasks_done += 1
                        continue
                    yield item
    else:
        raise Error(f"Unrecognized path: '{path}'")


def _sharded_listdir_worker(
    prefixes: mp.Queue[Tuple[str, str, bool]], items: mp.Queue[Optional[str]]
) -> None:
    while True:
        base, prefix, exact = prefixes.get(True)
        if exact:
            if exists(base + prefix):
                items.put(prefix)
        else:
            it = _list_blobs_in_dir(base + prefix, exclude_dirpath=False)
            for item in it:
                items.put(prefix + item)
        items.put(None)  # indicate that we have finished this path


def makedirs(path: str) -> None:
    """
    Make any directories necessary to ensure that path is a directory
    """
    if _is_local_path(path):
        os.makedirs(path, exist_ok=True)
    elif _is_google_path(path):
        if not path.endswith("/"):
            path += "/"
        bucket, blob = google.split_url(path)
        req = Request(
            url=google.build_url("/upload/storage/v1/b/{bucket}/o", bucket=bucket),
            method="POST",
            params=dict(uploadType="media", name=blob),
            success_codes=(200, 400),
        )
        with _execute_google_api_request(req) as resp:
            if resp.status == 400:
                raise Error(
                    f"Unable to create directory, bucket does not exist: '{path}'"
                )
    elif _is_azure_path(path):
        if not path.endswith("/"):
            path += "/"
        account, container, blob = azure.split_url(path)
        req = Request(
            url=azure.build_url(
                account, "/{container}/{blob}", container=container, blob=blob
            ),
            method="PUT",
            headers={"x-ms-blob-type": "BlockBlob"},
            success_codes=(201, 400),
        )
        with _execute_azure_api_request(req) as resp:
            if resp.status == 400:
                raise Error(
                    f"Unable to create directory, account/container does not exist: '{path}'"
                )
    else:
        raise Error(f"Unrecognized path: '{path}'")


def remove(path: str) -> None:
    """
    Remove a file at the given path
    """
    if _is_local_path(path):
        os.remove(path)
    elif _is_google_path(path):
        if path.endswith("/"):
            raise IsADirectoryError(f"Is a directory: '{path}'")
        bucket, blob = google.split_url(path)
        if blob == "":
            raise FileNotFoundError(
                f"The system cannot find the path specified: '{path}'"
            )
        req = Request(
            url=google.build_url(
                "/storage/v1/b/{bucket}/o/{object}", bucket=bucket, object=blob
            ),
            method="DELETE",
            success_codes=(204, 404),
        )
        with _execute_google_api_request(req) as resp:
            if resp.status == 404:
                raise FileNotFoundError(
                    f"The system cannot find the path specified: '{path}'"
                )
    elif _is_azure_path(path):
        if path.endswith("/"):
            raise IsADirectoryError(f"Is a directory: '{path}'")
        account, container, blob = azure.split_url(path)
        if blob == "":
            raise FileNotFoundError(
                f"The system cannot find the path specified: '{path}'"
            )
        req = Request(
            url=azure.build_url(
                account, "/{container}/{blob}", container=container, blob=blob
            ),
            method="DELETE",
            success_codes=(202, 404),
        )
        with _execute_azure_api_request(req) as resp:
            if resp.status == 404:
                raise FileNotFoundError(
                    f"The system cannot find the path specified: '{path}'"
                )
    else:
        raise Error(f"Unrecognized path: '{path}'")


def rmdir(path: str) -> None:
    """
    Remove an empty directory at the given path
    """
    if _is_local_path(path):
        os.rmdir(path)
        return

    # directories in blob storage are different from normal directories
    # a directory exists if there are any blobs that have that directory as a prefix
    # when the last blob with that prefix is deleted, the directory no longer exists
    # except in the case when there is a blob with a name ending in a slash
    # representing an empty directory

    # to make this more usable it is not an error to delete a directory that does
    # not exist, but is still an error to delete a non-empty one
    if not path.endswith("/"):
        path += "/"

    if _is_google_path(path):
        _, blob = google.split_url(path)
    elif _is_azure_path(path):
        _, _, blob = azure.split_url(path)
    else:
        raise Error(f"Unrecognized path: '{path}'")

    if blob == "":
        raise Error(f"Cannot delete bucket: '{path}'")
    it = listdir(path)
    try:
        next(it)
    except FileNotFoundError:
        # this directory does not exist
        return
    except StopIteration:
        # this directory exists and is empty
        pass
    else:
        # this directory exists but is not empty
        raise OSError(f"The directory is not empty: '{path}'")

    if _is_google_path(path):
        bucket, blob = google.split_url(path)
        req = Request(
            url=google.build_url(
                "/storage/v1/b/{bucket}/o/{object}", bucket=bucket, object=blob
            ),
            method="DELETE",
            success_codes=(204,),
        )
        with _execute_google_api_request(req):
            pass
    elif _is_azure_path(path):
        account, container, blob = azure.split_url(path)
        req = Request(
            url=azure.build_url(
                account, "/{container}/{blob}", container=container, blob=blob
            ),
            method="DELETE",
            success_codes=(202,),
        )
        with _execute_azure_api_request(req):
            pass
    else:
        raise Error(f"Unrecognized path: '{path}'")


def stat(path: str) -> Stat:
    """
    Stat a file or object representing a directory, returns a Stat object
    """
    if _is_local_path(path):
        s = os.stat(path)
        return Stat(size=s.st_size, mtime=s.st_mtime)
    elif _is_google_path(path):
        isfile, metadata = _google_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file: '{path}'")
        ts = time.strptime(
            metadata["updated"].replace("Z", "GMT"), "%Y-%m-%dT%H:%M:%S.%f%Z"
        )
        t = calendar.timegm(ts)
        return Stat(size=int(metadata["size"]), mtime=t)
    elif _is_azure_path(path):
        isfile, metadata = _azure_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file: '{path}'")
        ts = time.strptime(metadata["Last-Modified"], "%a, %d %b %Y %H:%M:%S %Z")
        t = calendar.timegm(ts)
        return Stat(size=int(metadata["Content-Length"]), mtime=t)
    else:
        raise Error(f"Unrecognized path: '{path}'")


def rmtree(path: str) -> None:
    """
    Delete a directory tree
    """
    if not isdir(path):
        raise NotADirectoryError(f"The directory name is invalid: '{path}'")

    if _is_local_path(path):
        shutil.rmtree(path)
    elif _is_google_path(path):
        if not path.endswith("/"):
            path += "/"
        bucket, blob = google.split_url(path)
        it = _create_google_page_iterator(
            url=google.build_url("/storage/v1/b/{bucket}/o", bucket=bucket),
            method="GET",
            params=dict(prefix=blob),
        )
        for result in it:
            for item in _google_get_names(result):
                req = Request(
                    url=google.build_url(
                        "/storage/v1/b/{bucket}/o/{object}", bucket=bucket, object=item
                    ),
                    method="DELETE",
                    # 404 is allowed in case a failed request successfully deleted the file
                    # before erroring out
                    success_codes=(204, 404),
                )
                with _execute_google_api_request(req):
                    pass
    elif _is_azure_path(path):
        if not path.endswith("/"):
            path += "/"
        account, container, blob = azure.split_url(path)
        it = _create_azure_page_iterator(
            url=azure.build_url(account, "/{container}", container=container),
            method="GET",
            params=dict(comp="list", restype="container", prefix=blob),
        )
        for result in it:
            for item in _azure_get_names(result):
                req = Request(
                    url=azure.build_url(
                        account, "/{container}/{blob}", container=container, blob=item
                    ),
                    method="DELETE",
                    # 404 is allowed in case a failed request successfully deleted the file
                    # before erroring out
                    success_codes=(202, 404),
                )
                with _execute_azure_api_request(req):
                    pass
    else:
        raise Error(f"Unrecognized path: '{path}'")


def walk(
    top: str, topdown: bool = True, onerror: Optional[Callable] = None
) -> Iterator[Tuple[str, Sequence[str], Sequence[str]]]:
    """
    Walk a directory tree in a similar manner to os.walk
    """
    if not isdir(top):
        return

    if _is_local_path(top):
        top = os.path.normpath(top)
        for root, dirnames, filenames in os.walk(
            top=top, topdown=topdown, onerror=onerror
        ):
            assert isinstance(root, str)
            if root.endswith(os.sep):
                root = root[:-1]
            yield (root, sorted(dirnames), sorted(filenames))
    elif _is_google_path(top) or _is_azure_path(top):
        if not topdown:
            raise Error("Only topdown mode currently supported")
        dq: collections.deque[str] = collections.deque()
        dq.append(top)
        while len(dq) > 0:
            cur = dq.popleft()
            if not cur.endswith("/"):
                cur += "/"
            if _is_google_path(top):
                bucket, blob = google.split_url(cur)
                it = _create_google_page_iterator(
                    url=google.build_url("/storage/v1/b/{bucket}/o", bucket=bucket),
                    method="GET",
                    params=dict(delimiter="/", prefix=blob),
                )
                get_names = _google_get_names
            elif _is_azure_path(top):
                account, container, blob = azure.split_url(cur)
                it = _create_azure_page_iterator(
                    url=azure.build_url(account, "/{container}", container=container),
                    method="GET",
                    params=dict(
                        comp="list", restype="container", delimiter="/", prefix=blob
                    ),
                )
                get_names = _azure_get_names
            else:
                raise Error(f"Unrecognized path: '{top}'")
            dirnames = []
            filenames = []
            for result in it:
                for name in get_names(result):
                    if name == blob:
                        continue
                    name = name[len(blob) :]
                    if name.endswith("/"):
                        dirnames.append(name[:-1])
                    else:
                        filenames.append(name)
            yield (_strip_slash(cur), dirnames, filenames)
            dq.extend(join(cur, dirname) for dirname in dirnames)
    else:
        raise Error(f"Unrecognized path: '{top}'")


def basename(path: str) -> str:
    """
    Get the filename component of the path

    For GCS, this is the part after the bucket
    """
    if _is_google_path(path):
        _, obj = google.split_url(path)
        return obj.split("/")[-1]
    elif _is_azure_path(path):
        _, _, obj = azure.split_url(path)
        return obj.split("/")[-1]
    else:
        return os.path.basename(path)


def dirname(path: str) -> str:
    """
    Get the directory name of the path

    If this is a GCS path, the root directory is gs://<bucket name>/
    """
    if _is_google_path(path):
        bucket, obj = google.split_url(path)
        obj = _strip_slash(obj)
        if "/" in obj:
            obj = "/".join(obj.split("/")[:-1])
            return google.combine_url(bucket, obj)
        else:
            return google.combine_url(bucket, "")[:-1]
    elif _is_azure_path(path):
        account, container, obj = azure.split_url(path)
        obj = _strip_slash(obj)
        if "/" in obj:
            obj = "/".join(obj.split("/")[:-1])
            return azure.combine_url(account, container, obj)
        else:
            return azure.combine_url(account, container, "")[:-1]
    else:
        return os.path.dirname(path)


def join(a: str, *args: str) -> str:
    """
    Join file paths, if a path is an absolute path, it will replace the entire path component of previous paths
    """
    out = a
    for b in args:
        out = _join2(out, b)
    return out


def _join2(a: str, b: str) -> str:
    if _is_local_path(a):
        return os.path.join(a, b)
    elif _is_google_path(a) or _is_azure_path(a):
        if not a.endswith("/"):
            a += "/"
        if "://" in b:
            raise Error("Cannot join two fully qualified paths")

        if _is_google_path(a):
            bucket, obj = google.split_url(a)
            obj = urllib.parse.urljoin(obj, b)
            if obj.startswith("/"):
                obj = obj[1:]
            return google.combine_url(bucket, obj)
        elif _is_azure_path(a):
            account, container, obj = azure.split_url(a)
            obj = urllib.parse.urljoin(obj, b)
            if obj.startswith("/"):
                obj = obj[1:]
            return azure.combine_url(account, container, obj)
        else:
            raise Error(f"Unrecognized path: '{a}'")
    else:
        raise Error(f"Unrecognized path: '{a}'")


def get_url(path: str) -> Tuple[str, Optional[float]]:
    """
    Get a URL for the given path that a browser could open
    """
    if _is_google_path(path):
        bucket, blob = google.split_url(path)
        return google.generate_signed_url(
            bucket, blob, expiration=google.MAX_EXPIRATION
        )
    elif _is_azure_path(path):
        account, container, blob = azure.split_url(path)
        url = azure.build_url(
            account, "/{container}/{blob}", container=container, blob=blob
        )
        token = global_azure_sas_token_manager.get_token(key=account)
        return azure.generate_signed_url(key=token, url=url)
    elif _is_local_path(path):
        return f"file://{path}", None
    else:
        raise Error(f"Unrecognized path: '{path}'")


def _block_md5(f: BinaryIO) -> bytes:
    m = hashlib.md5()
    while True:
        block = f.read(CHUNK_SIZE)
        if block == b"":
            break
        m.update(block)
    return m.digest()


def _azure_maybe_update_md5(path: str, etag: str, hexdigest: str) -> bool:
    account, container, blob = azure.split_url(path)
    digest = binascii.unhexlify(hexdigest)
    req = Request(
        url=azure.build_url(
            account, "/{container}/{blob}", container=container, blob=blob
        ),
        method="PUT",
        params=dict(comp="properties"),
        headers={
            "x-ms-blob-content-md5": base64.b64encode(digest).decode("utf8"),
            # https://docs.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations
            "If-Match": etag,
        },
        success_codes=(200, 412),
    )
    with _execute_azure_api_request(req) as resp:
        return resp.status == 200


def md5(path: str) -> str:
    """
    Get the MD5 hash for a file in hexdigest format.

    For GCS this can just look up the MD5 in the blob's metadata.
    For Azure this can look up the MD5 if it's available, otherwise it must calculate it.
    For local paths, this must always calculate the MD5.
    """
    if _is_google_path(path):
        isfile, metadata = _google_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file: '{path}'")
        return base64.b64decode(metadata["md5Hash"]).hex()
    elif _is_azure_path(path):
        isfile, metadata = _azure_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file: '{path}'")
        # https://docs.microsoft.com/en-us/rest/api/storageservices/get-blob-properties
        if "Content-MD5" in metadata:
            result = base64.b64decode(metadata["Content-MD5"]).hex()
        else:
            # md5 is missing, calculate it and store it on file if the file has not changed
            with BlobFile(path, "rb") as f:
                result = _block_md5(f).hex()
            _azure_maybe_update_md5(path, metadata["ETag"], result)
        return result
    else:
        with BlobFile(path, "rb") as f:
            return _block_md5(f).hex()


class _RangeError:
    """
    Indicate to the caller that we attempted to read past the end of a file
    This can happen if a file was truncated while reading
    """


@runtime_checkable
class ReadableBinaryFile(Protocol):
    # self should probably not need to be annotated
    # https://github.com/microsoft/pyright/issues/370
    def readinto(self: Any, b: Any) -> Optional[int]:
        ...

    def close(self: Any) -> None:
        ...


class _StreamingReadFile(io.RawIOBase):
    def __init__(self, path: str, size: int) -> None:
        super().__init__()
        self._size = size
        self._path = path
        # current reading byte offset in the file
        self._offset = 0
        self._f = None
        self.requests = 0
        self.failures = 0
        self.bytes_read = 0

    def _get_file(
        self, offset: int
    ) -> Tuple[ReadableBinaryFile, Optional[_RangeError]]:
        raise NotImplementedError

    def readall(self) -> bytes:
        opt_bytes = self.read(self._size - self._offset)
        assert opt_bytes is not None, "file is in non-blocking mode"
        return opt_bytes

    # https://bugs.python.org/issue27501
    def readinto(self, b: Any) -> Optional[int]:
        if self._size == self._offset:
            return 0

        n = 0  # for pyright
        for attempt, backoff in enumerate(
            _exponential_sleep_generator(0.1, maximum=60.0)
        ):
            if self._f is None:
                self._f, file_err = self._get_file(self._offset)
                if isinstance(file_err, _RangeError):
                    return 0
                self.requests += 1

            err = None
            try:
                opt_n = self._f.readinto(b)
                assert opt_n is not None, "file is in non-blocking mode"
                n = opt_n
                if n == 0:
                    # assume that the connection has died
                    self._f.close()
                    self._f = None
                    err = "failed to read from connection"
                else:
                    # only break out if we successfully read at least one byte
                    break
            except (
                urllib3.exceptions.ReadTimeoutError,  # haven't seen this error here, but seems possible
                urllib3.exceptions.ProtocolError,
            ) as e:
                err = e
            self.failures += 1
            if attempt >= RETRY_LOG_THRESHOLD:
                _log_callback(
                    f"error {err} when executing readinto({len(b)}) at offset {self._offset} on file {self._path}, sleeping for {backoff:.1f} seconds"
                )
            time.sleep(backoff)
        self._offset += n
        self.bytes_read += n
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_offset = offset
        elif whence == io.SEEK_CUR:
            new_offset = self._offset + offset
        elif whence == io.SEEK_END:
            new_offset = self._size + offset
        else:
            raise ValueError(
                f"Invalid whence ({whence}, should be {io.SEEK_SET}, {io.SEEK_CUR}, or {io.SEEK_END})"
            )
        if new_offset != self._offset:
            self._offset = new_offset
            self._f = None
        return self._offset

    def tell(self) -> int:
        return self._offset

    def close(self) -> None:
        if self.closed:
            return

        if hasattr(self, "_f") and self._f is not None:
            self._f.close()
            self._f = None

        super().close()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


class _GoogleStreamingReadFile(_StreamingReadFile):
    def __init__(self, path: str) -> None:
        isfile, self._metadata = _google_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        super().__init__(path, int(self._metadata["size"]))

    def _get_file(
        self, offset: int
    ) -> Tuple[ReadableBinaryFile, Optional[_RangeError]]:
        req = Request(
            url=google.build_url(
                "/storage/v1/b/{bucket}/o/{name}",
                bucket=self._metadata["bucket"],
                name=self._metadata["name"],
            ),
            method="GET",
            params=dict(alt="media"),
            headers={"Range": _calc_range(start=offset)},
            success_codes=(206, 416),
        )
        resp = _execute_google_api_request(req)
        if resp.status == 416:
            # likely the file was truncated while we were reading it
            # return an empty file and indicate to the caller what happened
            return io.BytesIO(), _RangeError()
        # we don't decode content, so this is actually a ReadableBinaryFile
        return resp, None


class _AzureStreamingReadFile(_StreamingReadFile):
    def __init__(self, path: str) -> None:
        isfile, self._metadata = _azure_isfile(path)
        if not isfile:
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        super().__init__(path, int(self._metadata["Content-Length"]))

    def _get_file(
        self, offset: int
    ) -> Tuple[ReadableBinaryFile, Optional[_RangeError]]:
        account, container, blob = azure.split_url(self._path)
        req = Request(
            url=azure.build_url(
                account, "/{container}/{blob}", container=container, blob=blob
            ),
            method="GET",
            headers={"Range": _calc_range(start=offset)},
            success_codes=(206, 416),
        )
        resp = _execute_azure_api_request(req)
        if resp.status == 416:
            # likely the file was truncated while we were reading it
            # return an empty file and indicate to the caller what happened
            return io.BytesIO(), _RangeError()
        # we don't decode content, so this is actually a ReadableBinaryFile
        return resp, None


class _StreamingWriteFile(io.BufferedIOBase):
    def __init__(self, chunk_size: int) -> None:
        # current writing byte offset in the file
        self._offset = 0
        # contents waiting to be uploaded
        self._buf = b""
        self._chunk_size = chunk_size

    def _upload_chunk(self, chunk: bytes, finalize: bool) -> None:
        raise NotImplementedError

    def _upload_buf(self, finalize: bool = False):
        if finalize:
            size = len(self._buf)
        else:
            size = (len(self._buf) // self._chunk_size) * self._chunk_size
            assert size > 0
        chunk = self._buf[:size]
        self._buf = self._buf[size:]

        self._upload_chunk(chunk, finalize)
        self._offset += len(chunk)

    def close(self) -> None:
        if self.closed:
            return

        # we will have a partial remaining buffer at this point
        self._upload_buf(finalize=True)
        super().close()

    def tell(self) -> int:
        return self._offset

    def writable(self) -> bool:
        return True

    def write(self, b: bytes) -> int:
        self._buf += b
        while len(self._buf) > self._chunk_size:
            self._upload_buf()
        return len(b)

    def readinto(self, b: Any) -> int:
        raise io.UnsupportedOperation("not readable")

    def detach(self) -> io.RawIOBase:
        raise io.UnsupportedOperation("no underlying raw stream")

    def read1(self, size: int = -1) -> bytes:
        raise io.UnsupportedOperation("not readable")

    def readinto1(self, b: Any) -> int:
        raise io.UnsupportedOperation("not readable")


class _GoogleStreamingWriteFile(_StreamingWriteFile):
    def __init__(self, path: str) -> None:
        bucket, name = google.split_url(path)
        req = Request(
            url=google.build_url(
                "/upload/storage/v1/b/{bucket}/o?uploadType=resumable", bucket=bucket
            ),
            method="POST",
            data=dict(name=name),
            headers={"Content-Type": "application/json; charset=UTF-8"},
            success_codes=(200, 400, 404),
        )
        with _execute_google_api_request(req) as resp:
            if resp.status in (400, 404):
                raise FileNotFoundError(f"Not such file or directory: '{path}'")
            self._upload_url = resp.headers["Location"]
        super().__init__(chunk_size=GOOGLE_CHUNK_SIZE)

    def _upload_chunk(self, chunk: bytes, finalize: bool) -> None:
        start = self._offset
        end = self._offset + len(chunk) - 1

        total_size = "*"
        if finalize:
            total_size = self._offset + len(chunk)
            assert len(self._buf) == 0

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Range": f"bytes {start}-{end}/{total_size}",
        }
        if len(chunk) == 0 and finalize:
            # this is not mentioned in the docs but appears to be allowed
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range
            headers["Content-Range"] = f"bytes */{total_size}"

        req = Request(
            url=self._upload_url,
            data=chunk,
            headers=headers,
            method="PUT",
            success_codes=(200, 201) if finalize else (308,),
        )

        try:
            with _execute_google_api_request(req):
                pass
        except RequestFailure as e:
            # https://cloud.google.com/storage/docs/resumable-uploads#practices
            if e.response.status in (404, 410):
                raise _GoogleResumableUploadFailure(
                    message=e.message, request=e.request, response=e.response
                )
            else:
                raise


class _AzureStreamingWriteFile(_StreamingWriteFile):
    def __init__(self, path: str) -> None:
        account, container, blob = azure.split_url(path)
        self._url = azure.build_url(
            account, "/{container}/{blob}", container=container, blob=blob
        )
        # premium block blob storage supports block blobs and append blobs
        # https://azure.microsoft.com/en-us/blog/azure-premium-block-blob-storage-is-now-generally-available/
        req = Request(
            url=self._url,
            method="PUT",
            headers={"x-ms-blob-type": "AppendBlob"},
            success_codes=(201, 400, 404, 409),
        )
        with _execute_azure_api_request(req) as resp:
            if resp.status in (400, 404):
                raise FileNotFoundError(f"Not such file or directory: '{path}'")
            if resp.status == 409:
                # a blob already exists with a different type so we failed to create the new one
                remove(path)
                retry_req: Request = python_copy.copy(req)
                retry_req.success_codes = (201,)
                with _execute_azure_api_request(retry_req):
                    pass
        self._md5 = hashlib.md5()
        super().__init__(chunk_size=AZURE_MAX_CHUNK_SIZE)

    def _upload_chunk(self, chunk: bytes, finalize: bool) -> None:
        if len(chunk) == 0:
            return

        # max 4MB https://docs.microsoft.com/en-us/rest/api/storageservices/append-block#remarks
        start = 0
        while start < len(chunk):
            end = start + AZURE_MAX_CHUNK_SIZE
            data = chunk[start:end]
            self._md5.update(data)
            req = Request(
                url=self._url,
                method="PUT",
                params=dict(comp="appendblock"),
                data=data,
                headers={"x-ms-blob-condition-appendpos": str(self._offset + start)},
                # https://docs.microsoft.com/en-us/rest/api/storageservices/append-block#remarks
                success_codes=(201, 412),
            )

            with _execute_azure_api_request(req):
                pass

            # azure does not calculate md5s for us, we have to do that manually
            # https://blogs.msdn.microsoft.com/windowsazurestorage/2011/02/17/windows-azure-blob-md5-overview/
            req = Request(
                url=self._url,
                method="PUT",
                params=dict(comp="properties"),
                headers={
                    "x-ms-blob-content-md5": base64.b64encode(
                        self._md5.digest()
                    ).decode("utf8")
                },
            )
            with _execute_azure_api_request(req):
                pass

            start += AZURE_MAX_CHUNK_SIZE


@overload
def BlobFile(
    path: str,
    mode: Literal["rb"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def BlobFile(
    path: str,
    mode: Literal["wb"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def BlobFile(
    path: str,
    mode: Literal["ab"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def BlobFile(
    path: str,
    mode: Literal["r"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


@overload
def BlobFile(
    path: str,
    mode: Literal["w"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


@overload
def BlobFile(
    path: str,
    mode: Literal["a"],
    streaming: Optional[bool] = ...,
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


def BlobFile(
    path: str,
    mode: Literal["r", "rb", "w", "wb", "a", "ab"] = "r",
    streaming: Optional[bool] = None,
    buffer_size: int = io.DEFAULT_BUFFER_SIZE,
    cache_dir: Optional[str] = None,
):
    """
    Open a local or remote file for reading or writing

    Args:
        path local or remote path
        mode: one of "r", "rb", "w", "wb", "a", "ab" indicating the mode to open the file in
        streaming: the default for `streaming` is `True` when `mode` is in `"r", "rb"` and `False` when `mode` is in `"w", "wb", "a", "ab"`.
            * `streaming=True`:
                * Reading is done without downloading the entire remote file.
                * Writing is done to the remote file directly, but only in chunks of a few MB in size.  `flush()` will not cause an early write.
                * Appending is not implemented.
            * `streaming=False`: 
                * Reading is done by downloading the remote file to a local file during the constructor.
                * Writing is done by uploading the file on `close()` or during destruction.
                * Appending is done by downloading the file during construction and uploading on `close()`.
        buffer_size: number of bytes to buffer, this can potentially make reading more efficient.
        cache_dir: a directory in which to cache files for reading, only valid if `streaming=False` and `mode` is in `"r", "rb"`.   You are reponsible for cleaning up the cache directory.

    Returns:
        A file-like object
    """
    if _guess_isdir(path):
        raise IsADirectoryError(f"Is a directory: '{path}'")

    if streaming is None:
        streaming = mode in ("r", "rb")

    if streaming:
        if mode not in ("w", "wb", "r", "rb"):
            raise Error(f"Invalid mode for streaming file: '{mode}'")
        if cache_dir is not None:
            raise Error("Cannot specify cache_dir for streaming files")
        if _is_local_path(path):
            f = io.FileIO(path, mode=mode)
            if "r" in mode:
                f = io.BufferedReader(f, buffer_size=buffer_size)
            else:
                f = io.BufferedWriter(f, buffer_size=buffer_size)
        elif _is_google_path(path):
            if mode in ("w", "wb"):
                f = _GoogleStreamingWriteFile(path)
            elif mode in ("r", "rb"):
                f = _GoogleStreamingReadFile(path)
                f = io.BufferedReader(f, buffer_size=buffer_size)
            else:
                raise Error(f"Unsupported mode: '{mode}'")
        elif _is_azure_path(path):
            if mode in ("w", "wb"):
                f = _AzureStreamingWriteFile(path)
            elif mode in ("r", "rb"):
                f = _AzureStreamingReadFile(path)
                f = io.BufferedReader(f, buffer_size=buffer_size)
            else:
                raise Error(f"Unsupported mode: '{mode}'")
        else:
            raise Error(f"Unrecognized path: '{path}'")

        # this should be a protocol so we don't have to cast
        # but the standard library does not seem to have a file-like protocol
        binary_f = cast(BinaryIO, f)
        if "b" in mode:
            return binary_f
        else:
            text_f = io.TextIOWrapper(binary_f, encoding="utf8")
            return cast(TextIO, text_f)
    else:
        remote_path = None
        tmp_dir = None
        if mode not in ("w", "wb", "r", "rb", "a", "ab"):
            raise Error(f"Invalid mode: '{mode}'")

        if cache_dir is not None and mode not in ("r", "rb"):
            raise Error("cache_dir only supported in read mode")

        local_filename = basename(path)
        if local_filename == "":
            local_filename = "local.tmp"
        if _is_google_path(path) or _is_azure_path(path):
            remote_path = path
            if mode in ("a", "ab"):
                tmp_dir = tempfile.mkdtemp()
                local_path = join(tmp_dir, local_filename)
                if exists(remote_path):
                    copy(remote_path, local_path)
            elif mode in ("r", "rb"):
                if cache_dir is None:
                    tmp_dir = tempfile.mkdtemp()
                    local_path = join(tmp_dir, local_filename)
                    copy(remote_path, local_path)
                else:
                    if not _is_local_path(cache_dir):
                        raise Error(f"cache_dir must be a local path: '{cache_dir}'")
                    makedirs(cache_dir)
                    path_md5 = hashlib.md5(path.encode("utf8")).hexdigest()
                    lock_path = join(cache_dir, f"{path_md5}.lock")
                    tmp_path = join(cache_dir, f"{path_md5}.tmp")
                    with filelock.FileLock(lock_path):
                        remote_etag = ""
                        # get the remote md5 so we can check for a local file
                        if _is_google_path(path):
                            remote_hexdigest = md5(path)
                        elif _is_azure_path(path):
                            # in the azure case the remote md5 may not exist
                            # this duplicates some of md5() because we want more control
                            isfile, metadata = _azure_isfile(path)
                            if not isfile:
                                raise FileNotFoundError(f"No such file: '{path}'")
                            remote_etag = metadata["ETag"]
                            if "Content-MD5" in metadata:
                                remote_hexdigest = base64.b64decode(
                                    metadata["Content-MD5"]
                                ).hex()
                            else:
                                remote_hexdigest = None
                        else:
                            raise Error(f"Unrecognized path: '{path}'")

                        perform_copy = False
                        if remote_hexdigest is None:
                            # there is no remote md5, copy the file
                            # and attempt to update the md5
                            perform_copy = True
                        else:
                            expected_local_path = join(
                                cache_dir, remote_hexdigest, local_filename
                            )
                            perform_copy = not exists(expected_local_path)

                        if perform_copy:
                            local_hexdigest = copy(
                                remote_path, tmp_path, overwrite=True, return_md5=True
                            )
                            assert local_hexdigest is not None, "failed to return md5"
                            # the file we downloaded may not match the remote file because
                            # the remote file changed while we were downloading it
                            # in this case make sure we don't cache it under the wrong md5
                            local_path = join(
                                cache_dir, local_hexdigest, local_filename
                            )
                            os.makedirs(dirname(local_path), exist_ok=True)
                            if os.path.exists(local_path):
                                # the file is already here, nevermind
                                os.remove(tmp_path)
                            else:
                                os.replace(tmp_path, local_path)

                            if _is_azure_path(path) and remote_hexdigest is None:
                                _azure_maybe_update_md5(
                                    path, remote_etag, local_hexdigest
                                )
                        else:
                            assert remote_hexdigest is not None
                            local_path = join(
                                cache_dir, remote_hexdigest, local_filename
                            )
                    local_path = local_path
            else:
                tmp_dir = tempfile.mkdtemp()
                local_path = join(tmp_dir, local_filename)
        elif _is_local_path(path):
            local_path = path
        else:
            raise Error(f"Unrecognized path: '{path}'")

        f = _ProxyFile(
            local_path=local_path, mode=mode, tmp_dir=tmp_dir, remote_path=remote_path
        )
        if "r" in mode:
            f = io.BufferedReader(f, buffer_size=buffer_size)
        else:
            f = io.BufferedWriter(f, buffer_size=buffer_size)
        binary_f = cast(BinaryIO, f)
        if "b" in mode:
            return binary_f
        else:
            text_f = io.TextIOWrapper(binary_f, encoding="utf8")
            return cast(TextIO, text_f)


class _ProxyFile(io.FileIO):
    def __init__(
        self,
        local_path: str,
        mode: Literal["r", "rb", "w", "wb", "a", "ab"],
        tmp_dir: Optional[str],
        remote_path: Optional[str],
    ) -> None:
        super().__init__(local_path, mode=mode)
        self._mode = mode
        self._tmp_dir = tmp_dir
        self._local_path = local_path
        self._remote_path = remote_path
        self._closed = False

    def close(self) -> None:
        if not hasattr(self, "_closed") or self._closed:
            return

        super().close()
        if self._remote_path is not None and self._mode in ("w", "wb", "a", "ab"):
            copy(self._local_path, self._remote_path, overwrite=True)
        if self._tmp_dir is not None:
            os.remove(self._local_path)
            os.rmdir(self._tmp_dir)
        self._closed = True


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["rb"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["wb"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["ab"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> BinaryIO:
    ...


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["r"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["w"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


@overload
def LocalBlobFile(
    path: str,
    mode: Literal["a"],
    buffer_size: int = ...,
    cache_dir: Optional[str] = ...,
) -> TextIO:
    ...


def LocalBlobFile(
    path: str,
    mode: Literal["r", "rb", "w", "wb", "a", "ab"] = "r",
    buffer_size: int = io.DEFAULT_BUFFER_SIZE,
    cache_dir: Optional[str] = None,
):
    """
    DEPRECATED: use BlobFile(streaming=False) instead
    """
    return BlobFile(
        path=path,
        streaming=False,
        mode=mode,
        buffer_size=buffer_size,
        cache_dir=cache_dir,
    )
