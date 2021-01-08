import concurrent.futures
import datetime
import hashlib
import os
import platform
import urllib.parse
from typing import Any, Dict, List, Mapping, Optional, Tuple
import configparser

import urllib3
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
import hmac
from Cryptodome.Signature import pkcs1_15

from blobfile import _common as common
from blobfile._common import (
    GCP_BASE_URL,
    BaseStreamingReadFile,
    BaseStreamingWriteFile,
    Context,
    Error,
    FileBody,
    Request,
    RequestFailure,
    RestartableStreamingWriteFailure,
    Stat,
    TokenManager,
)

MAX_EXPIRATION = 7 * 24 * 60 * 60


# https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(key: str, dateStamp: str, regionName: str, serviceName: str):
    kDate = _sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = _sign(kDate, regionName)
    kService = _sign(kRegion, serviceName)
    kSigning = _sign(kService, "aws4_request")
    return kSigning


# Virtual host style: https://BUCKET.s3.amazonaws.com/FILE
def _load_credentials() -> Tuple[Dict[str, Any], Optional[str]]:
    creds = {
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "aws_default_region": os.getenv("AWS_DEFAULT_REGION"),
    }
    if any(creds.values()):
        return creds, None

    creds_path = os.getenv("AWS_SHARED_CREDENTIALS_FILE")
    if creds_path:
        if not os.path.exists(creds_path):
            return (
                {},
                f"credentials not found at {creds_path} specified by environment variable 'AWS_SHARED_CREDENTIALS_FILE'",
            )
    elif platform.system() == "Windows":
        raise NotImplementedError()
    else:
        creds_path = os.path.join(os.environ["HOME"], ".aws/credentials")

    if os.path.exists(creds_path):
        with open(creds_path) as f:
            config = configparser.ConfigParser()
            config.read_string(f.read())
            return dict(config["default"]), None
    return (
        {},
        "credentials not found, please login with 'aws configure' or else set the 'AWS_SHARED_CREDENTIALS_FILE' environment variable to the path of a ini format service account key",
    )


def makedirs(ctx: Context, path: str) -> None:
    """
    Make any directories necessary to ensure that path is a directory
    """
    raise NotImplementedError()


def sign_request(
    secret_key: str,
    access_key: str,
    url: str,
    region: str,
    method: str,
    body: str = "",
    service: str = "s3",
    now: Optional[datetime.datetime] = None,
):
    u = urllib.parse.urlparse(url)

    # Create a date for headers and the credential string
    t = now or datetime.datetime.utcnow()
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")  # Date w/o time, used in credential scope

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    canonical_uri = u.path

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the request_parameters variable.
    canonical_querystring = u.query

    headers = {
        "host": u.netloc,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": hashlib.sha256(body.encode()).hexdigest(),
    }

    # Step 4: Create the canonical headers and signed headers. Header names
    # must be trimmed and lowercase, and sorted in code point order from
    # low to high. Note that there is a trailing \n.
    canonical_headers = ""
    ordered_headers = sorted(headers.items())
    for k, v in ordered_headers:
        lower_k = str(k).lower()
        strip_v = str(v).strip()
        canonical_headers += f"{lower_k}:{strip_v}\n"

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers_parts = []
    for k, _ in ordered_headers:
        lower_k = str(k).lower()
        signed_headers_parts.append(lower_k)
    signed_headers = ";".join(signed_headers_parts)

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    # Step 7: Combine elements to create canonical request
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = "/".join([datestamp, region, service, "aws4_request"])
    string_to_sign = "\n".join(
        [
            algorithm,
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = _get_signature_key(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
    # Create authorization header and add to request headers
    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope},"
        f"SignedHeaders={signed_headers},Signature={signature}"
    )

    # The request can include any headers, but MUST include "host", "x-amz-date",
    # and (for this scenario) "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python 'requests' library.
    headers["Authorization"] = authorization_header
    return headers


def build_url(bucket: str, template: str, **data: str) -> str:
    return f"https://{bucket}.s3.amazonaws.com" + template.format(**data)


def create_api_request(req: Request, access_token: str) -> Request:
    if req.headers is None:
        headers = {}
    else:
        headers = dict(req.headers).copy()

    if req.params is None:
        params = {}
    else:
        params = dict(req.params).copy()

    data = req.data
    if data is not None and isinstance(data, dict):
        raise NotImplementedError()
    else:
        data = ""

    creds, err = _load_credentials()
    if err is not None:
        raise Error(err)

    headers.update(
        sign_request(
            secret_key=creds["aws_secret_access_key"],
            access_key=creds["aws_access_key_id"],
            region=creds["aws_default_region"],
            method=req.method,
            url=req.url,
            body=data,
        )
    )

    result = Request(
        method=req.method,
        url=req.url,
        params=params,
        headers=headers,
        data=data,
        preload_content=req.preload_content,
        success_codes=tuple(req.success_codes),
        retry_codes=tuple(req.retry_codes),
    )

    return result


# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html
# https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
def _get_access_token(ctx: Context, key: Any) -> Tuple[Any, float]:
    # Dummy for now
    return None, 60 * 60 * 24


def _create_access_token_request(scopes: List[str]) -> Request:
    raise NotImplementedError()


def execute_api_request(ctx: Context, req: Request) -> urllib3.HTTPResponse:
    def build_req() -> Request:
        return create_api_request(
            req, access_token=access_token_manager.get_token(ctx, key="")
        )

    return common.execute_request(ctx, build_req)


def generate_signed_url(
    bucket: str,
    name: str,
    expiration: float,
    method: str = "GET",
    params: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
    now: Optional[datetime.datetime] = None,
) -> Tuple[str, Optional[float]]:
    if params is None:
        p = {}
    else:
        p = dict(params).copy()

    if headers is None:
        h = {}
    else:
        h = dict(headers).copy()

    # https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    creds, err = _load_credentials()
    if err is not None:
        raise Error(err)

    if expiration > MAX_EXPIRATION:
        raise Error(f"Expiration can't be longer than {MAX_EXPIRATION} seconds.")

    escaped_object_name = urllib.parse.quote(name, safe="")
    canonical_uri = f"/{escaped_object_name}"

    datetime_now = now or datetime.datetime.utcnow()
    request_timestamp = datetime_now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = datetime_now.strftime("%Y%m%d")

    credential_scope = f"{datestamp}/{creds['aws_default_region']}/s3/aws4_request"
    credential = f"{creds['aws_access_key_id']}/{credential_scope}"
    h["host"] = f"{bucket}.s3.amazonaws.com"

    canonical_headers = ""
    ordered_headers = sorted(h.items())
    for k, v in ordered_headers:
        lower_k = str(k).lower()
        strip_v = str(v).strip()
        canonical_headers += f"{lower_k}:{strip_v}\n"

    signed_headers_parts = []
    for k, _ in ordered_headers:
        lower_k = str(k).lower()
        signed_headers_parts.append(lower_k)
    signed_headers = ";".join(signed_headers_parts)

    p["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
    p["X-Amz-Credential"] = credential
    p["X-Amz-Date"] = request_timestamp
    p["X-Amz-Expires"] = str(expiration)
    p["X-Amz-SignedHeaders"] = signed_headers

    canonical_query_string_parts = []
    ordered_params = sorted(p.items())
    for k, v in ordered_params:
        encoded_k = urllib.parse.quote(str(k), safe="")
        encoded_v = urllib.parse.quote(str(v), safe="")
        canonical_query_string_parts.append(f"{encoded_k}={encoded_v}")
    canonical_query_string = "&".join(canonical_query_string_parts)

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query_string,
            canonical_headers,
            signed_headers,
            "UNSIGNED-PAYLOAD",
        ]
    )

    canonical_request_hash = hashlib.sha256(canonical_request.encode()).hexdigest()

    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            request_timestamp,
            credential_scope,
            canonical_request_hash,
        ]
    )

    signing_key = _get_signature_key(
        creds["aws_secret_access_key"], datestamp, creds["aws_default_region"], "s3"
    )
    signature = hmac.new(
        signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256
    ).hexdigest()

    host_name = f"https://{bucket}.s3.amazonaws.com"
    signed_url = f"{host_name}{canonical_uri}?{canonical_query_string}&X-Amz-Signature={signature}"
    return signed_url, expiration


def split_path(path: str) -> Tuple[str, str, str]:
    """Extract bucket and key from uri.

    Based on https://stackoverflow.com/a/42985195
    """
    bucket_name: str = ""
    region: str = ""
    key: str = ""

    # http://bucket.s3.amazonaws.com/key1/key2
    match = re.search("^https?://([^.]+).s3.amazonaws.com(.*?)$", path)
    if match:
        bucket_name, key = match.group(1), match.group(2)

    # http://bucket.s3-aws-region.amazonaws.com/key1/key2
    match = re.search(r"^https?://([^.]+).s3-([^\.]+).amazonaws.com(.*?)$", path)
    if match:
        bucket_name, region, key = match.group(1), match.group(2), match.group(3)

    # http://s3.amazonaws.com/bucket/key1/key2
    match = re.search(r"^https?://s3.amazonaws.com/([^\/]+)(.*?)$", path)
    if match:
        bucket_name, key = match.group(1), match.group(2)

    # http://s3-aws-region.amazonaws.com/bucket/key1/key2
    match = re.search(r"^https?://s3-([^.]+).amazonaws.com/([^\/]+)(.*?)$", path)
    if match:
        bucket_name, region, key = match.group(2), match.group(1), match.group(3)

    if path.startswith("s3://"):
        path = path[len("s3://") :]
        bucket_name, _, key = path.partition("/")

    if not bucket_name:
        raise Error(f"Invalid path: '{path}'")

    return bucket_name, region, key


def combine_path(bucket: str, obj: str) -> str:
    return f"s3://{bucket}/{obj}"


def _get_md5(metadata: Mapping[str, Any]) -> Optional[str]:
    # https://aws.amazon.com/premiumsupport/knowledge-center/data-integrity-s3/
    if "Content-MD5" in metadata:
        b64_encoded = metadata["Content-MD5"]
        if b64_encoded is None:
            return None
        return base64.b64decode(b64_encoded).hex()
    else:
        return None
    return None


def _parse_timestamp(text: str) -> float:
    return datetime.datetime.strptime(
        text.replace("GMT", "Z"), "%a, %d %b %Y %H:%M:%S %z"
    ).timestamp()


def make_stat(item: Mapping[str, Any]) -> Stat:
    # AWS doesn't provide ctime, only mtime.
    # https://stackoverflow.com/a/40699793
    mtime = _parse_timestamp(item["Last-Modified"])
    return Stat(
        size=int(item["Content-Length"]),
        mtime=mtime,
        ctime=mtime,
        md5=_get_md5(item),
        version=item["Etag"],
    )


class StreamingReadFile(BaseStreamingReadFile):
    def __init__(self, ctx: Context, path: str) -> None:
        st = maybe_stat(ctx, path)
        if st is None:
            raise FileNotFoundError(f"No such file or bucket: '{path}'")
        super().__init__(ctx=ctx, path=path, size=st.size)

    def _request_chunk(
        self, streaming: bool, start: int, end: Optional[int] = None
    ) -> urllib3.response.HTTPResponse:
        raise NotImplementedError()


class StreamingWriteFile(BaseStreamingWriteFile):
    def __init__(self, ctx: Context, path: str) -> None:
        raise NotImplementedError()

    def _upload_chunk(self, chunk: bytes, finalize: bool) -> None:
        raise NotImplementedError()


def maybe_stat(ctx: Context, path: str) -> Optional[Stat]:
    bucket, _, blob = split_path(path)
    if blob == "":
        return None
    req = Request(
        url=build_url(bucket, "/{object}", object=blob),
        method="HEAD",
        success_codes=(200, 404),
    )
    resp = execute_api_request(ctx, req)
    if resp.status != 200:
        return None
    return make_stat(resp.headers)


def remove(ctx: Context, path: str) -> bool:
    raise NotImplementedError()


def maybe_update_md5(ctx: Context, path: str, generation: str, hexdigest: str) -> bool:
    raise NotImplementedError()


def parallel_upload(
    ctx: Context,
    executor: concurrent.futures.Executor,
    src: str,
    dst: str,
    return_md5: bool,
) -> Optional[str]:
    raise NotImplementedError()


access_token_manager = TokenManager(_get_access_token)
