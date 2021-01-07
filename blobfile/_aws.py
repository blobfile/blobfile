import base64
import binascii
import concurrent.futures
import datetime
import hashlib
import json
import logging
import math
import os
import platform
import re
import socket
import time
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


def build_url(template: str, **data: str) -> str:
    raise NotImplementedError()


def create_api_request(req: Request, access_token: str) -> Request:
    raise NotImplementedError()


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
        strip_v = str(v).lower()
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


def split_path(path: str) -> Tuple[str, str]:
    raise NotImplementedError()


def combine_path(bucket: str, obj: str) -> str:
    raise NotImplementedError()


def get_md5(metadata: Mapping[str, Any]) -> Optional[str]:
    raise NotImplementedError()


def make_stat(item: Mapping[str, Any]) -> Stat:
    raise NotImplementedError()


def execute_api_request(ctx: Context, req: Request) -> urllib3.HTTPResponse:
    raise NotImplementedError()


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
    raise NotImplementedError()


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
