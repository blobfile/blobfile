import urllib.parse
import json
import base64
import os
import time
import platform
import datetime
import hashlib
import binascii
import copy
from typing import Mapping, Any, Optional, Tuple, List

from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

from . import common
from .common import Request, Error

MAX_EXPIRATION = 7 * 24 * 60 * 60


def _b64encode(s: bytes) -> bytes:
    return base64.urlsafe_b64encode(s)


def _sign(private_key: str, msg: bytes) -> bytes:
    key = RSA.import_key(private_key)
    h = SHA256.new(msg)
    return pkcs1_15.new(key).sign(h)


def _create_jwt(private_key: str, data: Mapping[str, Any]) -> bytes:
    header_b64 = _b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf8"))
    body_b64 = _b64encode(json.dumps(data).encode("utf8"))
    to_sign = header_b64 + b"." + body_b64
    signature_b64 = _b64encode(_sign(private_key, to_sign))
    return header_b64 + b"." + body_b64 + b"." + signature_b64


def _create_token_request(
    client_email: str, private_key: str, scopes: List[str]
) -> Request:
    # https://developers.google.com/identity/protocols/OAuth2ServiceAccount
    now = time.time()
    claim_set = {
        "iss": client_email,
        "scope": " ".join(scopes),
        "aud": "https://www.googleapis.com/oauth2/v4/token",
        "exp": now + 60 * 60,
        "iat": now,
    }
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": _create_jwt(private_key, claim_set),
    }
    return Request(
        url="https://www.googleapis.com/oauth2/v4/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode(data).encode("utf8"),
    )


def _refresh_access_token_request(
    client_id: str, client_secret: str, refresh_token: str
) -> Request:
    # https://developers.google.com/identity/protocols/OAuth2WebServer#offline
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    return Request(
        url="https://www.googleapis.com/oauth2/v4/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode(data).encode("utf8"),
    )


def _load_credentials() -> Tuple[Mapping[str, Any], Optional[str]]:
    if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
        creds_path = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
        if not os.path.exists(creds_path):
            return (
                {},
                f"credentials not found at {creds_path} specified by environment variable 'GOOGLE_APPLICATION_CREDENTIALS'",
            )
        with open(creds_path) as f:
            return json.load(f), None
    if platform.system() == "Windows":
        # https://www.jhanley.com/google-cloud-application-default-credentials/
        default_creds_path = os.path.join(
            os.environ["APPDATA"], "gcloud/application_default_credentials.json"
        )
    else:
        default_creds_path = os.path.join(
            os.environ["HOME"], ".config/gcloud/application_default_credentials.json"
        )

    if os.path.exists(default_creds_path):
        with open(default_creds_path) as f:
            return json.load(f), None
    return (
        {},
        "credentials not found, please login with 'gcloud auth application-default login' or else set the 'GOOGLE_APPLICATION_CREDENTIALS' environment variable to the path of a JSON format service account key",
    )


def create_access_token_request(scopes: List[str]) -> Request:
    creds, err = _load_credentials()
    if err is not None:
        raise Error(err)
    if "private_key" in creds:
        # looks like GCS does not support the no-oauth flow https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth
        return _create_token_request(
            creds["client_email"], creds["private_key"], scopes
        )
    elif "refresh_token" in creds:
        return _refresh_access_token_request(
            refresh_token=creds["refresh_token"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
    else:
        raise Error("Credentials not recognized")


def have_credentials() -> bool:
    _, err = _load_credentials()
    return err is None


def build_url(template: str, **data: str) -> str:
    return common.build_url("https://www.googleapis.com", template, **data)


def make_api_request(req: Request, access_token: str) -> Request:
    if req.headers is None:
        headers = {}
    else:
        headers = dict(req.headers).copy()
    headers["Authorization"] = f"Bearer {access_token}"
    data = req.data
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = json.dumps(data).encode("utf8")
    result = copy.copy(req)
    result.headers = headers
    result.data = data
    return result


def generate_signed_url(
    bucket: str,
    name: str,
    expiration: float,
    method: str = "GET",
    params: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Tuple[str, Optional[float]]:
    if params is None:
        p = {}
    else:
        p = dict(params).copy()

    if headers is None:
        h = {}
    else:
        h = dict(headers).copy()

    # https://cloud.google.com/storage/docs/access-control/signing-urls-manually
    creds, err = _load_credentials()
    if err is not None:
        raise Error(err)
    if "private_key" not in creds:
        raise Error(
            "Private key not found in credentials.  Please set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to a JSON key for a service account to use this call"
        )

    if expiration > MAX_EXPIRATION:
        raise Error(f"Expiration can't be longer than {MAX_EXPIRATION} seconds.")

    escaped_object_name = urllib.parse.quote(name, safe="")
    canonical_uri = f"/{bucket}/{escaped_object_name}"

    datetime_now = datetime.datetime.utcnow()
    request_timestamp = datetime_now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = datetime_now.strftime("%Y%m%d")

    credential_scope = f"{datestamp}/auto/storage/goog4_request"
    credential = f"{creds['client_email']}/{credential_scope}"
    h["host"] = "storage.googleapis.com"

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

    p["X-Goog-Algorithm"] = "GOOG4-RSA-SHA256"
    p["X-Goog-Credential"] = credential
    p["X-Goog-Date"] = request_timestamp
    p["X-Goog-Expires"] = str(expiration)
    p["X-Goog-SignedHeaders"] = signed_headers

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
            "GOOG4-RSA-SHA256",
            request_timestamp,
            credential_scope,
            canonical_request_hash,
        ]
    )

    signature = binascii.hexlify(
        _sign(creds["private_key"], string_to_sign.encode("utf8"))
    ).decode("utf8")
    host_name = "https://storage.googleapis.com"
    signed_url = f"{host_name}{canonical_uri}?{canonical_query_string}&X-Goog-Signature={signature}"
    return signed_url, expiration


def split_url(path: str) -> Tuple[str, str]:
    if not path.startswith("gs://"):
        raise Error(f"Invalid path: '{path}'")
    path = path[len("gs://") :]
    bucket, _, obj = path.partition("/")
    if bucket == "":
        raise Error(f"Invalid path: '{path}'")
    return bucket, obj


def combine_url(bucket: str, obj: str) -> str:
    return f"gs://{bucket}/{obj}"
