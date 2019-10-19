import urllib.parse
import json
import base64
import os
import time
import platform
import datetime
import hashlib
import binascii

from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

from . import common
from .common import Request

MAX_EXPIRATION = 7 * 24 * 60 * 60


def _b64encode(s):
    if isinstance(s, str):
        s = s.encode("utf8")
    return base64.urlsafe_b64encode(s)


def _sign(private_key, msg):
    key = RSA.import_key(private_key)
    h = SHA256.new(msg)
    return pkcs1_15.new(key).sign(h)


def _create_jwt(private_key, data):
    header_b64 = _b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}))
    body_b64 = _b64encode(json.dumps(data))
    to_sign = header_b64 + b"." + body_b64
    signature_b64 = _b64encode(_sign(private_key, to_sign))
    return header_b64 + b"." + body_b64 + b"." + signature_b64


def _create_token_request(client_email, private_key, scopes):
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


def _refresh_access_token_request(client_id, client_secret, refresh_token):
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


def _load_credentials():
    if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
        creds_path = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
        if not os.path.exists(creds_path):
            raise Exception(
                f"credentials not found at {creds_path} specified by environment variable 'GOOGLE_APPLICATION_CREDENTIALS'"
            )
        with open(creds_path) as f:
            return json.load(f)
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
            return json.load(f)
    raise Exception(
        "credentials not found, please login with 'gcloud auth application-default login' or else set the 'GOOGLE_APPLICATION_CREDENTIALS' environment variable to the path of a JSON format service account key"
    )


def create_access_token_request(scopes):
    creds = _load_credentials()
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
        raise Exception("credentials not recognized")


def build_url(template, **data):
    return common.build_url("https://www.googleapis.com", template, **data)


def create_api_request(access_token, **kwargs):
    return common.create_authenticated_request(
        access_token=access_token, encoding="json", **kwargs
    )


def generate_signed_url(
    bucket, name, expiration, method="GET", params=None, headers=None
):
    if params is None:
        params = {}

    if headers is None:
        headers = {}

    # https://cloud.google.com/storage/docs/access-control/signing-urls-manually
    creds = _load_credentials()
    if "private_key" not in creds:
        raise Exception(
            "private key not found in credentials, please set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to a JSON key for a service account to use this call"
        )

    if expiration > MAX_EXPIRATION:
        raise Exception(
            f"expiration can't be longer than {MAX_EXPIRATION} seconds (7 days)."
        )

    escaped_object_name = urllib.parse.quote(name, safe="")
    canonical_uri = f"/{bucket}/{escaped_object_name}"

    datetime_now = datetime.datetime.utcnow()
    request_timestamp = datetime_now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = datetime_now.strftime("%Y%m%d")

    credential_scope = f"{datestamp}/auto/storage/goog4_request"
    credential = f"{creds['client_email']}/{credential_scope}"
    headers["host"] = "storage.googleapis.com"

    canonical_headers = ""
    ordered_headers = sorted(headers.items())
    for k, v in ordered_headers:
        lower_k = str(k).lower()
        strip_v = str(v).lower()
        canonical_headers += f"{lower_k}:{strip_v}\n"

    signed_headers_parts = []
    for k, _ in ordered_headers:
        lower_k = str(k).lower()
        signed_headers_parts.append(lower_k)
    signed_headers = ";".join(signed_headers_parts)

    params["X-Goog-Algorithm"] = "GOOG4-RSA-SHA256"
    params["X-Goog-Credential"] = credential
    params["X-Goog-Date"] = request_timestamp
    params["X-Goog-Expires"] = expiration
    params["X-Goog-SignedHeaders"] = signed_headers

    canonical_query_string_parts = []
    ordered_params = sorted(params.items())
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
    return signed_url


def split_url(path):
    url = urllib.parse.urlparse(path)
    assert url.scheme == "gs"
    return url.netloc, url.path[1:]
