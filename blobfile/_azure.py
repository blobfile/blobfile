import urllib.parse
import os
import json
import hmac
import base64
import time
import calendar
import datetime
import re
from typing import Any, Mapping, Dict, Optional, Tuple, Sequence, List

import xmltodict
import urllib3

from blobfile import _common as common
from blobfile._common import (
    Request,
    Error,
    Stat,
    Context,
    INVALID_HOSTNAME_STATUS,
    TokenManager,
)

SHARED_KEY = "shared_key"
OAUTH_TOKEN = "oauth_token"
ANONYMOUS = "anonymous"

# it looks like azure signed urls cannot exceed the lifetime of the token used
# to create them, so don't keep the key around too long
SAS_TOKEN_EXPIRATION_SECONDS = 60 * 60
# these seem to be expired manually, but we don't currently detect that
SHARED_KEY_EXPIRATION_SECONDS = 24 * 60 * 60


def _load_credentials() -> Dict[str, Any]:
    # https://github.com/Azure/azure-sdk-for-python/tree/master/sdk/identity/azure-identity#environment-variables
    # AZURE_STORAGE_KEY seems to be the environment variable mentioned by the az cli
    # AZURE_STORAGE_ACCOUNT_KEY is mentioned elsewhere on the internet
    for varname in ["AZURE_STORAGE_KEY", "AZURE_STORAGE_ACCOUNT_KEY"]:
        if varname in os.environ:
            result = dict(storageAccountKey=os.environ[varname])
            if "AZURE_STORAGE_ACCOUNT" in os.environ:
                result["account"] = os.environ["AZURE_STORAGE_ACCOUNT"]
            return result

    if "AZURE_APPLICATION_CREDENTIALS" in os.environ:
        creds_path = os.environ["AZURE_APPLICATION_CREDENTIALS"]
        if not os.path.exists(creds_path):
            raise Error(
                f"Credentials not found at '{creds_path}' specified by environment variable 'AZURE_APPLICATION_CREDENTIALS'"
            )
        with open(creds_path) as f:
            return json.load(f)

    if "AZURE_CLIENT_ID" in os.environ:
        return dict(
            appId=os.environ["AZURE_CLIENT_ID"],
            password=os.environ["AZURE_CLIENT_SECRET"],
            tenant=os.environ["AZURE_TENANT_ID"],
        )

    if "AZURE_STORAGE_CONNECTION_STRING" in os.environ:
        connection_data = {}
        # technically this should be parsed according to the rules in https://www.connectionstrings.com/formating-rules-for-connection-strings/
        for part in os.environ["AZURE_STORAGE_CONNECTION_STRING"].split(";"):
            key, _, val = part.partition("=")
            connection_data[key.lower()] = val
        return dict(
            account=connection_data["accountname"],
            storageAccountKey=connection_data["accountkey"],
        )

    # look for a refresh token in the az command line credentials
    # https://mikhail.io/2019/07/how-azure-cli-manages-access-tokens/
    default_creds_path = os.path.expanduser("~/.azure/accessTokens.json")
    if os.path.exists(default_creds_path):
        with open(default_creds_path) as f:
            tokens = json.load(f)
            best_token = None
            for token in tokens:
                if best_token is None:
                    best_token = token
                else:
                    # expiresOn may be missing for tokens from service principals
                    if token.get("expiresOn", "") > best_token.get("expiresOn", ""):
                        best_token = token
            if best_token is not None:
                return best_token

    return {}


def load_subscription_ids() -> List[str]:
    """
    Return a list of subscription ids from the local azure profile
    the default subscription will appear first in the list
    """
    default_profile_path = os.path.expanduser("~/.azure/azureProfile.json")
    if not os.path.exists(default_profile_path):
        return []

    with open(default_profile_path, "rb") as f:
        # this file has a UTF-8 BOM
        profile = json.loads(f.read().decode("utf-8-sig"))
    subscriptions = profile["subscriptions"]

    def key_fn(x: Mapping[str, Any]) -> bool:
        return x["isDefault"]

    subscriptions.sort(key=key_fn, reverse=True)
    return [sub["id"] for sub in subscriptions]


def build_url(account: str, template: str, **data: str) -> str:
    return common.build_url(
        f"https://{account}.blob.core.windows.net", template, **data
    )


def create_access_token_request(
    creds: Mapping[str, str], scope: str, success_codes: Sequence[int] = (200,)
) -> Request:
    if "refreshToken" in creds:
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code#refreshing-the-access-tokens
        data = {
            "grant_type": "refresh_token",
            "refresh_token": creds["refreshToken"],
            "resource": scope,
        }
        tenant = "common"
    else:
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-client-creds-grant-flow#request-an-access-token
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code
        # https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#use-oauth-access-tokens-for-authentication
        # https://docs.microsoft.com/en-us/rest/api/azure/
        # https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory
        # az ad sp create-for-rbac --name <name>
        # az account list
        # az role assignment create --role "Storage Blob Data Contributor" --assignee <appid> --scope "/subscriptions/<account id>"
        data = {
            "grant_type": "client_credentials",
            "client_id": creds["appId"],
            "client_secret": creds["password"],
            "resource": scope,
        }
        tenant = creds["tenant"]
    return Request(
        url=f"https://login.microsoftonline.com/{tenant}/oauth2/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode(data).encode("utf8"),
        success_codes=success_codes,
    )


def create_user_delegation_sas_request(account: str) -> Request:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
    now = datetime.datetime.utcnow()
    start = (now + datetime.timedelta(hours=-1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expiration = now + datetime.timedelta(days=6)
    expiry = expiration.strftime("%Y-%m-%dT%H:%M:%SZ")
    return Request(
        url=f"https://{account}.blob.core.windows.net/",
        method="POST",
        params=dict(restype="service", comp="userdelegationkey"),
        data={"KeyInfo": {"Start": start, "Expiry": expiry}},
    )


def create_api_request(req: Request, auth: Tuple[str, str]) -> Request:
    if req.headers is None:
        headers = {}
    else:
        headers = dict(req.headers).copy()

    if req.params is None:
        params = {}
    else:
        params = dict(req.params).copy()

    # https://docs.microsoft.com/en-us/rest/api/storageservices/previous-azure-storage-service-versions
    headers["x-ms-version"] = "2019-02-02"
    headers["x-ms-date"] = datetime.datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    data = req.data
    if data is not None and isinstance(data, dict):
        data = xmltodict.unparse(data).encode("utf8")

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

    kind, token = auth
    if kind == SHARED_KEY:
        # make sure we are signing the request that has the ms headers added already
        headers["Authorization"] = sign_with_shared_key(result, token)
    elif kind == OAUTH_TOKEN:
        headers["Authorization"] = f"Bearer {token}"
    elif kind == ANONYMOUS:
        pass
    return result


def generate_signed_url(key: Mapping[str, str], url: str) -> Tuple[str, float]:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature
    # https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
    # https://docs.microsoft.com/en-us/rest/api/storageservices/service-sas-examples
    params = {
        "st": key["SignedStart"],
        "se": key["SignedExpiry"],
        "sks": key["SignedService"],
        "skt": key["SignedStart"],
        "ske": key["SignedExpiry"],
        "sktid": key["SignedTid"],
        "skoid": key["SignedOid"],
        # signed key version (param name not mentioned in docs)
        "skv": key["SignedVersion"],
        "sv": "2018-11-09",  # signed version
        "sr": "b",  # signed resource
        "sp": "r",  # signed permissions
        "sip": "",  # signed ip
        "si": "",  # signed identifier
        "spr": "https,http",  # signed http protocol
        "rscc": "",  # Cache-Control header
        "rscd": "",  # Content-Disposition header
        "rsce": "",  # Content-Encoding header
        "rscl": "",  # Content-Language header
        "rsct": "",  # Content-Type header
    }
    u = urllib.parse.urlparse(url)
    storage_account = u.netloc.split(".")[0]
    canonicalized_resource = urllib.parse.unquote(
        f"/blob/{storage_account}/{u.path[1:]}"
    )
    parts_to_sign = (
        params["sp"],
        params["st"],
        params["se"],
        canonicalized_resource,
        params["skoid"],
        params["sktid"],
        params["skt"],
        params["ske"],
        params["sks"],
        params["skv"],
        params["sip"],
        params["spr"],
        params["sv"],
        params["sr"],
        params["rscc"],
        params["rscd"],
        params["rsce"],
        params["rscl"],
        params["rsct"],
        # this is documented on a different page
        # https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas#specifying-the-signed-identifier
        params["si"],
    )
    string_to_sign = "\n".join(parts_to_sign)
    params["sig"] = base64.b64encode(
        hmac.digest(
            base64.b64decode(key["Value"]), string_to_sign.encode("utf8"), "sha256"
        )
    ).decode("utf8")
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    # convert to a utc struct_time by replacing the timezone
    ts = time.strptime(key["SignedExpiry"].replace("Z", "GMT"), "%Y-%m-%dT%H:%M:%S%Z")
    t = calendar.timegm(ts)
    return url + "?" + query, t


def split_path(path: str) -> Tuple[str, str, str]:
    if path.startswith("az://"):
        return split_az_path(path)
    elif path.startswith("https://"):
        return split_https_path(path)
    else:
        raise Error(f"Invalid path: '{path}'")


def split_az_path(path: str) -> Tuple[str, str, str]:
    parts = path[len("az://") :].split("/")
    if len(parts) < 2:
        raise Error(f"Invalid path: '{path}'")
    account = parts[0]
    container = parts[1]
    obj = "/".join(parts[2:])
    return account, container, obj


def split_https_path(path: str) -> Tuple[str, str, str]:
    parts = path[len("https://") :].split("/")
    if len(parts) < 2:
        raise Error(f"Invalid path: '{path}'")
    hostname = parts[0]
    container = parts[1]
    if not hostname.endswith(".blob.core.windows.net") or container == "":
        raise Error(f"Invalid path: '{path}'")
    obj = "/".join(parts[2:])
    account = hostname.split(".")[0]
    return account, container, obj


def combine_https_path(account: str, container: str, obj: str) -> str:
    return f"https://{account}.blob.core.windows.net/{container}/{obj}"


def combine_az_path(account: str, container: str, obj: str) -> str:
    return f"az://{account}/{container}/{obj}"


def sign_with_shared_key(req: Request, key: str) -> str:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
    params_to_sign = []
    if req.params is not None:
        for name, value in req.params.items():
            canonical_name = name.lower()
            params_to_sign.append(f"{canonical_name}:{value}")

    u = urllib.parse.urlparse(req.url)
    storage_account = u.netloc.split(".")[0]
    canonical_url = f"/{storage_account}/{u.path[1:]}"
    canonicalized_resource = "\n".join([canonical_url] + list(sorted(params_to_sign)))

    if req.headers is None:
        headers = {}
    else:
        headers = dict(req.headers)

    headers_to_sign = []
    for name, value in headers.items():
        canonical_name = name.lower()
        canonical_value = re.sub(r"\s+", " ", value).strip()
        if canonical_name.startswith("x-ms-"):
            headers_to_sign.append(f"{canonical_name}:{canonical_value}")
    canonicalized_headers = "\n".join(sorted(headers_to_sign))

    content_length = headers.get("Content-Length", "")
    if req.data is not None:
        content_length = str(len(req.data))

    parts_to_sign = [
        req.method,
        headers.get("Content-Encoding", ""),
        headers.get("Content-Language", ""),
        content_length,
        headers.get("Content-MD5", ""),
        headers.get("Content-Type", ""),
        headers.get("Date", ""),
        headers.get("If-Modified-Since", ""),
        headers.get("If-Match", ""),
        headers.get("If-None-Match", ""),
        headers.get("If-Unmodified-Since", ""),
        headers.get("Range", ""),
        canonicalized_headers,
        canonicalized_resource,
    ]
    string_to_sign = "\n".join(parts_to_sign)

    signature = base64.b64encode(
        hmac.digest(base64.b64decode(key), string_to_sign.encode("utf8"), "sha256")
    ).decode("utf8")

    return f"SharedKey {storage_account}:{signature}"


def _get_md5(metadata: Mapping[str, Any]) -> Optional[str]:
    if "Content-MD5" in metadata:
        b64_encoded = metadata["Content-MD5"]
        if b64_encoded is None:
            return None
        return base64.b64decode(b64_encoded).hex()
    else:
        return None


def _parse_timestamp(text: str) -> float:
    return datetime.datetime.strptime(
        text.replace("GMT", "Z"), "%a, %d %b %Y %H:%M:%S %z"
    ).timestamp()


def make_stat(item: Mapping[str, str]) -> Stat:
    if "Creation-Time" in item:
        raw_ctime = item["Creation-Time"]
    else:
        raw_ctime = item["x-ms-creation-time"]
    if "x-ms-meta-blobfilemtime" in item:
        mtime = float(item["x-ms-meta-blobfilemtime"])
    else:
        mtime = _parse_timestamp(item["Last-Modified"])
    return Stat(
        size=int(item["Content-Length"]),
        mtime=mtime,
        ctime=_parse_timestamp(raw_ctime),
        md5=_get_md5(item),
        version=item["Etag"],
    )


def _can_access_container(
    ctx: Context, account: str, container: str, auth: Tuple[str, str]
) -> bool:
    # https://myaccount.blob.core.windows.net/mycontainer?restype=container&comp=list
    success_codes = [200, 403, 404, INVALID_HOSTNAME_STATUS]
    if auth[0] == ANONYMOUS:
        # some containers can produce a 409 error "PublicAccessNotPermitted" when accessed with an anonymous account
        success_codes.append(409)

    def build_req() -> Request:
        req = Request(
            method="GET",
            url=build_url(account, "/{container}", container=container),
            params={"restype": "container", "comp": "list", "maxresults": "1"},
            success_codes=success_codes,
        )
        return create_api_request(req, auth=auth)

    resp = common.execute_request(ctx, build_req)
    # technically INVALID_HOSTNAME_STATUS means we can't access the account because it
    # doesn't exist, but to be consistent with how we treat this error elsewhere we
    # ignore it here
    if resp.status == INVALID_HOSTNAME_STATUS:
        return True
    # anonymous requests will for some reason get a 404 when they should get a 403
    # so treat a 404 from anon requests as a 403
    if resp.status == 404 and auth[0] == ANONYMOUS:
        return False
    # if the container list succeeds or the container doesn't exist, return success
    return resp.status in (200, 404)


def _get_storage_account_id(
    ctx: Context, subscription_id: str, account: str, auth: Tuple[str, str]
) -> Optional[str]:
    # get a list of storage accounts
    def build_req() -> Request:
        req = Request(
            method="GET",
            url=f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts",
            params={"api-version": "2019-04-01"},
            success_codes=(200, 401, 403),
        )
        return create_api_request(req, auth=auth)

    resp = common.execute_request(ctx, build_req)
    if resp.status in (401, 403):
        # we aren't allowed to query this for this subscription, skip it
        return None

    out = json.loads(resp.data)
    # check if we found the storage account we are looking for
    for obj in out["value"]:
        if obj["name"] == account:
            return obj["id"]
    return None


def _get_storage_account_key(
    ctx: Context, account: str, container: str, creds: Mapping[str, Any]
) -> Optional[Tuple[Any, float]]:
    # azure resource manager has very low limits on number of requests, so we have
    # to be careful to avoid extra requests here
    # https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#storage-resource-provider-limits

    # in general, this code path should be avoided by using a service principal and
    # giving it access to the bucket

    # get an access token for the management service
    def build_req() -> Request:
        return create_access_token_request(
            creds=creds, scope="https://management.azure.com/"
        )

    resp = common.execute_request(ctx, build_req)
    result = json.loads(resp.data)
    auth = (OAUTH_TOKEN, result["access_token"])

    # attempt to use list of subscriptions from the azure cli tool
    stored_subscription_ids = load_subscription_ids()

    storage_account_id = None
    for subscription_id in stored_subscription_ids:
        storage_account_id = _get_storage_account_id(
            ctx, subscription_id, account, auth
        )
        if storage_account_id is not None:
            break
    else:
        # if we didn't find the storage account we are looking for, check to see if there
        # are any subscriptions that we did not query
        def build_req() -> Request:
            req = Request(
                method="GET",
                url="https://management.azure.com/subscriptions",
                params={"api-version": "2020-01-01"},
            )
            return create_api_request(req, auth=auth)

        resp = common.execute_request(ctx, build_req)
        result = json.loads(resp.data)
        unchecked_subscription_ids = [
            item["subscriptionId"]
            for item in result["value"]
            if item["subscriptionId"] not in stored_subscription_ids
        ]

        for subscription_id in unchecked_subscription_ids:
            storage_account_id = _get_storage_account_id(
                ctx, subscription_id, account, auth
            )
            if storage_account_id is not None:
                break
        else:
            # we failed to find the storage account, give up
            return None

    def build_req() -> Request:
        req = Request(
            method="POST",
            url=f"https://management.azure.com{storage_account_id}/listKeys",
            params={"api-version": "2019-04-01"},
        )
        return create_api_request(req, auth=auth)

    resp = common.execute_request(ctx, build_req)
    result = json.loads(resp.data)
    for key in result["keys"]:
        if key["permissions"] == "FULL":
            storage_key_auth = (SHARED_KEY, key["value"])
            if _can_access_container(ctx, account, container, storage_key_auth):
                return storage_key_auth
            else:
                raise Error(
                    f"Found storage account key, but it was unable to access storage account: '{account}' and container: '{container}'"
                )
    raise Error(
        f"Storage account was found, but storage account keys were missing: '{account}'"
    )


def _get_access_token(ctx: Context, key: Any) -> Tuple[Any, float]:
    account, container = key
    now = time.time()
    creds = _load_credentials()
    if "storageAccountKey" in creds:
        if "account" in creds:
            if creds["account"] != account:
                raise Error(
                    f"Found credentials for account '{creds['account']}' but needed credentials for account '{account}'"
                )
        auth = (SHARED_KEY, creds["storageAccountKey"])
        if _can_access_container(ctx, account, container, auth):
            return (auth, now + SHARED_KEY_EXPIRATION_SECONDS)
    elif "refreshToken" in creds:
        # we have a refresh token, convert it into an access token for this account
        def build_req() -> Request:
            return create_access_token_request(
                creds=creds,
                scope=f"https://{account}.blob.core.windows.net/",
                success_codes=(200, 400),
            )

        resp = common.execute_request(ctx, build_req)
        result = json.loads(resp.data)
        if resp.status == 400:
            if (
                (
                    result["error"] == "invalid_grant"
                    and "AADSTS700082" in result["error_description"]
                )
                or (
                    result["error"] == "interaction_required"
                    and "AADSTS50078" in result["error_description"]
                )
                or (
                    result["error"] == "interaction_required"
                    and "AADSTS50076" in result["error_description"]
                )
            ):
                raise Error(
                    "Your refresh token is no longer valid, please run `az login` to get a new one"
                )
            else:
                raise Error(
                    f"Encountered an error when requesting an access token: `{result['error']}: {result['error_description']}`.  You can attempt to fix this by re-running `az login`."
                )

        auth = (OAUTH_TOKEN, result["access_token"])

        # for some azure accounts this access token does not work, check if it works
        if _can_access_container(ctx, account, container, auth):
            return (auth, now + float(result["expires_in"]))

        if ctx.use_azure_storage_account_key_fallback:
            # fall back to getting the storage keys
            storage_account_key_auth = _get_storage_account_key(
                ctx=ctx, account=account, container=container, creds=creds
            )
            if storage_account_key_auth is not None:
                return (storage_account_key_auth, now + SHARED_KEY_EXPIRATION_SECONDS)
    elif "appId" in creds:
        # we have a service principal, get an oauth token
        def build_req() -> Request:
            return create_access_token_request(
                creds=creds, scope="https://storage.azure.com/"
            )

        resp = common.execute_request(ctx, build_req)
        result = json.loads(resp.data)
        auth = (OAUTH_TOKEN, result["access_token"])
        if _can_access_container(ctx, account, container, auth):
            return (auth, now + float(result["expires_in"]))

        if ctx.use_azure_storage_account_key_fallback:
            # fall back to getting the storage keys
            storage_account_key_auth = _get_storage_account_key(
                ctx=ctx, account=account, container=container, creds=creds
            )
            if storage_account_key_auth is not None:
                return (storage_account_key_auth, now + SHARED_KEY_EXPIRATION_SECONDS)

    # oddly, it seems that if you request a public container with a valid azure account, you cannot list the bucket
    # but if you list it with no account, that works fine
    anonymous_auth = (ANONYMOUS, "")
    if _can_access_container(ctx, account, container, anonymous_auth):
        return (anonymous_auth, float("inf"))

    msg = f"Could not find any credentials that grant access to storage account: '{account}' and container: '{container}'"
    if len(creds) == 0:
        msg += """

No Azure credentials were found.  If the container is not marked as public, please do one of the following:

* Log in with 'az login', blobfile will use your default credentials to lookup your storage account key
* Set the environment variable 'AZURE_STORAGE_KEY' to your storage account key which you can find by following this guide: https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
* Create an account with 'az ad sp create-for-rbac --name <name>' and set the 'AZURE_APPLICATION_CREDENTIALS' environment variable to the path of the output from that command or individually set the 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', and 'AZURE_TENANT_ID' environment variables"""
    raise Error(msg)


def _get_sas_token(ctx: Context, key: Any) -> Tuple[Any, float]:
    auth = access_token_manager.get_token(ctx, key=key)
    if auth[0] == ANONYMOUS:
        # for public containers, use None as the token so that this will be cached
        # and we can tell when we don't have a real SAS token for a container
        return (None, time.time() + SAS_TOKEN_EXPIRATION_SECONDS)

    account, container = key

    def build_req() -> Request:
        req = create_user_delegation_sas_request(account=account)
        auth = access_token_manager.get_token(ctx, key=key)
        if auth[0] != OAUTH_TOKEN:
            raise Error(
                "Only OAuth tokens can be used to get SAS tokens. You should set the Storage "
                "Blob Data Reader or Storage Blob Data Contributor IAM role. You can run "
                f"`az storage blob list --auth-mode login --account-name {account} --container {container}` "
                "to confirm that the missing role is the issue."
            )
        return create_api_request(req, auth=auth)

    resp = common.execute_request(ctx, build_req)
    out = xmltodict.parse(resp.data)
    t = time.time() + SAS_TOKEN_EXPIRATION_SECONDS
    return out["UserDelegationKey"], t


def execute_api_request(ctx: Context, req: Request) -> urllib3.HTTPResponse:
    u = urllib.parse.urlparse(req.url)
    account = u.netloc.split(".")[0]
    path_parts = u.path.split("/")
    if len(path_parts) < 2:
        raise Error("missing container from path")
    container = u.path.split("/")[1]

    def build_req() -> Request:
        return create_api_request(
            req, auth=access_token_manager.get_token(ctx, key=(account, container))
        )

    return common.execute_request(ctx, build_req)


access_token_manager = TokenManager(_get_access_token)

sas_token_manager = TokenManager(_get_sas_token)
