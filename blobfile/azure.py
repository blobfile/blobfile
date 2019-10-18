import urllib.parse
import os
import json
import hmac
import base64
import datetime

from . import common


def _create_token_request(appId, tenant, password, scope):
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-client-creds-grant-flow#request-an-access-token
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code
    # https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#use-oauth-access-tokens-for-authentication
    # https://docs.microsoft.com/en-us/rest/api/azure/
    # https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory
    # az ad sp create-for-rbac --name <name>
    # az account list
    # az role assignment create --role "Storage Blob Data Contributor" --assignee <appid> --scope "/subscriptions/<sub id>"
    data = {
        "grant_type": "client_credentials",
        "client_id": appId,
        "client_secret": password,
        "resource": scope,
    }
    return common.Request(
        url=f"https://login.microsoftonline.com/{tenant}/oauth2/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode(data).encode("utf8"),
    )


def _load_credentials():
    if "AZURE_APPLICATION_CREDENTIALS" in os.environ:
        creds_path = os.environ["AZURE_APPLICATION_CREDENTIALS"]
        if not os.path.exists(creds_path):
            raise Exception(
                "credentials not found at {creds_path} specified by environment variable 'AZURE_APPLICATION_CREDENTIALS'"
            )
        with open(creds_path) as f:
            return json.load(f)
    raise Exception(
        "credentials not found, please create an account with 'az ad sp create-for-rbac --name <name>' and set the 'AZURE_APPLICATION_CREDENTIALS' environment variable to the path of the output from that command"
    )


def create_access_token_request(scope):
    creds = _load_credentials()
    return _create_token_request(
        appId=creds["appId"],
        password=creds["password"],
        tenant=creds["tenant"],
        scope=scope,
    )


def create_api_request(access_token, **kwargs):
    req = common.create_authenticated_request(
        access_token=access_token, encoding="xml", **kwargs
    )
    # https://docs.microsoft.com/en-us/rest/api/storageservices/previous-azure-storage-service-versions
    req.headers["x-ms-version"] = "2019-02-02"
    req.headers["x-ms-date"] = datetime.datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    return req


def create_user_delegation_sas_request(access_token, account):
    # https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
    now = datetime.datetime.utcnow()
    start = (now + datetime.timedelta(hours=-1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expiration = now + datetime.timedelta(days=6)
    expiry = expiration.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        create_api_request(
            access_token=access_token,
            url=f"https://{account}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
            method="POST",
            data={"KeyInfo": {"Start": start, "Expiry": expiry}},
        ),
        expiration,
    )


def generate_signed_url(key, url):
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
        # # this is documented on a different page
        # # https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas#specifying-the-signed-identifier
        # params["si"], # not sure where this is supposed to go
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
        "",  # unknown
    )
    string_to_sign = "\n".join(parts_to_sign)
    params["sig"] = base64.b64encode(
        hmac.digest(
            base64.b64decode(key["Value"]), string_to_sign.encode("utf8"), "sha256"
        )
    )
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    return url + "?" + query
