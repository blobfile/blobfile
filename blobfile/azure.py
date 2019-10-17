import urllib.parse
import os
import json

from .common import Request


def create_token_request(appId, tenant, password, scope):
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
    return Request(
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
    return create_token_request(
        appId=creds["appId"],
        password=creds["password"],
        tenant=creds["tenant"],
        scope=scope,
    )
