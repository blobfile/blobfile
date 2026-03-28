"""Azure cloud configuration with ARM metadata discovery.

Supports multiple Azure clouds (Public, US Government, airgapped) by discovering
endpoints from the ARM cloud metadata endpoint.

`ARM_CLOUD_METADATA_URL` is treated as the full metadata URL, for example:
`https://management.usgovcloudapi.net/metadata/endpoints?api-version=2019-05-01`.

Configuration resolution order:
    1. ARM_CLOUD_METADATA_URL env var set -> fetch metadata, select cloud by AZURE_CLOUD
       or by matching the metadata URL's ARM endpoint
    2. AZURE_CLOUD env var set (no metadata URL) -> use built-in preset
    3. Default -> public cloud preset (no network call)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

STORAGE_AUDIENCE = "https://storage.azure.com"


@dataclass(frozen=True)
class AzureCloudConfig:
    storage_endpoint_suffix: str
    login_endpoint: str
    arm_endpoint: str

    def blob_endpoint_url(self, account: str) -> str:
        return f"https://{account}.blob.{self.storage_endpoint_suffix}"

    @property
    def authority_host(self) -> str:
        parsed = urllib.parse.urlsplit(self.login_endpoint)
        return (parsed.netloc or parsed.path).rstrip("/")

    def storage_scope(self, account: str | None = None) -> str:
        if account:
            return f"https://{account}.blob.{self.storage_endpoint_suffix}/.default"
        return f"{STORAGE_AUDIENCE}/.default"


def _strip_trailing_slash(url: str) -> str:
    return url.rstrip("/")


def _arm_endpoint_from_metadata_url(metadata_url: str) -> str:
    parsed = urllib.parse.urlsplit(metadata_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid ARM metadata URL '{metadata_url}'")
    return _strip_trailing_slash(f"{parsed.scheme}://{parsed.netloc}")


AZURE_PUBLIC_CLOUD = AzureCloudConfig(
    storage_endpoint_suffix="core.windows.net",
    login_endpoint="https://login.microsoftonline.com",
    arm_endpoint="https://management.azure.com",
)

AZURE_US_GOV_CLOUD = AzureCloudConfig(
    storage_endpoint_suffix="core.usgovcloudapi.net",
    login_endpoint="https://login.microsoftonline.us",
    arm_endpoint="https://management.usgovcloudapi.net",
)

_CLOUD_PRESETS: dict[str, AzureCloudConfig] = {
    "AzureCloud": AZURE_PUBLIC_CLOUD,
    "AzureUSGovernment": AZURE_US_GOV_CLOUD,
}


def _fetch_arm_cloud_metadata(metadata_url: str) -> list[dict[str, Any]]:
    req = urllib.request.Request(metadata_url, headers={"User-Agent": "blobfile"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            metadata = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch ARM cloud metadata from '{metadata_url}': {e}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"ARM cloud metadata from '{metadata_url}' was not valid JSON: {e}"
        ) from e

    if not isinstance(metadata, list):
        raise RuntimeError(
            f"ARM cloud metadata from '{metadata_url}' had unexpected type "
            f"{type(metadata).__name__}; expected a list of cloud definitions"
        )
    return metadata


def _cloud_config_from_metadata(cloud_entry: dict[str, Any]) -> AzureCloudConfig:
    try:
        storage_endpoint_suffix = cloud_entry["suffixes"]["storage"]
        login_endpoint = cloud_entry["authentication"]["loginEndpoint"]
        arm_endpoint = cloud_entry["resourceManager"]
    except KeyError as e:
        raise ValueError(f"ARM metadata entry missing required field {e!s}: {cloud_entry!r}") from e

    return AzureCloudConfig(
        storage_endpoint_suffix=storage_endpoint_suffix,
        login_endpoint=_strip_trailing_slash(login_endpoint),
        arm_endpoint=_strip_trailing_slash(arm_endpoint),
    )


def _select_cloud_from_metadata(
    metadata: list[dict[str, Any]], cloud_name: str | None, arm_endpoint: str | None = None
) -> dict[str, Any]:
    if cloud_name:
        for entry in metadata:
            if entry.get("name") == cloud_name:
                return entry
        available = [entry.get("name", "unknown") for entry in metadata]
        raise ValueError(
            f"Cloud '{cloud_name}' not found in ARM metadata. Available clouds: {available}"
        )

    if not metadata:
        raise ValueError("ARM metadata response contained no cloud definitions")

    if arm_endpoint:
        normalized_arm_endpoint = _strip_trailing_slash(arm_endpoint)
        for entry in metadata:
            resource_manager = entry.get("resourceManager")
            if isinstance(resource_manager, str):
                if _strip_trailing_slash(resource_manager) == normalized_arm_endpoint:
                    return entry

        available = [
            _strip_trailing_slash(resource_manager)
            for entry in metadata
            if isinstance(resource_manager := entry.get("resourceManager"), str)
        ]
        raise ValueError(
            f"ARM endpoint '{normalized_arm_endpoint}' not found in ARM metadata. "
            f"Available resourceManager endpoints: {available}"
        )

    return metadata[0]


def resolve_cloud_config(metadata_url: str | None, cloud_name: str | None) -> AzureCloudConfig:
    if metadata_url:
        metadata = _fetch_arm_cloud_metadata(metadata_url)
        arm_endpoint = _arm_endpoint_from_metadata_url(metadata_url)
        cloud_entry = _select_cloud_from_metadata(metadata, cloud_name, arm_endpoint=arm_endpoint)
        return _cloud_config_from_metadata(cloud_entry)

    if cloud_name:
        if cloud_name in _CLOUD_PRESETS:
            return _CLOUD_PRESETS[cloud_name]
        raise ValueError(
            f"Unknown cloud '{cloud_name}'. Known clouds: {list(_CLOUD_PRESETS.keys())}. "
            f"Set ARM_CLOUD_METADATA_URL to discover endpoints for custom clouds."
        )

    return AZURE_PUBLIC_CLOUD


def get_cloud_config() -> AzureCloudConfig:
    return resolve_cloud_config(
        metadata_url=os.environ.get("ARM_CLOUD_METADATA_URL"),
        cloud_name=os.environ.get("AZURE_CLOUD"),
    )
