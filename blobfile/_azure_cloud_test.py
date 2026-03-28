from __future__ import annotations

import os
import pickle
import sys
import urllib.error
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blobfile import _azure as azure
from blobfile import _common as common
from blobfile import _context as context
from blobfile import _ops as ops
from blobfile._azure_cloud import (
    AZURE_PUBLIC_CLOUD,
    AZURE_US_GOV_CLOUD,
    _arm_endpoint_from_metadata_url,
    _cloud_config_from_metadata,
    _fetch_arm_cloud_metadata,
    _select_cloud_from_metadata,
    get_cloud_config,
)

SAMPLE_ARM_METADATA = [
    {
        "name": "AzureCloud",
        "authentication": {
            "loginEndpoint": "https://login.microsoftonline.com/",
            "audiences": ["https://management.core.windows.net/", "https://management.azure.com/"],
        },
        "resourceManager": "https://management.azure.com/",
        "suffixes": {"storage": "core.windows.net", "keyVaultDns": "vault.azure.net"},
    },
    {
        "name": "AzureUSGovernment",
        "authentication": {
            "loginEndpoint": "https://login.microsoftonline.us",
            "audiences": ["https://management.core.usgovcloudapi.net"],
        },
        "resourceManager": "https://management.usgovcloudapi.net",
        "suffixes": {"storage": "core.usgovcloudapi.net", "keyVaultDns": "vault.usgovcloudapi.net"},
    },
]


class TestAzureCloudHelpers:
    def test_arm_endpoint_from_metadata_url(self):
        assert (
            _arm_endpoint_from_metadata_url(
                "https://management.azure.com/metadata/endpoints?api-version=2019-05-01"
            )
            == "https://management.azure.com"
        )
        assert (
            _arm_endpoint_from_metadata_url(
                "https://management.usgovcloudapi.net/metadata/endpoints?api-version=2019-05-01"
            )
            == "https://management.usgovcloudapi.net"
        )

    def test_fetch_arm_cloud_metadata_uses_supplied_url(self):
        response = MagicMock()
        response.read.return_value = b'[{"name":"AzureCloud","authentication":{"loginEndpoint":"https://login.microsoftonline.com/"},"resourceManager":"https://management.azure.com/","suffixes":{"storage":"core.windows.net"}}]'
        response.__enter__.return_value = response
        response.__exit__.return_value = False

        with patch("urllib.request.urlopen", return_value=response) as mock_urlopen:
            metadata = _fetch_arm_cloud_metadata(
                "https://management.azure.com/metadata/endpoints?api-version=2019-05-01"
            )

        request = mock_urlopen.call_args.args[0]
        assert request.full_url == (
            "https://management.azure.com/metadata/endpoints?api-version=2019-05-01"
        )
        assert metadata[0]["name"] == "AzureCloud"

    def test_fetch_arm_cloud_metadata_network_error(self):
        with patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")
        ):
            with pytest.raises(RuntimeError, match="Failed to fetch ARM cloud metadata"):
                _fetch_arm_cloud_metadata("https://management.invalid")

    def test_fetch_arm_cloud_metadata_invalid_json(self):
        response = MagicMock()
        response.read.return_value = b"{"
        response.__enter__.return_value = response
        response.__exit__.return_value = False

        with patch("urllib.request.urlopen", return_value=response):
            with pytest.raises(RuntimeError, match="was not valid JSON"):
                _fetch_arm_cloud_metadata("https://management.azure.com")

    def test_authority_host(self):
        assert AZURE_PUBLIC_CLOUD.authority_host == "login.microsoftonline.com"
        assert AZURE_US_GOV_CLOUD.authority_host == "login.microsoftonline.us"


class TestCloudConfigFromMetadata:
    def test_parses_public_cloud(self):
        assert _cloud_config_from_metadata(SAMPLE_ARM_METADATA[0]) == AZURE_PUBLIC_CLOUD

    def test_parses_us_gov_cloud(self):
        assert _cloud_config_from_metadata(SAMPLE_ARM_METADATA[1]) == AZURE_US_GOV_CLOUD

    def test_missing_required_field_raises_clear_error(self):
        bad_entry = {
            "name": "AzureCloud",
            "authentication": {},
            "resourceManager": "https://management.azure.com/",
            "suffixes": {"storage": "core.windows.net"},
        }
        with pytest.raises(ValueError, match="missing required field"):
            _cloud_config_from_metadata(bad_entry)


class TestSelectCloudFromMetadata:
    def test_select_by_name(self):
        entry = _select_cloud_from_metadata(SAMPLE_ARM_METADATA, "AzureUSGovernment")
        assert entry["name"] == "AzureUSGovernment"

    def test_select_first_when_no_name(self):
        entry = _select_cloud_from_metadata(SAMPLE_ARM_METADATA, None)
        assert entry["name"] == "AzureCloud"

    def test_select_by_resource_manager_when_no_name(self):
        entry = _select_cloud_from_metadata(
            SAMPLE_ARM_METADATA, None, "https://management.usgovcloudapi.net/"
        )
        assert entry["name"] == "AzureUSGovernment"

    def test_raises_on_unknown_name(self):
        with pytest.raises(ValueError, match="not found in ARM metadata"):
            _select_cloud_from_metadata(SAMPLE_ARM_METADATA, "AzureNonExistent")

    def test_raises_on_empty_metadata(self):
        with pytest.raises(ValueError, match="no cloud definitions"):
            _select_cloud_from_metadata([], None)


class TestGetCloudConfig:
    def test_default_is_public_cloud(self):
        with patch.dict(os.environ, {}, clear=True):
            assert get_cloud_config() == AZURE_PUBLIC_CLOUD

    def test_azure_cloud_selects_preset(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            assert get_cloud_config() == AZURE_US_GOV_CLOUD

    def test_azure_cloud_unknown_raises(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "UnknownCloud"}, clear=True):
            with pytest.raises(ValueError, match="Unknown cloud"):
                get_cloud_config()

    def test_arm_metadata_url_fetches_and_selects(self):
        with patch.dict(
            os.environ,
            {
                "ARM_CLOUD_METADATA_URL": "https://management.example.com/metadata/endpoints?api-version=2019-05-01",
                "AZURE_CLOUD": "AzureUSGovernment",
            },
            clear=True,
        ):
            with patch(
                "blobfile._azure_cloud._fetch_arm_cloud_metadata", return_value=SAMPLE_ARM_METADATA
            ) as mock_fetch:
                cloud = get_cloud_config()

        mock_fetch.assert_called_once_with(
            "https://management.example.com/metadata/endpoints?api-version=2019-05-01"
        )
        assert cloud == AZURE_US_GOV_CLOUD

    def test_arm_metadata_url_matches_resource_manager_when_name_unset(self):
        with patch.dict(
            os.environ,
            {
                "ARM_CLOUD_METADATA_URL": "https://management.usgovcloudapi.net/metadata/endpoints?api-version=2019-05-01"
            },
            clear=True,
        ):
            with patch(
                "blobfile._azure_cloud._fetch_arm_cloud_metadata", return_value=SAMPLE_ARM_METADATA
            ):
                cloud = get_cloud_config()

        assert cloud == AZURE_US_GOV_CLOUD


class TestLazyConfigResolution:
    def test_context_does_not_resolve_cloud_at_creation(self):
        with patch(
            "blobfile._common.resolve_cloud_config", return_value=AZURE_PUBLIC_CLOUD
        ) as mock_get:
            ctx = context.create_context()
            assert mock_get.call_count == 0
            assert ctx._conf.azure_cloud == AZURE_PUBLIC_CLOUD
            assert mock_get.call_count == 1
            assert ctx._conf.azure_cloud == AZURE_PUBLIC_CLOUD
            assert mock_get.call_count == 1

    def test_context_pins_cloud_env_before_first_use(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)

        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureCloud"}, clear=True):
            assert azure.join_paths(ctx._conf, "az://account/container/dir/", "blob") == (
                "https://account.blob.core.usgovcloudapi.net/container/dir/blob"
            )

    def test_pickled_config_uses_snapshotted_cloud(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)

        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureCloud"}, clear=True):
            conf = pickle.loads(pickle.dumps(ctx._conf))
            assert azure.combine_path(conf, "account", "container", "blob") == (
                "https://account.blob.core.usgovcloudapi.net/container/blob"
            )

    def test_configure_keeps_default_context_bound_to_live_env(self):
        with patch.dict(os.environ, {}, clear=True):
            try:
                ops.configure(output_az_paths=False)
                os.environ["AZURE_CLOUD"] = "AzureUSGovernment"
                assert ops.join("az://account/container/dir/", "blob") == (
                    "https://account.blob.core.usgovcloudapi.net/container/dir/blob"
                )
            finally:
                ops.configure()

    def test_https_path_helpers_do_not_fetch_metadata(self):
        with patch.dict(
            os.environ,
            {
                "ARM_CLOUD_METADATA_URL": "https://management.usgovcloudapi.net/metadata/endpoints?api-version=2019-05-01"
            },
            clear=True,
        ):
            ctx = context.create_context(output_az_paths=False)
            with patch(
                "blobfile._azure_cloud._fetch_arm_cloud_metadata", return_value=SAMPLE_ARM_METADATA
            ) as mock_fetch:
                path = "https://account.blob.core.usgovcloudapi.net/container/blob"
                dir_path = "https://account.blob.core.usgovcloudapi.net/container/dir/"

                assert ctx.basename(path) == "blob"
                assert ctx.dirname(path) == "https://account.blob.core.usgovcloudapi.net/container"
                assert (
                    ctx.join(dir_path, "blob")
                    == "https://account.blob.core.usgovcloudapi.net/container/dir/blob"
                )
                assert context._guess_isdir(dir_path, ctx._conf)
                assert mock_fetch.call_count == 0


class TestAzurePathHandling:
    def test_non_azure_paths_do_not_resolve_cloud(self):
        with patch(
            "blobfile._common.get_cloud_config", side_effect=AssertionError("should not resolve")
        ):
            assert not context._is_azure_path("C:\\temp\\file.txt")
            assert not context._is_azure_path("gs://bucket/blob")
            assert context._is_azure_path("az://account/container")
            assert not context._is_azure_path("https://example.com/blob")

    def test_azure_path_uses_active_cloud(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)
            path = azure.combine_path(ctx._conf, "account", "container", "blob")

            assert path == "https://account.blob.core.usgovcloudapi.net/container/blob"
            assert context._is_azure_path(path, ctx._conf)
            assert azure.split_path(path, conf=ctx._conf) == ("account", "container", "blob")
            assert azure.join_paths(ctx._conf, "az://account/container/dir/", "blob") == (
                "https://account.blob.core.usgovcloudapi.net/container/dir/blob"
            )

    def test_public_cloud_url_rejected_under_gov_cloud(self):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)
            public_url = "https://account.blob.core.windows.net/container/blob"

            assert not context._is_azure_path(public_url, ctx._conf)
            with pytest.raises(common.Error, match="Invalid path"):
                azure.split_path(public_url, conf=ctx._conf)

    def test_malformed_https_path_with_empty_container_is_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            ctx = context.create_context(output_az_paths=False)
            with pytest.raises(common.Error, match="Invalid path"):
                azure.split_path("https://account.blob.core.windows.net//blob", conf=ctx._conf)

    def test_cache_keys_include_cloud_identity(self):
        with patch.dict(os.environ, {}, clear=True):
            public_ctx = context.create_context()
            public_key = azure.azure_cache_key(public_ctx._conf, "account", "container")

        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            gov_ctx = context.create_context()
            gov_key = azure.azure_cache_key(gov_ctx._conf, "account", "container")

        assert public_key != gov_key


class TestAzureIdentityAuthority:
    def test_get_access_token_uses_authority_host(self, monkeypatch):
        calls: dict[str, str] = {}

        class FakeDefaultAzureCredential:
            def __init__(self, *, authority: str):
                calls["authority"] = authority

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get_token(self, scope: str):
                calls["scope"] = scope
                return SimpleNamespace(token="token", expires_on=123)

        azure_module = ModuleType("azure")
        identity_module = ModuleType("azure.identity")
        identity_module.DefaultAzureCredential = FakeDefaultAzureCredential
        azure_module.identity = identity_module

        monkeypatch.setitem(sys.modules, "azure", azure_module)
        monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
        monkeypatch.setattr(azure, "_can_access_container", lambda *args, **kwargs: True)

        with patch.dict(
            os.environ, {"AZURE_USE_IDENTITY": "1", "AZURE_CLOUD": "AzureUSGovernment"}, clear=True
        ):
            ctx = context.create_context()
            auth, expires_on = azure._get_access_token(
                ctx._conf, azure.azure_cache_key(ctx._conf, "account", "container")
            )

        assert calls["authority"] == "login.microsoftonline.us"
        assert calls["scope"] == "https://storage.azure.com/.default"
        assert auth == (azure.OAUTH_TOKEN, "token")
        assert expires_on == 123


class TestDeletePathsUseContextCloud:
    def test_rmdir_uses_context_cloud_for_delete_url(self, monkeypatch):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)
            assert ctx._conf.azure_cloud == AZURE_US_GOV_CLOUD

        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureCloud"}, clear=True):
            monkeypatch.setattr(ctx, "listdir", lambda path: iter(()))
            seen_urls: list[str] = []

            def fake_execute_api_request(conf, req):
                seen_urls.append(req.url)
                return SimpleNamespace(status=202, headers={}, data=b"")

            monkeypatch.setattr(context.azure, "execute_api_request", fake_execute_api_request)
            ctx.rmdir("https://account.blob.core.usgovcloudapi.net/container/dir/")

        assert seen_urls == ["https://account.blob.core.usgovcloudapi.net/container/dir%2F"]

    def test_rmtree_uses_context_cloud_for_delete_urls(self, monkeypatch):
        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureUSGovernment"}, clear=True):
            ctx = context.create_context(output_az_paths=False)
            assert ctx._conf.azure_cloud == AZURE_US_GOV_CLOUD

        entry = common.DirEntry(
            path="https://account.blob.core.usgovcloudapi.net/container/dir/blob",
            name="blob",
            is_dir=False,
            is_file=True,
            stat=None,
        )

        with patch.dict(os.environ, {"AZURE_CLOUD": "AzureCloud"}, clear=True):
            monkeypatch.setattr(ctx, "isdir", lambda path: True)
            monkeypatch.setattr(context.azure, "list_blobs", lambda conf, path: iter([entry]))
            seen_urls: list[str] = []

            def fake_execute_api_request(conf, req):
                seen_urls.append(req.url)
                return SimpleNamespace(status=202, headers={}, data=b"")

            monkeypatch.setattr(context.azure, "execute_api_request", fake_execute_api_request)
            ctx.rmtree("https://account.blob.core.usgovcloudapi.net/container/dir/")

        assert seen_urls == ["https://account.blob.core.usgovcloudapi.net/container/dir%2Fblob"]
