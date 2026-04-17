"""Helpers for the OpenAPI-generated client."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import NetidmClient
from .types import NetidmClientConfig

try:
    from netidm_openapi_client import ApiClient, Configuration
except ImportError as exc:  # pragma: no cover - packaged with project
    raise ImportError("netidm_openapi_client is not available; re-run OpenAPI codegen") from exc


def openapi_configuration_from_client_config(config: NetidmClientConfig) -> Configuration:
    """Create an OpenAPI Configuration from a NetidmClientConfig."""
    if config.uri is None:
        raise ValueError("NetidmClientConfig.uri must be set")

    host = config.uri.rstrip("/")
    configuration = Configuration(host=host)

    verify_ssl = config.verify_certificate and config.verify_ca
    configuration.verify_ssl = verify_ssl
    setattr(configuration, "assert_hostname", config.verify_hostnames)
    if config.ca_path is not None:
        configuration.ssl_ca_cert = config.ca_path
    if config.auth_token is not None:
        configuration.access_token = config.auth_token

    return configuration


def openapi_client_from_client_config(config: NetidmClientConfig) -> ApiClient:
    """Create an OpenAPI ApiClient from a NetidmClientConfig."""
    return ApiClient(configuration=openapi_configuration_from_client_config(config))


def openapi_client_from_netidm_client(client: "NetidmClient") -> ApiClient:
    """Create an OpenAPI ApiClient from a NetidmClient instance."""
    return openapi_client_from_client_config(client.config)


__all__ = [
    "ApiClient",
    "Configuration",
    "openapi_client_from_client_config",
    "openapi_client_from_netidm_client",
    "openapi_configuration_from_client_config",
]
