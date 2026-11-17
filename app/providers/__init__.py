"""Provider adapters and their wiring."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.config import ProviderMode, Settings
from app.providers.base import HttpProvider, Provider
from app.providers.fixtures import FixtureTransport
from app.providers.malwarebazaar import MalwareBazaarProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.virustotal import VirusTotalProvider

__all__ = [
    "HttpProvider",
    "MalwareBazaarProvider",
    "Provider",
    "ProviderSet",
    "URLhausProvider",
    "VirusTotalProvider",
    "build_providers",
    "create_http_client",
]

_USER_AGENT = "ioc-enrichment-assistant/0.1"
_FIXTURE_KEY = "fixture-key"


@dataclass(frozen=True, slots=True)
class ProviderSet:
    virustotal: Provider
    urlhaus: Provider
    malwarebazaar: Provider


def create_http_client(settings: Settings) -> httpx.AsyncClient:
    """One shared client (connection pool) for all providers."""
    transport = FixtureTransport() if settings.provider_mode is ProviderMode.FIXTURES else None
    return httpx.AsyncClient(
        transport=transport,
        timeout=settings.provider_timeout_seconds,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )


def build_providers(settings: Settings, client: httpx.AsyncClient) -> ProviderSet:
    if settings.provider_mode is ProviderMode.FIXTURES:
        vt_key: str | None = _FIXTURE_KEY
        abusech_key: str | None = _FIXTURE_KEY
    else:
        vt_key = (
            settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else None
        )
        abusech_key = (
            settings.abusech_auth_key.get_secret_value() if settings.abusech_auth_key else None
        )

    timeout = settings.provider_timeout_seconds
    return ProviderSet(
        virustotal=VirusTotalProvider(client, vt_key, timeout),
        urlhaus=URLhausProvider(client, abusech_key, timeout),
        malwarebazaar=MalwareBazaarProvider(client, abusech_key, timeout),
    )
