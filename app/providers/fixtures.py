"""Offline fixture mode.

Instead of separate fake clients, fixture mode swaps the HTTP transport. The real provider
adapters build real requests and parse responses, so fixtures exercise the same code paths that
live mode uses.

Fixture files map an indicator value to either `{"status": int, "body": {...}}` or
`{"simulate": "timeout"}`. Keys starting with `_` are comments. Missing indicators get the
provider's normal "not found" response.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from app.schemas import ProviderName

FIXTURE_DIR = Path(__file__).parent / "fixtures"

_HOSTS = {
    "www.virustotal.com": ProviderName.VIRUSTOTAL,
    "urlhaus-api.abuse.ch": ProviderName.URLHAUS,
    "mb-api.abuse.ch": ProviderName.MALWAREBAZAAR,
}

_NOT_FOUND: dict[ProviderName, tuple[int, dict[str, Any]]] = {
    ProviderName.VIRUSTOTAL: (404, {"error": {"code": "NotFoundError", "message": "Not found"}}),
    ProviderName.URLHAUS: (200, {"query_status": "no_results"}),
    ProviderName.MALWAREBAZAAR: (200, {"query_status": "hash_not_found"}),
}


def _load(fixture_dir: Path) -> dict[ProviderName, dict[str, Any]]:
    fixtures: dict[ProviderName, dict[str, Any]] = {}
    for provider in ProviderName:
        path = fixture_dir / f"{provider}.json"
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        fixtures[provider] = {k: v for k, v in raw.items() if not k.startswith("_")}
    return fixtures


def _decode_vt_url_id(url_id: str) -> str:
    padding = "=" * (-len(url_id) % 4)
    return base64.urlsafe_b64decode(url_id + padding).decode()


class FixtureTransport(httpx.AsyncBaseTransport):
    def __init__(self, fixture_dir: Path = FIXTURE_DIR) -> None:
        self._fixtures = _load(fixture_dir)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        provider = _HOSTS.get(request.url.host)
        if provider is None:
            raise httpx.ConnectError(f"No fixtures for host {request.url.host}", request=request)

        key = await self._indicator_key(provider, request)
        entry = self._fixtures[provider].get(key)
        if entry is None:
            status, body = _NOT_FOUND[provider]
            return httpx.Response(status, json=body, request=request)
        if entry.get("simulate") == "timeout":
            raise httpx.ReadTimeout("Simulated fixture timeout", request=request)
        return httpx.Response(entry.get("status", 200), json=entry.get("body", {}), request=request)

    @staticmethod
    async def _indicator_key(provider: ProviderName, request: httpx.Request) -> str:
        if provider is ProviderName.VIRUSTOTAL:
            kind, _, ident = urlsplit(str(request.url)).path.rstrip("/").rpartition("/")
            return _decode_vt_url_id(ident) if kind.endswith("/urls") else ident

        form = parse_qs((await request.aread()).decode())
        field = "url" if provider is ProviderName.URLHAUS else "hash"
        return form.get(field, [""])[0]
