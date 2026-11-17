from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import httpx
import pytest

from app.providers import MalwareBazaarProvider, URLhausProvider, VirusTotalProvider
from app.providers.fixtures import FixtureTransport
from app.providers.virustotal import url_identifier
from app.schemas import LookupStatus
from tests.conftest import MD5, URL

Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]


def client_for(handler: Handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def respond(status: int, body: object) -> Handler:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body, request=request)

    return handler


VT_FILE_BODY = {
    "data": {
        "attributes": {
            "last_analysis_date": 1762905600,
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 1,
                "harmless": 3,
                "undetected": 1,
            },
            "popular_threat_classification": {"suggested_threat_label": "trojan.x"},
        }
    }
}


async def test_virustotal_found_parses_counts_and_sends_key() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=VT_FILE_BODY, request=request)

    async with client_for(handler) as client:
        evidence = await VirusTotalProvider(client, "k", 5).lookup(MD5)

    assert evidence.lookup_status is LookupStatus.FOUND
    assert evidence.findings["malicious"] == 5
    assert evidence.findings["suggested_threat_label"] == "trojan.x"
    assert evidence.findings["last_analysis_date"].startswith("2025-11-12")
    assert seen[0].headers["x-apikey"] == "k"
    assert seen[0].url.path == f"/api/v3/files/{MD5.value}"


async def test_virustotal_url_uses_unpadded_base64_id() -> None:
    assert url_identifier("https://a.b/") == "aHR0cHM6Ly9hLmIv"
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(404, json={}, request=request)

    async with client_for(handler) as client:
        evidence = await VirusTotalProvider(client, "k", 5).lookup(URL)

    assert evidence.lookup_status is LookupStatus.NOT_FOUND
    assert seen == [f"/api/v3/urls/{url_identifier(URL.value)}"]


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (404, {"error": {}}, LookupStatus.NOT_FOUND),
        (429, {"error": {}}, LookupStatus.RATE_LIMITED),
        (500, {}, LookupStatus.ERROR),
        (200, {"unexpected": True}, LookupStatus.ERROR),
    ],
)
async def test_virustotal_status_mapping(status: int, body: object, expected: LookupStatus) -> None:
    async with client_for(respond(status, body)) as client:
        evidence = await VirusTotalProvider(client, "k", 5).lookup(MD5)
    assert evidence.lookup_status is expected


async def test_transport_timeout_maps_to_timeout() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    async with client_for(handler) as client:
        evidence = await VirusTotalProvider(client, "k", 5).lookup(MD5)
    assert evidence.lookup_status is LookupStatus.TIMEOUT


async def test_overall_timeout_is_enforced() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json=VT_FILE_BODY, request=request)

    async with client_for(handler) as client:
        evidence = await VirusTotalProvider(client, "k", timeout=0.05).lookup(MD5)
    assert evidence.lookup_status is LookupStatus.TIMEOUT


async def test_missing_key_and_unsupported_type_are_errors() -> None:
    async with client_for(respond(200, {})) as client:
        no_key = await VirusTotalProvider(client, None, 5).lookup(MD5)
        wrong_type = await URLhausProvider(client, "k", 5).lookup(MD5)
    assert no_key.lookup_status is LookupStatus.ERROR
    assert no_key.detail == "API key not configured"
    assert wrong_type.lookup_status is LookupStatus.ERROR


async def test_urlhaus_found_and_not_found() -> None:
    body = {
        "query_status": "ok",
        "threat": "malware_download",
        "tags": None,
        "url_status": "online",
    }
    async with client_for(respond(200, body)) as client:
        found = await URLhausProvider(client, "k", 5).lookup(URL)
    assert found.lookup_status is LookupStatus.FOUND
    assert found.findings == {"threat": "malware_download", "url_status": "online"}

    async with client_for(respond(200, {"query_status": "no_results"})) as client:
        missing = await URLhausProvider(client, "k", 5).lookup(URL)
    assert missing.lookup_status is LookupStatus.NOT_FOUND


async def test_malwarebazaar_found_not_found_and_illegal() -> None:
    body = {"query_status": "ok", "data": [{"signature": "Emotet", "tags": ["dll"]}]}
    async with client_for(respond(200, body)) as client:
        found = await MalwareBazaarProvider(client, "k", 5).lookup(MD5)
    assert found.findings == {"signature": "Emotet", "tags": ["dll"]}

    async with client_for(respond(200, {"query_status": "hash_not_found"})) as client:
        missing = await MalwareBazaarProvider(client, "k", 5).lookup(MD5)
    assert missing.lookup_status is LookupStatus.NOT_FOUND

    async with client_for(respond(200, {"query_status": "illegal_hash"})) as client:
        bad = await MalwareBazaarProvider(client, "k", 5).lookup(MD5)
    assert bad.lookup_status is LookupStatus.ERROR


async def test_fixture_transport_serves_real_adapters() -> None:
    async with httpx.AsyncClient(transport=FixtureTransport()) as client:
        vt_url = await VirusTotalProvider(client, "k", 5).lookup(URL)
        urlhaus = await URLhausProvider(client, "k", 5).lookup(URL)
        mb = await MalwareBazaarProvider(client, "k", 5).lookup(MD5)

    assert vt_url.lookup_status is LookupStatus.FOUND
    assert vt_url.findings["malicious"] == 12
    assert urlhaus.findings["threat"] == "malware_download"
    assert mb.findings["signature"] == "EICAR-Test-File"
