"""End-to-end through FastAPI in fixture mode (no keys, no network, no LLM)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import ProviderMode, Settings
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(_env_file=None, provider_mode=ProviderMode.FIXTURES)  # type: ignore[call-arg]
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def analyze(client: TestClient, kind: str, value: str) -> dict:  # type: ignore[type-arg]
    response = client.post("/analyze", json={"type": kind, "value": value})
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("kind", "value", "outcome"),
    [
        ("url", "https://malware.example.com/payload.exe", "malicious_record_found"),
        ("url", "https://phish.example.net/login?session=42", "flagged_by_engines"),
        ("url", "https://clean.example.org/", "no_malicious_evidence_found"),
        ("url", "https://slow.example.com/", "inconclusive"),
        ("hash", "44D88612FEA8A8F36DE82E1278ABB02F", "malicious_record_found"),
        ("hash", "3395856ce81f2b7382dee72602f798b642f14140", "malicious_record_found"),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e", "no_malicious_evidence_found"),
        (
            "hash",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "inconclusive",
        ),
    ],
)
def test_fixture_scenarios(client: TestClient, kind: str, value: str, outcome: str) -> None:
    body = analyze(client, kind, value)
    assert body["outcome"] == outcome
    assert body["summary_source"] == "template"
    assert len(body["evidence"]) == 2
    assert body["limitations"][0].startswith("Offline fixture mode")


def test_demo_hash_with_rate_limited_virustotal(client: TestClient) -> None:
    body = analyze(client, "hash", "3395856ce81f2b7382dee72602f798b642f14140")
    statuses = {e["provider"]: e["lookup_status"] for e in body["evidence"]}
    assert statuses == {"virustotal": "rate_limited", "malwarebazaar": "found"}
    assert body["summary"].endswith("cross-source confirmation is unavailable.")


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "url", "value": "ftp://example.org/"},
        {"type": "hash", "value": "not-a-hash"},
        {"type": "ip", "value": "1.2.3.4"},
        {"type": "url"},
    ],
)
def test_invalid_input_returns_422(client: TestClient, payload: dict) -> None:  # type: ignore[type-arg]
    assert client.post("/analyze", json=payload).status_code == 422


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {
        "status": "ok",
        "provider_mode": "fixtures",
        "llm_enabled": False,
    }
