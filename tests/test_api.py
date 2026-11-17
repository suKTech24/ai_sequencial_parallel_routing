"""End-to-end over HTTP in fixture mode: no keys, no network, no LLM."""

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


def test_analyze_returns_a_report(client: TestClient) -> None:
    """FastAPI -> graph -> providers -> fixtures -> report, all wired together."""
    response = client.post(
        "/analyze", json={"type": "url", "value": "https://malware.example.com/payload.exe"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "malicious_record_found"
    assert [e["provider"] for e in body["evidence"]] == ["virustotal", "urlhaus"]


def test_invalid_input_is_rejected_before_the_graph_runs(client: TestClient) -> None:
    """schemas.py validation turns bad input into 422."""
    response = client.post("/analyze", json={"type": "hash", "value": "not-a-hash"})
    assert response.status_code == 422
