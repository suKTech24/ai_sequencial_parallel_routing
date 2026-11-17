from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from app.config import Settings
from app.schemas import (
    Evidence,
    HashType,
    Indicator,
    IndicatorType,
    LookupStatus,
    ProviderName,
)

URL = Indicator(type=IndicatorType.URL, value="https://malware.example.com/payload.exe")
MD5 = Indicator(
    type=IndicatorType.HASH, value="44d88612fea8a8f36de82e1278abb02f", hash_type=HashType.MD5
)


def ev(
    provider: ProviderName,
    status: LookupStatus,
    **findings: object,
) -> Evidence:
    return Evidence(provider=provider, lookup_status=status, findings=dict(findings))


class FakeProvider:
    """Records calls and returns a canned Evidence, optionally after a hook."""

    def __init__(
        self,
        name: ProviderName,
        status: LookupStatus = LookupStatus.NOT_FOUND,
        findings: dict[str, object] | None = None,
        before: Callable[[], asyncio.Future[object]] | None = None,
    ) -> None:
        self.name = name
        self.calls: list[Indicator] = []
        self._result = Evidence(provider=name, lookup_status=status, findings=findings or {})
        self._before = before

    async def lookup(self, indicator: Indicator) -> Evidence:
        self.calls.append(indicator)
        if self._before is not None:
            await self._before()
        return self._result


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests hermetic: ignore the developer's .env and shell settings."""
    for field in Settings.model_fields:
        monkeypatch.delenv(field.upper(), raising=False)


@pytest.fixture
def fake_providers() -> dict[ProviderName, FakeProvider]:
    return {name: FakeProvider(name) for name in ProviderName}
