"""VirusTotal v3: retrieve existing URL and file reports (never submits new scans)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from app.providers.base import HttpProvider, compact
from app.schemas import Evidence, Indicator, IndicatorType, LookupStatus, ProviderName

BASE_URL = "https://www.virustotal.com/api/v3"
_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


def url_identifier(url: str) -> str:
    """VirusTotal's URL id: unpadded URL-safe base64 of the exact URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalProvider(HttpProvider):
    name = ProviderName.VIRUSTOTAL
    supported_types = frozenset({IndicatorType.URL, IndicatorType.HASH})

    async def _lookup(self, indicator: Indicator) -> Evidence:
        if indicator.type is IndicatorType.URL:
            path = f"/urls/{url_identifier(indicator.value)}"
        else:
            path = f"/files/{indicator.value}"

        response = await self._client.get(
            f"{BASE_URL}{path}", headers={"x-apikey": self._api_key or ""}
        )
        if response.status_code == 404:
            return self._evidence(LookupStatus.NOT_FOUND)
        response.raise_for_status()

        attributes: dict[str, Any] = response.json()["data"]["attributes"]
        return self._evidence(LookupStatus.FOUND, findings=_findings(attributes))


def _findings(attributes: dict[str, Any]) -> dict[str, Any]:
    stats = attributes.get("last_analysis_stats") or {}
    findings: dict[str, Any] = {key: int(stats.get(key, 0)) for key in _STAT_KEYS}

    analysis_ts = attributes.get("last_analysis_date")
    threat = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
    findings |= compact(
        {
            "last_analysis_date": (
                datetime.fromtimestamp(int(analysis_ts), UTC).isoformat()
                if analysis_ts is not None
                else None
            ),
            "meaningful_name": attributes.get("meaningful_name"),
            "suggested_threat_label": threat,
        }
    )
    return findings
