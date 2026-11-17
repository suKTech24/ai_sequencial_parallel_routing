"""URLhaus (abuse.ch): exact URL lookup for a malware-distribution record."""

from __future__ import annotations

from app.providers.base import HttpProvider, compact
from app.schemas import Evidence, Indicator, IndicatorType, LookupStatus, ProviderName

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausProvider(HttpProvider):
    name = ProviderName.URLHAUS
    supported_types = frozenset({IndicatorType.URL})

    async def _lookup(self, indicator: Indicator) -> Evidence:
        response = await self._client.post(
            API_URL, data={"url": indicator.value}, headers={"Auth-Key": self._api_key or ""}
        )
        response.raise_for_status()
        body = response.json()
        query_status = body.get("query_status")

        if query_status == "no_results":
            return self._evidence(LookupStatus.NOT_FOUND)
        if query_status != "ok":
            return self._evidence(LookupStatus.ERROR, detail=f"query_status={query_status}")

        findings = compact(
            {
                "threat": body.get("threat"),
                "url_status": body.get("url_status"),
                "tags": body.get("tags") or [],
                "date_added": body.get("date_added"),
                "reference": body.get("urlhaus_reference"),
            }
        )
        return self._evidence(LookupStatus.FOUND, findings=findings)
