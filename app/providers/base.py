"""Shared provider interface and failure-to-status mapping."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Protocol

import httpx

from app.schemas import Evidence, Indicator, IndicatorType, LookupStatus, ProviderName

logger = logging.getLogger(__name__)


class Provider(Protocol):
    """Anything that can enrich an indicator. Implementations must never raise."""

    @property
    def name(self) -> ProviderName: ...

    async def lookup(self, indicator: Indicator) -> Evidence: ...


class HttpProvider(ABC):
    """Base class for HTTP-backed providers.

    Subclasses implement `_lookup`, which may raise httpx errors freely; `lookup` converts every
    failure into an `Evidence` with the matching `LookupStatus` so a graph branch never crashes.
    """

    name: ClassVar[ProviderName]
    supported_types: ClassVar[frozenset[IndicatorType]]

    def __init__(self, client: httpx.AsyncClient, api_key: str | None, timeout: float) -> None:
        self._client = client
        self._api_key = api_key
        self._timeout = timeout

    async def lookup(self, indicator: Indicator) -> Evidence:
        if indicator.type not in self.supported_types:
            return self._evidence(LookupStatus.ERROR, detail=f"{indicator.type} not supported")
        if not self._api_key:
            return self._evidence(LookupStatus.ERROR, detail="API key not configured")
        try:
            async with asyncio.timeout(self._timeout):
                return await self._lookup(indicator)
        except (TimeoutError, httpx.TimeoutException):
            return self._evidence(LookupStatus.TIMEOUT, detail="Lookup timed out")
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == httpx.codes.TOO_MANY_REQUESTS:
                return self._evidence(LookupStatus.RATE_LIMITED, detail="Provider rate limit hit")
            return self._evidence(LookupStatus.ERROR, detail=f"HTTP {code}")
        except httpx.HTTPError as exc:
            return self._evidence(
                LookupStatus.ERROR, detail=f"Transport error: {type(exc).__name__}"
            )
        except (ValueError, KeyError, TypeError, IndexError):
            logger.warning("%s returned an unexpected response format", self.name, exc_info=True)
            return self._evidence(LookupStatus.ERROR, detail="Unexpected response format")
        except Exception:
            logger.exception("%s lookup failed unexpectedly", self.name)
            return self._evidence(LookupStatus.ERROR, detail="Unexpected error")

    @abstractmethod
    async def _lookup(self, indicator: Indicator) -> Evidence: ...

    def _evidence(
        self,
        status: LookupStatus,
        findings: dict[str, Any] | None = None,
        detail: str | None = None,
    ) -> Evidence:
        return Evidence(
            provider=self.name, lookup_status=status, findings=findings or {}, detail=detail
        )


def compact(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None or empty, keeping zeros and False."""
    return {k: v for k, v in mapping.items() if v is not None and v != [] and v != ""}
