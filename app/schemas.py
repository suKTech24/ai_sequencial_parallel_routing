"""Pydantic models for the API contract and the workflow's internal data."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_URL_LENGTH = 2048


class IndicatorType(StrEnum):
    URL = "url"
    HASH = "hash"


class HashType(StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


_HASH_TYPES_BY_LENGTH = {32: HashType.MD5, 40: HashType.SHA1, 64: HashType.SHA256}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def normalize_url(value: str) -> str:
    """Validate an http(s) URL. Path and query are preserved exactly for exact-match lookups."""
    value = value.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be at most {MAX_URL_LENGTH} characters")
    if any(ch.isspace() for ch in value):
        raise ValueError("URL must not contain whitespace")
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parts.hostname:
        raise ValueError("URL must include a host")
    return value


def classify_hash(value: str) -> tuple[str, HashType]:
    """Validate a hex digest and return it lowercased along with its algorithm."""
    value = value.strip()
    if not _HEX_RE.fullmatch(value):
        raise ValueError("Hash must contain only hexadecimal characters")
    hash_type = _HASH_TYPES_BY_LENGTH.get(len(value))
    if hash_type is None:
        raise ValueError("Hash must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters")
    return value.lower(), hash_type


class AnalyzeRequest(BaseModel):
    """Request body for `POST /analyze`."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"type": "url", "value": "https://malware.example.com/payload.exe"},
                {"type": "hash", "value": "44D88612FEA8A8F36DE82E1278ABB02F"},
            ]
        },
    )

    type: IndicatorType
    value: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @model_validator(mode="after")
    def _normalize_value(self) -> Self:
        if self.type is IndicatorType.URL:
            self.value = normalize_url(self.value)
        else:
            self.value, _ = classify_hash(self.value)
        return self


class Indicator(BaseModel):
    """A validated, normalised indicator."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str
    hash_type: HashType | None = None

    @classmethod
    def from_request(cls, request: AnalyzeRequest) -> Indicator:
        if request.type is IndicatorType.URL:
            return cls(type=request.type, value=normalize_url(request.value))
        value, hash_type = classify_hash(request.value)
        return cls(type=request.type, value=value, hash_type=hash_type)


class ProviderName(StrEnum):
    VIRUSTOTAL = "virustotal"
    URLHAUS = "urlhaus"
    MALWAREBAZAAR = "malwarebazaar"


class LookupStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"

    @property
    def completed(self) -> bool:
        return self in {LookupStatus.FOUND, LookupStatus.NOT_FOUND}


class Evidence(BaseModel):
    """One provider's normalised lookup result."""

    provider: ProviderName
    lookup_status: LookupStatus
    findings: dict[str, Any] = Field(default_factory=dict)
    detail: str | None = Field(default=None, description="Why a lookup did not complete.")


class Outcome(StrEnum):
    MALICIOUS_RECORD_FOUND = "malicious_record_found"
    FLAGGED_BY_ENGINES = "flagged_by_engines"
    INCONCLUSIVE = "inconclusive"
    NO_MALICIOUS_EVIDENCE_FOUND = "no_malicious_evidence_found"


class SummarySource(StrEnum):
    LLM = "llm"
    TEMPLATE = "template"


class AnalyzeResponse(BaseModel):
    indicator: Indicator
    outcome: Outcome
    evidence: list[Evidence]
    limitations: list[str]
    summary: str
    summary_source: SummarySource
