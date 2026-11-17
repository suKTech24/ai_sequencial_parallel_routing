"""Application settings loaded from environment variables and `.env`."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Any

from dotenv import load_dotenv
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProviderMode(StrEnum):
    FIXTURES = "fixtures"
    LIVE = "live"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    provider_mode: ProviderMode = ProviderMode.FIXTURES
    virustotal_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    provider_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    llm_model: str | None = None
    llm_provider: str | None = None
    llm_timeout_seconds: float = Field(default=20.0, gt=0, le=120)

    log_level: str = "INFO"

    @field_validator(
        "virustotal_api_key", "abusech_auth_key", "llm_model", "llm_provider", mode="before"
    )
    @classmethod
    def _blank_to_none(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    # LangChain integrations read their own keys (OPENAI_API_KEY, OPENROUTER_API_KEY, ...) from
    # os.environ, which pydantic-settings does not populate. Export .env without overriding
    # variables that are already set.
    load_dotenv(".env", override=False)
    return Settings()
