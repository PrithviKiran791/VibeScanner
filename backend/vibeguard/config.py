from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MODELS = {"anthropic": "claude-opus-5-5", "gemini": "gemini-2.5-flash"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIBEGUARD_", env_file=".env", extra="ignore")

    # Ingestion limits (PRD FR-1.3)
    max_repo_bytes: int = 50 * 1024 * 1024
    max_file_bytes: int = 1 * 1024 * 1024

    # Deterministic pass
    registry_check: bool = True
    registry_timeout_s: float = 5.0

    # LLM pass
    llm_provider: Literal["none", "anthropic", "gemini"] = "anthropic"
    # Swap models without code changes. Unset -> the provider default in DEFAULT_MODELS.
    llm_model: str | None = Field(
        default=None, validation_alias=AliasChoices("VIBEGUARD_LLM_MODEL", "LLM_MODEL_ID")
    )
    anthropic_api_key: SecretStr | None = None
    anthropic_effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    gemini_api_key: SecretStr | None = None
    llm_max_units: int = 40
    llm_chunk_chars: int = 24_000
    llm_concurrency: int = 4

    # Whole-scan wall clock budget (NFR: 60s worker timeout, leave headroom)
    scan_deadline_s: float = 55.0

    # Service (Phase 2). One URL serves both drivers: SQLAlchemy's psycopg dialect is sync+async.
    database_url: str = "postgresql+psycopg://vibeguard:vibeguard@localhost:5432/vibeguard"
    redis_url: str = "redis://localhost:6379/0"
    github_token: SecretStr | None = None
    clone_timeout_s: int = 30
    # On-disk ceiling for a fresh clone, .git included; the 50MB scan budget applies after filtering.
    max_clone_bytes: int = 200 * 1024 * 1024
    # Scanning server-side paths is arbitrary file read for anyone who can reach the API: off by
    # default, and when on, confined to this directory.
    allow_local_paths: bool = False
    local_scan_root: Path | None = None
    cors_origins: list[str] = ["http://localhost:3000"]

    @property
    def resolved_llm_model(self) -> str | None:
        return self.llm_model or DEFAULT_MODELS.get(self.llm_provider)


@lru_cache
def get_settings() -> Settings:
    return Settings()
