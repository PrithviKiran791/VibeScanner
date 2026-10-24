from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MODELS = {"openrouter": "google/gemma-4-31b-it:free", "gemini": "gemini-2.5-flash"}

# backend/.env is read no matter where the process starts (repo root, backend/, Docker);
# a .env in the working directory, if any, overrides it.
BACKEND_ENV = Path(__file__).resolve().parents[1] / ".env"


def _env(name: str) -> AliasChoices:
    """Accept both VIBEGUARD_<NAME> and the bare <NAME> (e.g. OPENROUTER_API_KEY)."""
    return AliasChoices(f"VIBEGUARD_{name}", name)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VIBEGUARD_", env_file=(BACKEND_ENV, ".env"), extra="ignore"
    )

    # Ingestion limits (PRD FR-1.3)
    max_repo_bytes: int = 50 * 1024 * 1024
    max_file_bytes: int = 1 * 1024 * 1024

    # Deterministic pass
    registry_check: bool = True
    registry_timeout_s: float = 5.0

    # LLM pass
    llm_provider: Literal["none", "openrouter", "gemini"] = "openrouter"
    # Swap models without code changes. Unset -> the provider default in DEFAULT_MODELS.
    llm_model: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VIBEGUARD_LLM_MODEL", "LLM_MODEL", "LLM_MODEL_ID"),
    )
    # Tried once when the primary model is rate-limited or unavailable (free tiers throttle hard)
    llm_fallback_model: str | None = Field(
        default="google/gemma-4-26b-a4b-it:free", validation_alias=_env("LLM_FALLBACK_MODEL")
    )
    # Let the model think before answering (OpenRouter `reasoning`). Better at spotting missing
    # auth, but slower: turn off if chunks start hitting the scan deadline.
    llm_reasoning: bool = Field(default=True, validation_alias=_env("LLM_REASONING"))
    llm_base_url: str = Field(
        default="https://openrouter.ai/api/v1", validation_alias=_env("LLM_BASE_URL")
    )
    openrouter_api_key: SecretStr | None = Field(
        default=None, validation_alias=_env("OPENROUTER_API_KEY")
    )
    # OpenRouter attribution headers (HTTP-Referer / X-Title)
    llm_app_url: str = "http://localhost:3000"
    llm_app_name: str = "VibeGuard"
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

    # Phase 4: production hardening
    rate_limit_enabled: bool = True
    rate_limit_scans_per_minute: int = 10
    rate_limit_prs_per_minute: int = 5
    rate_limit_triage_per_minute: int = 60
    rate_limit_webhooks_per_minute: int = 120
    # Proxies (IPs/CIDRs) whose X-Forwarded-For is believed, e.g. the dashboard's Next server.
    # Empty = rate-limit by socket peer only.
    trusted_proxies: list[str] = []
    # Requests larger than this are refused before the body is read (webhooks included)
    max_request_bytes: int = 5 * 1024 * 1024
    # Shared secret for GitHub webhook signatures (repo webhook or GitHub App); unset = disabled
    github_webhook_secret: SecretStr | None = None

    # Authentication: Firebase ID tokens (Sign in with GitHub, Google or email in the dashboard).
    # Fails closed: no project ID -> 503 on every protected route; empty allowlist -> 403.
    firebase_project_id: str | None = None
    # Who may use this deployment. PRs are opened with the server's GitHub token, so anyone
    # allowed here can act on GitHub as that token: keep it tight.
    auth_allowed_emails: list[str] = []
    auth_allowed_domains: list[str] = []
    # Numeric GitHub account ids (https://api.github.com/users/<login> -> "id"). Firebase never
    # marks GitHub emails as verified, so GitHub sign-ins are allowlisted by account instead.
    auth_allowed_github_ids: list[str] = []
    # Local development only (the Docker-free devserver sets it). Never in production.
    auth_disabled: bool = False

    @property
    def resolved_llm_model(self) -> str | None:
        return self.llm_model or DEFAULT_MODELS.get(self.llm_provider)


@lru_cache
def get_settings() -> Settings:
    return Settings()
