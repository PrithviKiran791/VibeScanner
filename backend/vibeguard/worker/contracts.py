"""Payloads shared by the API (producer) and the Celery task (consumer). JSON-serializable."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from vibeguard.config import Settings
from vibeguard.engine.ingest.workspace import IngestError, parse_github_url


class TargetSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["github", "local"]
    url: str | None = None
    path: str | None = None

    @property
    def canonical(self) -> str:
        """Stable identity for the repositories table and the per-repo scan lock."""
        if self.kind == "github":
            owner, repo = parse_github_url(self.url or "")
            return f"https://github.com/{owner.lower()}/{repo.lower()}"
        return str(Path(self.path or "").resolve())

    @property
    def display_name(self) -> str:
        if self.kind == "github":
            owner, repo = parse_github_url(self.url or "")
            return f"{owner}/{repo}"
        return Path(self.path or "").resolve().name


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    llm: bool = True
    registry: bool = True


def resolve_local_path(raw: str, settings: Settings) -> Path:
    """Only directories inside `local_scan_root`, and only when explicitly enabled."""
    if not settings.allow_local_paths or settings.local_scan_root is None:
        raise IngestError("Local path scanning is disabled on this server")
    root = settings.local_scan_root.resolve()
    path = Path(raw).resolve()
    if not path.is_relative_to(root):
        raise IngestError("Path is outside the allowed scan root")
    if not path.is_dir():
        raise IngestError("Path is not a directory")
    return path
