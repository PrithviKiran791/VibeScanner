from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vibeguard.db.models import FindingStatus, ScanSource, ScanStatus
from vibeguard.engine.models import FindingDomain, FindingSource, Severity
from vibeguard.worker.contracts import ScanOptions


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str | None = Field(default=None, examples=["https://github.com/acme/vibe-app"])
    local_path: str | None = None
    options: ScanOptions = Field(default_factory=ScanOptions)

    @model_validator(mode="after")
    def _exactly_one_target(self) -> ScanCreate:
        if (self.repo_url is None) == (self.local_path is None):
            raise ValueError("Provide exactly one of repo_url or local_path")
        return self


class Counts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    total: int
    # Fixed through a VibeGuard PR; not part of `total` (which counts OPEN findings only)
    patched: int


class Progress(BaseModel):
    step: str
    percentage: int


class ScanOut(BaseModel):
    id: uuid.UUID
    status: ScanStatus
    source_type: ScanSource
    target: str
    repository: str
    commit_hash: str | None
    hardening_score: int | None
    # Code quality (NULL when not measured): score 0-100, grade A-F, and the five sub-scores
    quality_score: int | None
    quality_grade: str | None
    quality_breakdown: dict | None
    counts: Counts
    files_scanned: int | None
    llm_used: bool
    warnings: list[str]
    duration_ms: int | None
    error_message: str | None
    progress: Progress | None
    created_by: str | None
    created_at: datetime
    completed_at: datetime | None


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: str
    file_path: str
    line: int
    col_start: int
    col_end: int
    replacement: str
    env_var_name: str | None
    expected_text: str | None
    verify_rule: str | None


class PullRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    pr_number: int
    pr_url: str
    branch_name: str
    opened_by: str | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    rule_id: str
    severity: Severity
    category: str
    title: str
    cwe_id: str | None
    file_path: str
    line_start: int
    line_end: int
    snippet_original: str
    snippet_fixed: str | None
    unified_diff: str | None
    explanation: str
    source: FindingSource
    domain: FindingDomain
    status: FindingStatus
    remediation: RemediationOut | None
    pull_request: PullRequestOut | None


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus


class ScoreOut(BaseModel):
    scan_id: uuid.UUID
    hardening_score: int | None
    counts: Counts


class FindingUpdateOut(BaseModel):
    finding: FindingOut
    scan: ScoreOut


class OpenPullRequestOut(BaseModel):
    finding: FindingOut
    scan: ScoreOut
    created: bool


class MeOut(BaseModel):
    uid: str
    email: str | None
    name: str | None
    picture: str | None
