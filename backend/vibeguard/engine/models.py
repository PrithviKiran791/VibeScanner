"""Core data models shared by the CLI, the API, and LLM output validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingSource(StrEnum):
    STATIC = "STATIC"
    LLM = "LLM"
    MERGED = "MERGED"


class Remediation(BaseModel):
    """Coordinates for re-applying a fix to a fresh clone without storing the secret.

    The stored `unified_diff` for a secret finding is masked and won't apply. The PR worker uses
    this instead: open `file_path`, take `line[col_start:col_end]`, confirm it is still the same
    thing (`expected_text` for non-secret spans, or a re-match of `verify_rule` for secrets), and
    swap in `replacement`.
    """

    kind: Literal["replace_span"] = "replace_span"
    file_path: str
    line: int = Field(ge=1)
    col_start: int = Field(ge=0, description="0-based character offset in the line, inclusive")
    col_end: int = Field(ge=0, description="0-based character offset in the line, exclusive")
    replacement: str
    env_var_name: str | None = None
    expected_text: str | None = None
    verify_rule: str | None = None


class Finding(BaseModel):
    """A confirmed vulnerability. Mirrors the `findings` table."""

    rule_id: str
    severity: Severity
    category: str
    title: str
    cwe_id: str | None = None
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    snippet_original: str
    snippet_fixed: str | None = None
    unified_diff: str | None = None
    explanation: str
    source: FindingSource = FindingSource.STATIC
    remediation: Remediation | None = None

    def overlaps(self, other: Finding) -> bool:
        return (
            self.file_path == other.file_path
            and self.line_start <= other.line_end
            and other.line_start <= self.line_end
        )


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    target: str
    commit_hash: str | None = None
    files_scanned: int
    units_analyzed: int = 0
    llm_used: bool = False
    hardening_score: int = Field(ge=0, le=100)
    counts: SeverityCounts
    findings: list[Finding]
    warnings: list[str] = Field(default_factory=list)
    duration_ms: int


@dataclass(frozen=True)
class SourceFile:
    """A text file that survived ingestion filtering. `path` is repo-relative POSIX."""

    path: str
    abs_path: Path
    text: str
    language: str | None = None

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def snippet(self, line_start: int, line_end: int, context: int = 3) -> str:
        lo = max(1, line_start - context)
        hi = min(len(self.lines), line_end + context)
        return "\n".join(self.lines[lo - 1 : hi])


@dataclass
class CodeUnit:
    """A security-relevant slice of code (route handler, server action, middleware)."""

    unit_id: str
    file_path: str
    kind: str  # "route_handler" | "server_action" | "api_route" | "express_route" | "middleware"
    name: str
    line_start: int
    line_end: int
    code: str
    http_method: str | None = None
    is_mutation: bool = False
    has_auth_signal: bool = False
    touches_db: bool = False
    reads_input: bool = False
    imports: list[str] = field(default_factory=list)

    @property
    def priority(self) -> int:
        """Higher = more likely to hide an authorization bug."""
        score = 0
        score += 4 if self.touches_db else 0
        score += 3 if self.is_mutation else 0
        score += 2 if self.reads_input else 0
        score += 2 if not self.has_auth_signal else 0
        return score
