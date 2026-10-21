"""SQLAlchemy 2.0 models matching markdown/backend_schema.md.

Types are dialect-portable (Uuid, Enum, JSON) so the test suite runs on SQLite; on PostgreSQL
the enums are native `CREATE TYPE`s and JSON becomes JSONB.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from vibeguard.engine.models import FindingSource, Severity


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    ANALYZING_STATIC = "ANALYZING_STATIC"
    ANALYZING_LLM = "ANALYZING_LLM"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    @property
    def terminal(self) -> bool:
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED)


class ScanSource(StrEnum):
    GITHUB = "GITHUB"
    ZIP = "ZIP"
    LOCAL = "LOCAL"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    PATCH_APPLIED = "PATCH_APPLIED"
    DISMISSED_FALSE_POSITIVE = "DISMISSED_FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


def _enum(cls: type[StrEnum], name: str) -> Enum:
    return Enum(
        cls, name=name, values_callable=lambda e: [m.value for m in e], validate_strings=True
    )


JSONType = JSON().with_variant(JSONB(), "postgresql")


def _now() -> datetime:
    # Set app-side too: SQLite's CURRENT_TIMESTAMP is whole seconds, which breaks ordering
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(512), unique=True)
    default_branch: Mapped[str] = mapped_column(String(64), default="main")
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now(), onupdate=func.now()
    )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("idx_scans_repo_id", "repo_id"),
        Index("idx_scans_status", "status"),
        CheckConstraint(
            "hardening_score >= 0 AND hardening_score <= 100", name="ck_scans_hardening_score"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    source_type: Mapped[ScanSource] = mapped_column(_enum(ScanSource, "scan_source"))
    commit_hash: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED
    )
    hardening_score: Mapped[int | None] = mapped_column(Integer)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int | None] = mapped_column(Integer)
    llm_used: Mapped[bool] = mapped_column(Boolean, default=False)
    warnings: Mapped[list[str]] = mapped_column(JSONType, default=list)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="scans", lazy="joined")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="raise"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "vulnerability_severity"))
    category: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255))
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    file_path: Mapped[str] = mapped_column(String(512))
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    snippet_original: Mapped[str] = mapped_column(Text)
    snippet_fixed: Mapped[str | None] = mapped_column(Text)
    unified_diff: Mapped[str | None] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    source: Mapped[FindingSource] = mapped_column(_enum(FindingSource, "finding_source"))
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin", uselist=False
    )
    pull_request: Mapped[PullRequest | None] = relationship(
        cascade="all, delete-orphan", lazy="selectin", uselist=False
    )


class Remediation(Base):
    """Span coordinates for re-applying a fix to a fresh clone (see engine/remediation.py)."""

    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True
    )
    kind: Mapped[str] = mapped_column(String(32), default="replace_span")
    file_path: Mapped[str] = mapped_column(String(512))
    line: Mapped[int] = mapped_column(Integer)
    col_start: Mapped[int] = mapped_column(Integer)
    col_end: Mapped[int] = mapped_column(Integer)
    replacement: Mapped[str] = mapped_column(Text)
    env_var_name: Mapped[str | None] = mapped_column(String(128))
    expected_text: Mapped[str | None] = mapped_column(Text)
    verify_rule: Mapped[str | None] = mapped_column(String(128))

    finding: Mapped[Finding] = relationship(back_populates="remediation")


class PullRequest(Base):
    """A GitHub PR opened from a finding's fix (one per finding)."""

    __tablename__ = "pull_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True
    )
    pr_number: Mapped[int] = mapped_column(Integer)
    pr_url: Mapped[str] = mapped_column(String(512))
    branch_name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )
