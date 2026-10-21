"""initial schema: repositories, scans, findings, remediations

Revision ID: 0001
Revises:
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENUMS = {
    "scan_source": ("GITHUB", "ZIP", "LOCAL"),
    "scan_status": (
        "QUEUED",
        "CLONING",
        "ANALYZING_STATIC",
        "ANALYZING_LLM",
        "COMPLETED",
        "FAILED",
    ),
    "vulnerability_severity": ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
    "finding_source": ("STATIC", "LLM", "MERGED"),
    "finding_status": ("OPEN", "PATCH_APPLIED", "DISMISSED_FALSE_POSITIVE", "RESOLVED"),
}
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _enum(name: str) -> sa.Enum:
    return sa.Enum(*ENUMS[name], name=name)


def _ts(**kw) -> sa.Column:
    return sa.Column(
        kw.pop("name"), sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(512), nullable=False, unique=True),
        sa.Column("default_branch", sa.String(64), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        _ts(name="created_at"),
        _ts(name="updated_at"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "repo_id",
            sa.Uuid(),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_type", _enum("scan_source"), nullable=False),
        sa.Column("commit_hash", sa.String(40)),
        sa.Column("status", _enum("scan_status"), nullable=False),
        sa.Column("hardening_score", sa.Integer()),
        sa.Column("total_findings", sa.Integer(), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.Column("files_scanned", sa.Integer()),
        sa.Column("llm_used", sa.Boolean(), nullable=False),
        sa.Column("warnings", JSON, nullable=False),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("error_message", sa.Text()),
        _ts(name="created_at"),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "hardening_score >= 0 AND hardening_score <= 100", name="ck_scans_hardening_score"
        ),
    )
    op.create_index("idx_scans_repo_id", "scans", ["repo_id"])
    op.create_index("idx_scans_status", "scans", ["status"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("severity", _enum("vulnerability_severity"), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("cwe_id", sa.String(32)),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("snippet_original", sa.Text(), nullable=False),
        sa.Column("snippet_fixed", sa.Text()),
        sa.Column("unified_diff", sa.Text()),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("source", _enum("finding_source"), nullable=False),
        sa.Column("status", _enum("finding_status"), nullable=False),
        _ts(name="created_at"),
    )
    op.create_index("idx_findings_scan_id", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])

    op.create_table(
        "remediations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Uuid(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("col_start", sa.Integer(), nullable=False),
        sa.Column("col_end", sa.Integer(), nullable=False),
        sa.Column("replacement", sa.Text(), nullable=False),
        sa.Column("env_var_name", sa.String(128)),
        sa.Column("expected_text", sa.Text()),
        sa.Column("verify_rule", sa.String(128)),
    )


def downgrade() -> None:
    op.drop_table("remediations")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("repositories")
    # PostgreSQL keeps enum types after their tables are gone
    for name in ENUMS:
        _enum(name).drop(op.get_bind(), checkfirst=True)
