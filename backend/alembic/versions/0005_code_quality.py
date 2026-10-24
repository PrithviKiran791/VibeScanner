"""code quality: per-scan quality score/grade/breakdown, and a domain on every finding

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-25

Scans from before this migration keep NULL quality fields (they were never measured), and
their findings are all SECURITY.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

finding_domain = sa.Enum("SECURITY", "QUALITY", name="finding_domain")
JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    finding_domain.create(op.get_bind(), checkfirst=True)
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("quality_score", sa.Integer()))
        batch.add_column(sa.Column("quality_grade", sa.String(2)))
        batch.add_column(sa.Column("quality_breakdown", JSONType))
        batch.create_check_constraint(
            "ck_scans_quality_score", "quality_score >= 0 AND quality_score <= 100"
        )
    with op.batch_alter_table("findings") as batch:
        batch.add_column(
            sa.Column("domain", finding_domain, nullable=False, server_default="SECURITY")
        )
        batch.create_index("idx_findings_scan_domain", ["scan_id", "domain"])


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("idx_findings_scan_domain")
        batch.drop_column("domain")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("ck_scans_quality_score", type_="check")
        batch.drop_column("quality_breakdown")
        batch.drop_column("quality_grade")
        batch.drop_column("quality_score")
    finding_domain.drop(op.get_bind(), checkfirst=True)
