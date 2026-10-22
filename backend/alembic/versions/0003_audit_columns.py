"""audit columns: who started each scan / opened each PR

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("created_by", sa.String(320)))
    with op.batch_alter_table("pull_requests") as batch:
        batch.add_column(sa.Column("opened_by", sa.String(320)))


def downgrade() -> None:
    with op.batch_alter_table("pull_requests") as batch:
        batch.drop_column("opened_by")
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("created_by")
