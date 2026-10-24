"""users: every scan belongs to the person who started it

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-24

Existing scans keep user_id NULL: they were recorded by email only, which can't be mapped to a
Firebase uid, so after this migration they no longer appear in anyone's history.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("firebase_uid", sa.String(128), nullable=False),
        sa.Column("github_id", sa.String(32)),
        sa.Column("email", sa.String(320)),
        sa.Column("name", sa.String(255)),
        sa.Column("avatar_url", sa.String(1024)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("firebase_uid", name="uq_users_firebase_uid"),
    )
    op.create_index("ix_users_github_id", "users", ["github_id"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("user_id", sa.Uuid()))
        batch.add_column(
            sa.Column("patched_count", sa.Integer(), server_default="0", nullable=False)
        )
        batch.create_foreign_key(
            "fk_scans_user_id_users", "users", ["user_id"], ["id"], ondelete="CASCADE"
        )
        batch.create_index("idx_scans_user_created", ["user_id", "created_at"])

    op.execute(
        "UPDATE scans SET patched_count = (SELECT COUNT(*) FROM findings "
        "WHERE findings.scan_id = scans.id AND findings.status = 'PATCH_APPLIED')"
    )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_index("idx_scans_user_created")
        batch.drop_constraint("fk_scans_user_id_users", type_="foreignkey")
        batch.drop_column("patched_count")
        batch.drop_column("user_id")
    op.drop_index("ix_users_github_id", table_name="users")
    op.drop_table("users")
