"""Add secure share options and audit IP addresses.

Revision ID: 20261123_0002
Revises: 20261123_0001
"""
from alembic import op
import sqlalchemy as sa

revision = "20261123_0002"
down_revision = "20261123_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("share_links", sa.Column("password_hash", sa.String(255), nullable=True))
    op.add_column(
        "share_links",
        sa.Column("one_time", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("audit_logs", sa.Column("ip_address", sa.String(45), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "ip_address")
    op.drop_column("share_links", "one_time")
    op.drop_column("share_links", "password_hash")
