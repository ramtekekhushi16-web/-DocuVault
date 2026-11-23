"""Create DocuVault schema, full-text index, and immutable audit guard.

Revision ID: 20261123_0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "20261123_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("encrypted_content", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_documents_owner_id", "documents", ["owner_id"])
    op.create_index("ix_documents_owner_updated", "documents", ["owner_id", "updated_at"])
    op.execute(
        "CREATE INDEX ix_documents_title_fts ON documents "
        "USING GIN (to_tsvector('english', title))"
    )

    op.create_table(
        "document_permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('editor', 'viewer')", name="ck_document_permission_role"),
        sa.UniqueConstraint("document_id", "user_id", name="uq_document_permission"),
    )
    op.create_index("ix_document_permissions_document_id", "document_permissions", ["document_id"])
    op.create_index("ix_document_permissions_user_id", "document_permissions", ["user_id"])

    op.create_table(
        "document_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("encrypted_content", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("document_id", "version_number", name="uq_document_version"),
    )
    op.create_index("ix_document_versions_document_id", "document_versions", ["document_id"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("jti", sa.String(100), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("replaced_by", sa.String(100)),
        sa.UniqueConstraint("jti", name="uq_refresh_tokens_jti"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"])
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])

    op.create_table(
        "share_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_share_links_token_hash"),
    )
    op.create_index("ix_share_links_document_id", "share_links", ["document_id"])
    op.create_index("ix_share_links_token_hash", "share_links", ["token_hash"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer()),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.execute("""
        CREATE FUNCTION reject_audit_log_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs are immutable';
        END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("""
        CREATE TRIGGER audit_logs_immutable
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_logs_immutable ON audit_logs")
    op.execute("DROP FUNCTION reject_audit_log_mutation()")
    op.drop_table("audit_logs")
    op.drop_index("ix_share_links_token_hash", table_name="share_links")
    op.drop_index("ix_share_links_document_id", table_name="share_links")
    op.drop_table("share_links")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_document_versions_document_id", table_name="document_versions")
    op.drop_table("document_versions")
    op.drop_index("ix_document_permissions_user_id", table_name="document_permissions")
    op.drop_index("ix_document_permissions_document_id", table_name="document_permissions")
    op.drop_table("document_permissions")
    op.drop_index("ix_documents_title_fts", table_name="documents")
    op.drop_index("ix_documents_owner_updated", table_name="documents")
    op.drop_index("ix_documents_owner_id", table_name="documents")
    op.drop_table("documents")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
