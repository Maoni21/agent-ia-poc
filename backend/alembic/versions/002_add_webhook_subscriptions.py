"""Add webhook_subscriptions table

Revision ID: 002_add_webhook_subscriptions
Revises: 001_create_complete_schema
Create Date: 2026-02-12
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "002_add_webhook_subscriptions"
down_revision = "001_create_complete_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_subscriptions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column(
            "events",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column("secret", sa.String(length=255), nullable=True),
        sa.Column("last_delivery_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index(
        "idx_webhook_org", "webhook_subscriptions", ["organization_id"]
    )
    op.create_index(
        "idx_webhook_active", "webhook_subscriptions", ["is_active"]
    )


def downgrade() -> None:
    op.drop_index("idx_webhook_active", table_name="webhook_subscriptions")
    op.drop_index("idx_webhook_org", table_name="webhook_subscriptions")
    op.drop_table("webhook_subscriptions")

