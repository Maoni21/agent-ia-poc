"""Add SSH credentials fields to assets

Revision ID: 003_add_ssh_credentials_to_assets
Revises: 002_add_webhook_subscriptions
Create Date: 2026-02-12
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "003_add_ssh_credentials_to_assets"
down_revision = "002_add_webhook_subscriptions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("ssh_username", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("ssh_password", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("ssh_private_key", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "ssh_private_key")
    op.drop_column("assets", "ssh_password")
    op.drop_column("assets", "ssh_username")

