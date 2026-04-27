"""Add remediation_projects table

Revision ID: 006_remediation_projects
Revises: 005_vuln_enrichment
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "006_remediation_projects"
down_revision = "005_vuln_enrichment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediation_projects",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("status", sa.String(50), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("due_date", sa.DateTime),
        sa.Column("total_vulns", sa.Integer, server_default="0"),
        sa.Column("resolved_vulns", sa.Integer, server_default="0"),
        sa.Column("assigned_to", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('open', 'in_progress', 'completed', 'cancelled')", name="check_project_status"),
        sa.CheckConstraint("priority IN ('critical', 'high', 'medium', 'low')", name="check_project_priority"),
    )
    op.create_index("idx_project_org", "remediation_projects", ["organization_id"])
    op.create_index("idx_project_status", "remediation_projects", ["status"])
    op.create_index("idx_project_priority", "remediation_projects", ["priority"])


def downgrade() -> None:
    op.drop_index("idx_project_priority")
    op.drop_index("idx_project_status")
    op.drop_index("idx_project_org")
    op.drop_table("remediation_projects")
