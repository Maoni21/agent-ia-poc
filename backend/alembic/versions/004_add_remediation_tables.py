"""Add remediation_plans, remediation_executions and validation_scans tables

Revision ID: 004_remediation_tables
Revises: 003_ssh_credentials
Create Date: 2026-03-31
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision = "004_remediation_tables"
down_revision = "003_ssh_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── remediation_plans ──────────────────────────────────────────────────
    op.create_table(
        "remediation_plans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("analysis_result", sa.JSON(), nullable=True),
        sa.Column("execution_plan", sa.JSON(), nullable=True),
        sa.Column("estimated_duration", sa.Integer, nullable=True),
        sa.Column("estimated_downtime", sa.Integer, nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending_approval"),
        sa.Column("approved_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("execution_log", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('analyzing', 'pending_approval', 'approved', 'executing', 'completed', 'failed', 'cancelled')",
            name="check_plan_status",
        ),
    )
    op.create_index("idx_plan_scan", "remediation_plans", ["scan_id"])
    op.create_index("idx_plan_org", "remediation_plans", ["organization_id"])
    op.create_index("idx_plan_status", "remediation_plans", ["status"])

    # ── remediation_executions ─────────────────────────────────────────────
    op.create_table(
        "remediation_executions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("remediation_plan_id", UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("step_number", sa.Integer, nullable=False),
        sa.Column("step_name", sa.String(500), nullable=False),
        sa.Column("script_content", sa.Text, nullable=True),
        sa.Column("rollback_script", sa.Text, nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("duration", sa.Integer, nullable=True),
        sa.Column("stdout", sa.Text, nullable=True),
        sa.Column("stderr", sa.Text, nullable=True),
        sa.Column("exit_code", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'rolled_back', 'skipped')",
            name="check_exec_status",
        ),
    )
    op.create_index("idx_exec_plan", "remediation_executions", ["remediation_plan_id"])
    op.create_index("idx_exec_status", "remediation_executions", ["status"])

    # ── validation_scans ───────────────────────────────────────────────────
    op.create_table(
        "validation_scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("remediation_plan_id", UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("before_score", sa.Integer, nullable=True),
        sa.Column("after_score", sa.Integer, nullable=True),
        sa.Column("fixed_vulnerabilities", sa.JSON(), nullable=True),
        sa.Column("remaining_vulnerabilities", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'scanning', 'completed', 'failed')",
            name="check_val_status",
        ),
    )
    op.create_index("idx_val_plan", "validation_scans", ["remediation_plan_id"])

    # ── Ajout colonnes SSH manquantes sur assets ───────────────────────────
    # ssh_port et ssh_auth_method n'existent pas encore
    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(sa.Column("ssh_port", sa.Integer, nullable=True, server_default="22"))
        batch_op.add_column(sa.Column("ssh_auth_method", sa.String(20), nullable=True))
        batch_op.add_column(sa.Column("auto_scan_enabled", sa.Boolean, nullable=True, server_default="true"))
        batch_op.add_column(sa.Column("last_security_score", sa.Integer, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_column("last_security_score")
        batch_op.drop_column("auto_scan_enabled")
        batch_op.drop_column("ssh_auth_method")
        batch_op.drop_column("ssh_port")

    op.drop_table("validation_scans")
    op.drop_table("remediation_executions")
    op.drop_table("remediation_plans")
