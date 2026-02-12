"""Create complete initial schema

Ce fichier implémente le schéma PostgreSQL complet décrit dans
`carhier-des-charges.md` pour la Phase 1 / Semaine 1.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Révision Alembic
revision = "001_create_complete_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # organizations
    op.create_table(
        "organizations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False, unique=True),
        sa.Column(
            "subscription_tier",
            sa.String(length=50),
            nullable=False,
            server_default="free",
        ),
        sa.Column(
            "max_assets", sa.Integer(), nullable=False, server_default=sa.text("10")
        ),
        sa.Column("max_scans_per_month", sa.Integer(), nullable=True),
        sa.Column("stripe_customer_id", sa.String(length=255), nullable=True),
        sa.Column(
            "subscription_status",
            sa.String(length=50),
            nullable=True,
            server_default="active",
        ),
        sa.Column("trial_ends_at", sa.DateTime(), nullable=True),
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
        sa.CheckConstraint(
            "subscription_tier IN ('free', 'pro', 'business', 'enterprise')",
            name="check_tier",
        ),
    )
    op.create_index("idx_org_slug", "organizations", ["slug"])
    op.create_index("idx_org_tier", "organizations", ["subscription_tier"])

    # users
    op.create_table(
        "users",
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
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column(
            "role",
            sa.String(length=50),
            nullable=False,
            server_default="viewer",
        ),
        sa.Column(
            "permissions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")
        ),
        sa.Column(
            "is_verified", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")
        ),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
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
        sa.CheckConstraint(
            "role IN ('admin', 'manager', 'analyst', 'viewer')",
            name="check_role",
        ),
    )
    op.create_index("idx_user_email", "users", ["email"])
    op.create_index("idx_user_org", "users", ["organization_id"])
    op.create_index("idx_user_role", "users", ["role"])

    # assets
    op.create_table(
        "assets",
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
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("mac_address", postgresql.MACADDR(), nullable=True),
        sa.Column(
            "asset_type",
            sa.String(length=50),
            nullable=False,
            server_default="server",
        ),
        sa.Column("os", sa.String(length=255), nullable=True),
        sa.Column("os_version", sa.String(length=100), nullable=True),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("environment", sa.String(length=50), nullable=True),
        sa.Column(
            "business_criticality",
            sa.String(length=50),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("datacenter", sa.String(length=100), nullable=True),
        sa.Column("cloud_provider", sa.String(length=50), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")
        ),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column(
            "monitoring_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column("notes", sa.Text(), nullable=True),
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
        sa.CheckConstraint(
            "asset_type IN ('server', 'workstation', 'network_device', 'container', 'cloud_instance')",
            name="check_asset_type",
        ),
        sa.CheckConstraint(
            "business_criticality IN ('critical', 'high', 'medium', 'low')",
            name="check_criticality",
        ),
    )
    op.create_index("idx_asset_org", "assets", ["organization_id"])
    op.create_index("idx_asset_ip", "assets", ["ip_address"])
    op.create_index("idx_asset_type", "assets", ["asset_type"])
    op.create_index("idx_asset_env", "assets", ["environment"])
    op.create_index(
        "idx_asset_tags",
        "assets",
        ["tags"],
        postgresql_using="gin",
    )

    # scans
    op.create_table(
        "scans",
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
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column("scan_profile", sa.String(length=100), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "total_ports_scanned",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "open_ports_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "vulnerabilities_found",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "critical_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("info_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Numeric(4, 2), nullable=True),
        sa.Column("nmap_output", sa.Text(), nullable=True),
        sa.Column(
            "scan_results",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "retry_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "triggered_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
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
        sa.CheckConstraint(
            "scan_type IN ('quick', 'full', 'stealth', 'compliance', 'custom')",
            name="check_scan_type",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="check_status",
        ),
    )
    op.create_index("idx_scan_org", "scans", ["organization_id"])
    op.create_index("idx_scan_asset", "scans", ["asset_id"])
    op.create_index("idx_scan_status", "scans", ["status"])
    op.create_index(
        "idx_scan_date",
        "scans",
        ["created_at"],
        postgresql_using="btree",
    )

    # vulnerabilities
    op.create_table(
        "vulnerabilities",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cve_id", sa.String(length=50), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("affected_package", sa.String(length=255), nullable=True),
        sa.Column("affected_version", sa.String(length=100), nullable=True),
        sa.Column("fixed_version", sa.String(length=100), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=10), nullable=True),
        sa.Column("service", sa.String(length=100), nullable=True),
        sa.Column("detection_method", sa.String(length=50), nullable=True),
        sa.Column("confidence", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("ai_analyzed", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column(
            "ai_analysis",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("ai_priority_score", sa.Integer(), nullable=True),
        sa.Column(
            "false_positive",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column(
            "remediation_available",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("remediation_complexity", sa.String(length=20), nullable=True),
        sa.Column(
            "remediation_script_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "remediation_status",
            sa.String(length=50),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default="open",
        ),
        sa.Column(
            "assigned_to",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column(
            "resolved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "exploit_available",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("exploit_maturity", sa.String(length=50), nullable=True),
        sa.Column(
            "first_detected_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "detection_count",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
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
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="check_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="check_confidence",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')",
            name="check_vuln_status",
        ),
    )
    op.create_index("idx_vuln_scan", "vulnerabilities", ["scan_id"])
    op.create_index("idx_vuln_org", "vulnerabilities", ["organization_id"])
    op.create_index("idx_vuln_cve", "vulnerabilities", ["cve_id"])
    op.create_index("idx_vuln_severity", "vulnerabilities", ["severity"])
    op.create_index("idx_vuln_status", "vulnerabilities", ["status"])
    op.create_index("idx_vuln_score", "vulnerabilities", ["cvss_score"])

    # cve_database
    op.create_table(
        "cve_database",
        sa.Column("cve_id", sa.String(length=50), primary_key=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("published_date", sa.Date(), nullable=True),
        sa.Column("last_modified", sa.Date(), nullable=True),
        sa.Column("cvss_v3_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("cvss_v3_vector", sa.String(length=200), nullable=True),
        sa.Column("cvss_v2_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column(
            "affected_products",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "cwe_ids",
            postgresql.ARRAY(sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "exploit_available",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("exploit_maturity", sa.String(length=50), nullable=True),
        sa.Column(
            "exploit_references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "source",
            sa.String(length=50),
            nullable=False,
            server_default="NVD",
        ),
        sa.Column(
            "last_synced_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("idx_cve_date", "cve_database", ["published_date"])
    op.create_index("idx_cve_score", "cve_database", ["cvss_v3_score"])
    op.create_index("idx_cve_severity", "cve_database", ["severity"])

    # remediation_scripts
    op.create_table(
        "remediation_scripts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("script_type", sa.String(length=50), nullable=False),
        sa.Column("script_content", sa.Text(), nullable=False),
        sa.Column("rollback_script", sa.Text(), nullable=True),
        sa.Column("target_os", sa.String(length=100), nullable=True),
        sa.Column(
            "requires_reboot",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column(
            "requires_sudo",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column("estimated_duration_minutes", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(length=20), nullable=False, server_default="MEDIUM"),
        sa.Column(
            "validation_performed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column(
            "validation_results",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "execution_status",
            sa.String(length=50),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "executed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("execution_output", sa.Text(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("generated_by", sa.String(length=50), nullable=True),
        sa.Column("generation_prompt", sa.Text(), nullable=True),
        sa.Column(
            "requires_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column(
            "approved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approval_notes", sa.Text(), nullable=True),
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
        sa.CheckConstraint(
            "script_type IN ('bash', 'ansible', 'powershell', 'python')",
            name="check_script_type",
        ),
        sa.CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="check_risk",
        ),
    )
    op.create_index("idx_script_vuln", "remediation_scripts", ["vulnerability_id"])
    op.create_index("idx_script_org", "remediation_scripts", ["organization_id"])
    op.create_index(
        "idx_script_status", "remediation_scripts", ["execution_status"]
    )

    # audit_logs
    op.create_table(
        "audit_logs",
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
            nullable=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("event_category", sa.String(length=50), nullable=True),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "action IN ('create', 'read', 'update', 'delete', 'execute')",
            name="check_action",
        ),
    )
    op.create_index("idx_audit_org", "audit_logs", ["organization_id"])
    op.create_index("idx_audit_user", "audit_logs", ["user_id"])
    op.create_index("idx_audit_type", "audit_logs", ["event_type"])
    op.create_index("idx_audit_date", "audit_logs", ["created_at"])

    # api_keys
    op.create_table(
        "api_keys",
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
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("key_hash", sa.String(length=255), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(length=20), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column(
            "scopes",
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
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column(
            "usage_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
    )
    op.create_index("idx_apikey_org", "api_keys", ["organization_id"])
    op.create_index("idx_apikey_hash", "api_keys", ["key_hash"])

    # notifications
    op.create_table(
        "notifications",
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
            nullable=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "priority",
            sa.String(length=20),
            nullable=False,
            server_default="normal",
        ),
        sa.Column("related_resource_type", sa.String(length=50), nullable=True),
        sa.Column(
            "related_resource_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "read",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("read_at", sa.DateTime(), nullable=True),
        sa.Column(
            "sent_via",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "priority IN ('low', 'normal', 'high', 'urgent')",
            name="check_priority",
        ),
    )
    op.create_index("idx_notif_user", "notifications", ["user_id"])
    op.create_index("idx_notif_org", "notifications", ["organization_id"])
    op.create_index("idx_notif_read", "notifications", ["read"])
    op.create_index("idx_notif_date", "notifications", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_notif_date", table_name="notifications")
    op.drop_index("idx_notif_read", table_name="notifications")
    op.drop_index("idx_notif_org", table_name="notifications")
    op.drop_index("idx_notif_user", table_name="notifications")
    op.drop_table("notifications")

    op.drop_index("idx_apikey_hash", table_name="api_keys")
    op.drop_index("idx_apikey_org", table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("idx_audit_date", table_name="audit_logs")
    op.drop_index("idx_audit_type", table_name="audit_logs")
    op.drop_index("idx_audit_user", table_name="audit_logs")
    op.drop_index("idx_audit_org", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("idx_script_status", table_name="remediation_scripts")
    op.drop_index("idx_script_org", table_name="remediation_scripts")
    op.drop_index("idx_script_vuln", table_name="remediation_scripts")
    op.drop_table("remediation_scripts")

    op.drop_index("idx_cve_severity", table_name="cve_database")
    op.drop_index("idx_cve_score", table_name="cve_database")
    op.drop_index("idx_cve_date", table_name="cve_database")
    op.drop_table("cve_database")

    op.drop_index("idx_vuln_score", table_name="vulnerabilities")
    op.drop_index("idx_vuln_status", table_name="vulnerabilities")
    op.drop_index("idx_vuln_severity", table_name="vulnerabilities")
    op.drop_index("idx_vuln_cve", table_name="vulnerabilities")
    op.drop_index("idx_vuln_org", table_name="vulnerabilities")
    op.drop_index("idx_vuln_scan", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")

    op.drop_index("idx_scan_date", table_name="scans")
    op.drop_index("idx_scan_status", table_name="scans")
    op.drop_index("idx_scan_asset", table_name="scans")
    op.drop_index("idx_scan_org", table_name="scans")
    op.drop_table("scans")

    op.drop_index("idx_asset_tags", table_name="assets")
    op.drop_index("idx_asset_env", table_name="assets")
    op.drop_index("idx_asset_type", table_name="assets")
    op.drop_index("idx_asset_ip", table_name="assets")
    op.drop_index("idx_asset_org", table_name="assets")
    op.drop_table("assets")

    op.drop_index("idx_user_role", table_name="users")
    op.drop_index("idx_user_org", table_name="users")
    op.drop_index("idx_user_email", table_name="users")
    op.drop_table("users")

    op.drop_index("idx_org_tier", table_name="organizations")
    op.drop_index("idx_org_slug", table_name="organizations")
    op.drop_table("organizations")

