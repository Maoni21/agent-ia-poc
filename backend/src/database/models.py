"""
Modèles SQLAlchemy pour la plateforme SaaS multi-tenant de gestion de vulnérabilités.

Ces modèles implémentent le schéma PostgreSQL défini dans `carhier-des-charges.md`.

Règles clés :
- Multi‑tenancy : presque toutes les tables sont reliées à `organizations`
- Auth & RBAC : utilisateurs avec rôles/permissions
- Toutes les clés primaires sont des UUID (sauf `cve_database`)
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import List, Optional

from sqlalchemy import (
    JSON,
    ARRAY,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    DECIMAL,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarative SQLAlchemy."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# ============================================================================
# TABLE 1: ORGANIZATIONS
# ============================================================================


class Organization(Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)

    # Subscription
    subscription_tier: Mapped[str] = mapped_column(
        String(50), nullable=False, default="free"
    )
    max_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_scans_per_month: Mapped[Optional[int]] = mapped_column(Integer)

    # Billing
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255))
    subscription_status: Mapped[Optional[str]] = mapped_column(
        String(50), default="active"
    )
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    users: Mapped[List["User"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    assets: Mapped[List["Asset"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    remediation_scripts: Mapped[List["RemediationScript"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    api_keys: Mapped[List["APIKey"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    notifications: Mapped[List["Notification"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "subscription_tier IN ('free', 'pro', 'business', 'enterprise')",
            name="check_tier",
        ),
        Index("idx_org_slug", "slug"),
        Index("idx_org_tier", "subscription_tier"),
    )


# ============================================================================
# TABLE 2: USERS
# ============================================================================


class User(Base):
    __tablename__ = "users"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Authentication
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))

    # RBAC
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    permissions: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="users")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="user")
    api_keys: Mapped[List["APIKey"]] = relationship(back_populates="user")
    notifications: Mapped[List["Notification"]] = relationship(back_populates="user")

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'manager', 'analyst', 'viewer')",
            name="check_role",
        ),
        Index("idx_user_email", "email"),
        Index("idx_user_org", "organization_id"),
        Index("idx_user_role", "role"),
    )


# ============================================================================
# TABLE 3: ASSETS
# ============================================================================


class Asset(Base):
    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identification
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[Optional[str]] = mapped_column(MACADDR)

    # Classification
    asset_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="server"
    )
    os: Mapped[Optional[str]] = mapped_column(String(255))
    os_version: Mapped[Optional[str]] = mapped_column(String(100))

    # Organization
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    environment: Mapped[Optional[str]] = mapped_column(String(50))
    business_criticality: Mapped[str] = mapped_column(
        String(50), default="medium"
    )

    # Location
    datacenter: Mapped[Optional[str]] = mapped_column(String(100))
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(50))
    region: Mapped[Optional[str]] = mapped_column(String(100))

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Metadata
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # SSH credentials (chiffrés au niveau applicatif)
    ssh_username: Mapped[Optional[str]] = mapped_column(String(255))
    ssh_password: Mapped[Optional[bytes]] = mapped_column()
    ssh_private_key: Mapped[Optional[bytes]] = mapped_column()

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="assets")
    scans: Mapped[List["Scan"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('server', 'workstation', 'network_device', 'container', 'cloud_instance')",
            name="check_asset_type",
        ),
        CheckConstraint(
            "business_criticality IN ('critical', 'high', 'medium', 'low')",
            name="check_criticality",
        ),
        Index("idx_asset_org", "organization_id"),
        Index("idx_asset_ip", "ip_address"),
        Index("idx_asset_type", "asset_type"),
        Index("idx_asset_env", "environment"),
        Index("idx_asset_tags", "tags", postgresql_using="gin"),
    )


# ============================================================================
# TABLE 4: SCANS
# ============================================================================


class Scan(Base):
    __tablename__ = "scans"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Scan Configuration
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_profile: Mapped[Optional[str]] = mapped_column(String(100))

    # Status
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="queued"
    )
    progress: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)

    # Results Summary
    total_ports_scanned: Mapped[int] = mapped_column(Integer, default=0)
    open_ports_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Risk Score
    risk_score: Mapped[Optional[float]] = mapped_column(DECIMAL(4, 2))

    # Raw Data
    nmap_output: Mapped[Optional[str]] = mapped_column(Text)
    scan_results: Mapped[Optional[dict]] = mapped_column(JSON)

    # Error Handling
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)

    # Metadata
    triggered_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="scans")
    asset: Mapped[Asset] = relationship(back_populates="scans")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "scan_type IN ('quick', 'full', 'stealth', 'compliance', 'custom')",
            name="check_scan_type",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="check_status",
        ),
        Index("idx_scan_org", "organization_id"),
        Index("idx_scan_asset", "asset_id"),
        Index("idx_scan_status", "status"),
        Index("idx_scan_date", "created_at"),
    )


# ============================================================================
# TABLE 5: VULNERABILITIES
# ============================================================================


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # CVE Information
    cve_id: Mapped[Optional[str]] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Severity
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1))
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200))

    # Affected Component
    affected_package: Mapped[Optional[str]] = mapped_column(String(255))
    affected_version: Mapped[Optional[str]] = mapped_column(String(100))
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100))
    port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(10))
    service: Mapped[Optional[str]] = mapped_column(String(100))

    # Detection
    detection_method: Mapped[Optional[str]] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(20), default="medium")

    # AI Analysis
    ai_analyzed: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_analysis: Mapped[Optional[dict]] = mapped_column(JSON)
    ai_priority_score: Mapped[Optional[int]] = mapped_column(Integer)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    # Remediation
    remediation_available: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_complexity: Mapped[Optional[str]] = mapped_column(String(20))
    remediation_script_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True)
    )
    remediation_status: Mapped[str] = mapped_column(
        String(50), default="pending"
    )
    remediation_notes: Mapped[Optional[str]] = mapped_column(Text)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="open")
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )

    # References
    references: Mapped[List[dict]] = mapped_column(JSON, default=list)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(50))

    # Metadata
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    detection_count: Mapped[int] = mapped_column(Integer, default=1)

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")
    organization: Mapped[Organization] = relationship(
        back_populates="vulnerabilities"
    )

    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="check_severity",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="check_confidence",
        ),
        CheckConstraint(
            "status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')",
            name="check_vuln_status",
        ),
        Index("idx_vuln_scan", "scan_id"),
        Index("idx_vuln_org", "organization_id"),
        Index("idx_vuln_cve", "cve_id"),
        Index("idx_vuln_severity", "severity"),
        Index("idx_vuln_status", "status"),
        Index("idx_vuln_score", "cvss_score"),
    )


# ============================================================================
# TABLE 6: CVE_DATABASE
# ============================================================================


class CVEDatabase(Base):
    __tablename__ = "cve_database"

    # On utilise la PK texte comme dans le schéma
    id: Mapped[str] = mapped_column(
        "cve_id", String(50), primary_key=True, unique=True
    )

    description: Mapped[Optional[str]] = mapped_column(Text)
    published_date: Mapped[Optional[date]] = mapped_column(Date)
    last_modified: Mapped[Optional[date]] = mapped_column(Date)

    cvss_v3_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1))
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(200))
    cvss_v2_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1))
    severity: Mapped[Optional[str]] = mapped_column(String(20))

    affected_products: Mapped[List[dict]] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    references: Mapped[List[dict]] = mapped_column(JSON, default=list)

    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(50))
    exploit_references: Mapped[List[dict]] = mapped_column(JSON, default=list)

    source: Mapped[str] = mapped_column(String(50), default="NVD")
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    __table_args__ = (
        Index("idx_cve_date", "published_date"),
        Index("idx_cve_score", "cvss_v3_score"),
        Index("idx_cve_severity", "severity"),
    )


# ============================================================================
# TABLE 7: REMEDIATION_SCRIPTS
# ============================================================================


class RemediationScript(Base):
    __tablename__ = "remediation_scripts"

    vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    script_type: Mapped[str] = mapped_column(String(50), nullable=False)
    script_content: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_script: Mapped[Optional[str]] = mapped_column(Text)

    target_os: Mapped[Optional[str]] = mapped_column(String(100))
    requires_reboot: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_sudo: Mapped[bool] = mapped_column(Boolean, default=True)
    estimated_duration_minutes: Mapped[Optional[int]] = mapped_column(Integer)

    risk_level: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    validation_performed: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_results: Mapped[Optional[dict]] = mapped_column(JSON)

    execution_status: Mapped[str] = mapped_column(
        String(50), default="pending"
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    executed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    execution_output: Mapped[Optional[str]] = mapped_column(Text)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer)

    generated_by: Mapped[Optional[str]] = mapped_column(String(50))
    generation_prompt: Mapped[Optional[str]] = mapped_column(Text)

    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    approval_notes: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    organization: Mapped[Organization] = relationship(
        back_populates="remediation_scripts"
    )

    __table_args__ = (
        CheckConstraint(
            "script_type IN ('bash', 'ansible', 'powershell', 'python')",
            name="check_script_type",
        ),
        CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="check_risk",
        ),
        Index("idx_script_vuln", "vulnerability_id"),
        Index("idx_script_org", "organization_id"),
        Index("idx_script_status", "execution_status"),
    )


# ============================================================================
# TABLE 8: AUDIT_LOGS
# ============================================================================


class AuditLog(Base):
    __tablename__ = "audit_logs"

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_category: Mapped[Optional[str]] = mapped_column(String(50))
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    action: Mapped[Optional[str]] = mapped_column(String(50))

    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    metadata: Mapped[dict] = mapped_column(JSON, default=dict)

    status: Mapped[Optional[str]] = mapped_column(String(20))
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    organization: Mapped[Optional[Organization]] = relationship(
        back_populates="audit_logs"
    )
    user: Mapped[Optional[User]] = relationship(back_populates="audit_logs")

    __table_args__ = (
        CheckConstraint(
            "action IN ('create', 'read', 'update', 'delete', 'execute')",
            name="check_action",
        ),
        Index("idx_audit_org", "organization_id"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_type", "event_type"),
        Index("idx_audit_date", "created_at"),
    )


# ============================================================================
# TABLE 9: API_KEYS
# ============================================================================


class APIKey(Base):
    __tablename__ = "api_keys"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
    )

    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    key_prefix: Mapped[Optional[str]] = mapped_column(String(20))
    name: Mapped[Optional[str]] = mapped_column(String(255))

    scopes: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)

    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="api_keys")
    user: Mapped[Optional[User]] = relationship(back_populates="api_keys")

    __table_args__ = (
        Index("idx_apikey_org", "organization_id"),
        Index("idx_apikey_hash", "key_hash"),
    )


class Notification(Base):
    __tablename__ = "notifications"

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
    )

    type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text)

    priority: Mapped[str] = mapped_column(String(20), default="normal")

    related_resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    related_resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))

    read: Mapped[bool] = mapped_column(Boolean, default=False)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    sent_via: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    metadata: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    organization: Mapped[Optional[Organization]] = relationship(
        back_populates="notifications"
    )
    user: Mapped[Optional[User]] = relationship(back_populates="notifications")

    __table_args__ = (
        CheckConstraint(
            "priority IN ('low', 'normal', 'high', 'urgent')",
            name="check_priority",
        ),
        Index("idx_notif_user", "user_id"),
        Index("idx_notif_org", "organization_id"),
        Index("idx_notif_read", "read"),
        Index("idx_notif_date", "created_at"),
    )


# ============================================================================
# TABLE 11: WEBHOOK_SUBSCRIPTIONS
# ============================================================================


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    events: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    secret: Mapped[Optional[str]] = mapped_column(String(255))
    last_delivery_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    organization: Mapped[Organization] = relationship("Organization")

    __table_args__ = (
        Index("idx_webhook_org", "organization_id"),
        Index("idx_webhook_active", "is_active"),
    )


__all__ = [
    "Base",
    "Organization",
    "User",
    "Asset",
    "Scan",
    "Vulnerability",
    "CVEDatabase",
    "RemediationScript",
    "AuditLog",
    "APIKey",
    "Notification",
    "WebhookSubscription",
]

