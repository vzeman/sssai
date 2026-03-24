import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, DateTime, Boolean, JSON, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from modules.api.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    plan: Mapped[str] = mapped_column(String, default="free")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scans: Mapped[list["Scan"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    monitors: Mapped[list["Monitor"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    scheduled_scans: Mapped[list["ScheduledScan"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    notification_channels: Mapped[list["NotificationChannel"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    campaigns: Mapped[list["Campaign"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    assets: Mapped[list["Asset"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    webhook_configs: Mapped[list["WebhookConfig"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String, default="")
    scan_type: Mapped[str] = mapped_column(String, default="security")
    status: Mapped[str] = mapped_column(String, default="running")  # running, completed, failed
    targets: Mapped[list] = mapped_column(JSON, default=list)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    aggregate_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="campaigns")
    scans: Mapped[list["Scan"]] = relationship(back_populates="campaign")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String, index=True)
    scan_type: Mapped[str] = mapped_column(String)  # security, pentest, performance, seo, uptime, compliance, full
    status: Mapped[str] = mapped_column(String, default="queued")  # queued, running, completed, failed
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    schedule_id: Mapped[str | None] = mapped_column(ForeignKey("scheduled_scans.id"), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    total_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost: Mapped[float] = mapped_column(Float, default=0.0)

    user: Mapped["User"] = relationship(back_populates="scans")
    campaign: Mapped["Campaign | None"] = relationship(back_populates="scans")


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String, default="")
    target: Mapped[str] = mapped_column(String)
    check_type: Mapped[str] = mapped_column(String, default="http")  # http, tcp, dns, tls
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    expected_status: Mapped[int] = mapped_column(Integer, default=200)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_status: Mapped[str | None] = mapped_column(String, nullable=True)
    last_response_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="monitors")
    checks: Mapped[list["MonitorCheck"]] = relationship(back_populates="monitor", cascade="all, delete-orphan")


class MonitorCheck(Base):
    __tablename__ = "monitor_checks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String)  # up, down, degraded
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    monitor: Mapped["Monitor"] = relationship(back_populates="checks")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String, index=True)
    scan_type: Mapped[str] = mapped_column(String, default="security")
    cron_expression: Mapped[str] = mapped_column(String)  # "hourly", "daily", "weekly", "12h", "30m"
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    max_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unlimited
    timezone: Mapped[str | None] = mapped_column(String, nullable=True, default="UTC")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="scheduled_scans")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String, index=True)  # parent scan target (e.g. example.com)
    asset_type: Mapped[str] = mapped_column(String)  # domain, subdomain, ip, api_endpoint, service, certificate, dns_record
    hostname: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String, nullable=True)
    technology: Mapped[str | None] = mapped_column(String, nullable=True)
    technology_name: Mapped[str | None] = mapped_column(String, nullable=True)  # normalized technology name (alias for cve_monitor)
    technology_version: Mapped[str | None] = mapped_column(String, nullable=True)  # version detected for technology
    cpe_entries: Mapped[list | None] = mapped_column(JSON, nullable=True)  # CPE identifiers for CVE matching
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # additional metadata
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_id: Mapped[str | None] = mapped_column(String, nullable=True)  # last scan that discovered/updated this

    user: Mapped["User"] = relationship(back_populates="assets")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String)
    channel_type: Mapped[str] = mapped_column(String)  # email, slack, discord, webhook, jira, linear, github_issues
    config: Mapped[dict] = mapped_column(JSON)  # channel-specific config (webhook_url, to_email, etc.)
    min_severity: Mapped[str] = mapped_column(String, default="info")  # info, warning, critical
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="notification_channels")


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String)
    key_prefix: Mapped[str] = mapped_column(String, index=True)  # first 8 chars for lookup
    key_hash: Mapped[str] = mapped_column(String)  # bcrypt hash for verification
    gates: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # default quality gates
    scan_type: Mapped[str] = mapped_column(String, default="security")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="webhook_configs")


class AuditLog(Base):
    """
    Immutable audit log for compliance and security monitoring.
    Records all user actions on resources for SOC 2 / ISO 27001 compliance.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    
    # Action metadata
    action: Mapped[str] = mapped_column(String, index=True)  # create, read, update, delete, export, download, etc.
    resource_type: Mapped[str] = mapped_column(String, index=True)  # scan, monitor, campaign, user, asset, etc.
    resource_id: Mapped[str] = mapped_column(String, index=True)  # ID of the affected resource
    
    # Request metadata
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    
    # State changes (JSON-serialized)
    before_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # Previous values
    after_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # New values
    
    # Outcome
    status: Mapped[str] = mapped_column(String, default="success")  # success, failure
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Immutable timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    
    user: Mapped["User"] = relationship(back_populates="audit_logs")


class CveAlert(Base):
    __tablename__ = "cve_alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str | None] = mapped_column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_product: Mapped[str | None] = mapped_column(String, nullable=True)
    affected_version: Mapped[str | None] = mapped_column(String, nullable=True)
    notification_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    asset: Mapped["Asset"] = relationship()


# Alias for backward compatibility
AssetInventory = Asset
