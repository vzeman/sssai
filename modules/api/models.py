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
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scans: Mapped[list["Scan"]] = relationship(back_populates="user")
    monitors: Mapped[list["Monitor"]] = relationship(back_populates="user")
    scheduled_scans: Mapped[list["ScheduledScan"]] = relationship(back_populates="user")
    notification_channels: Mapped[list["NotificationChannel"]] = relationship(back_populates="user")


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

    user: Mapped["User"] = relationship(back_populates="scans")


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String)
    check_type: Mapped[str] = mapped_column(String, default="http")  # http, tcp, dns, tls
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_status: Mapped[str | None] = mapped_column(String, nullable=True)
    last_response_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="monitors")


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
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="scheduled_scans")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String)
    channel_type: Mapped[str] = mapped_column(String)  # email, slack, discord, webhook, openclaw
    config: Mapped[dict] = mapped_column(JSON)  # channel-specific config (webhook_url, to_email, etc.)
    min_severity: Mapped[str] = mapped_column(String, default="info")  # info, warning, critical
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="notification_channels")
