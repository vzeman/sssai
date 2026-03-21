from datetime import datetime

from pydantic import BaseModel


# ─── Auth ──────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    plan: str

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ─── Scans ─────────────────────────────────────────────────────────────
class ScanCreate(BaseModel):
    target: str
    scan_type: str = "security"
    config: dict | None = None


class ScanResponse(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    risk_score: float | None = None
    findings_count: int = 0
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


# ─── Monitors ──────────────────────────────────────────────────────────
class MonitorCreate(BaseModel):
    target: str
    check_type: str = "http"
    interval_seconds: int = 300


class MonitorResponse(BaseModel):
    id: str
    target: str
    check_type: str
    interval_seconds: int
    is_active: bool
    last_status: str | None = None
    last_response_ms: int | None = None
    last_checked_at: datetime | None = None

    model_config = {"from_attributes": True}


# ─── Scheduled Scans ──────────────────────────────────────────────────
class ScheduledScanCreate(BaseModel):
    target: str
    scan_type: str = "security"
    cron_expression: str = "daily"  # "hourly", "daily", "weekly", "12h", "30m", etc.
    config: dict | None = None
    max_runs: int | None = None


class ScheduledScanUpdate(BaseModel):
    is_active: bool | None = None
    cron_expression: str | None = None
    config: dict | None = None
    max_runs: int | None = None


class ScheduledScanResponse(BaseModel):
    id: str
    target: str
    scan_type: str
    cron_expression: str
    is_active: bool
    next_run_at: datetime
    last_run_at: datetime | None = None
    run_count: int = 0
    max_runs: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Notification Channels ────────────────────────────────────────────
class NotificationChannelCreate(BaseModel):
    name: str
    channel_type: str  # email, slack, discord, webhook, openclaw
    config: dict  # channel-specific: {"webhook_url": "..."}, {"to_email": "..."}, etc.
    min_severity: str = "info"


class NotificationChannelUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    min_severity: str | None = None
    is_active: bool | None = None


class NotificationChannelResponse(BaseModel):
    id: str
    name: str
    channel_type: str
    config: dict
    min_severity: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Reports ──────────────────────────────────────────────────────────
class ReportRequest(BaseModel):
    format: str = "json"  # json, html, pdf


# ─── Tools ────────────────────────────────────────────────────────────
class ToolInfo(BaseModel):
    name: str
    category: str
    description: str
    examples: list[str] = []
    output_formats: list[str] = []
