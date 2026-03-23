from datetime import datetime

from pydantic import BaseModel, Field


# ─── Auth ──────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    plan: str
    is_active: bool = True
    failed_attempts: int = 0
    locked_until: datetime | None = None
    last_login: datetime | None = None
    totp_enabled: bool = False
    created_at: datetime | None = None

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
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost: float = 0.0

    model_config = {"from_attributes": True}


# ─── Monitors ──────────────────────────────────────────────────────────
class MonitorCreate(BaseModel):
    name: str = ""
    target: str
    check_type: str = "http"
    interval_seconds: int = 300
    expected_status: int = 200


class MonitorUpdate(BaseModel):
    name: str | None = None
    target: str | None = None
    check_type: str | None = None
    interval_seconds: int | None = None
    expected_status: int | None = None
    is_active: bool | None = None


class MonitorResponse(BaseModel):
    id: str
    name: str = ""
    target: str
    check_type: str
    interval_seconds: int
    expected_status: int = 200
    is_active: bool
    last_status: str | None = None
    last_response_ms: int | None = None
    last_checked_at: datetime | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class MonitorCheckResponse(BaseModel):
    id: str
    status: str
    status_code: int | None = None
    response_ms: int = 0
    error: str | None = None
    checked_at: datetime

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


# ─── Campaigns ────────────────────────────────────────────────────────
class CampaignCreate(BaseModel):
    name: str = ""
    targets: list[str] = Field(..., min_length=1, max_length=50)
    scan_type: str = "security"
    config: dict | None = None


class CampaignScanSummary(BaseModel):
    id: str
    target: str
    status: str
    risk_score: float | None = None
    findings_count: int = 0

    model_config = {"from_attributes": True}


class CampaignResponse(BaseModel):
    id: str
    name: str
    scan_type: str
    status: str
    targets: list[str]
    aggregate_risk_score: float | None = None
    created_at: datetime
    completed_at: datetime | None = None
    scans: list[CampaignScanSummary] = []

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
