import os
import subprocess

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from modules.api.database import engine, Base
from modules.api.routes import scans, auth, monitors, schedules, notifications, reports, tools

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Scanner API",
    version="0.2.0",
    description="AI-powered autonomous security scanning, SEO analysis, and compliance monitoring platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core routes
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(monitors.router, prefix="/api/monitors", tags=["monitors"])

# New routes
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(tools.router, prefix="/api/tools", tags=["tools"])


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


# ─── Worker logs endpoint (reads from Redis pub/sub or Docker logs) ────
import redis as _redis

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")


@app.get("/api/logs/worker")
def worker_logs():
    """Return recent worker log lines stored in Redis."""
    try:
        r = _redis.from_url(_REDIS_URL)
        lines = r.lrange("worker:logs", -200, -1)
        return {"logs": "\n".join(l.decode() if isinstance(l, bytes) else l for l in lines)}
    except Exception:
        return {"logs": "Log streaming not available. Check docker compose logs worker."}


@app.get("/api/scans/{scan_id}/activity")
def scan_activity(scan_id: str):
    """Return live scan activity (commands executed, current tool) from Redis."""
    try:
        r = _redis.from_url(_REDIS_URL)
        # Read activity log for this scan
        lines = r.lrange(f"scan:activity:{scan_id}", 0, -1)
        activities = []
        for line in lines:
            try:
                import json as _json
                activities.append(_json.loads(line.decode() if isinstance(line, bytes) else line))
            except Exception:
                activities.append({"message": line.decode() if isinstance(line, bytes) else str(line)})
        return {"scan_id": scan_id, "activities": activities}
    except Exception:
        return {"scan_id": scan_id, "activities": []}


# ─── Dashboard UI ─────────────────────────────────────────────────────
_STATIC = os.path.join(os.path.dirname(__file__), "static")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    path = os.path.join(_STATIC, "dashboard.html")
    if os.path.exists(path):
        with open(path) as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)
