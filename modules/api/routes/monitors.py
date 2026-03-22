from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Monitor, MonitorCheck, User
from modules.api.schemas import (
    MonitorCreate, MonitorUpdate, MonitorResponse,
    MonitorCheckResponse,
)
from modules.api.auth import get_current_user

router = APIRouter()


@router.post("/", response_model=MonitorResponse)
def create_monitor(body: MonitorCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = Monitor(
        user_id=user.id,
        name=body.name or body.target,
        target=body.target,
        check_type=body.check_type,
        interval_seconds=body.interval_seconds,
        expected_status=body.expected_status,
    )
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor


@router.get("/", response_model=list[MonitorResponse])
def list_monitors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Monitor).filter(Monitor.user_id == user.id).order_by(Monitor.created_at.desc()).all()


@router.get("/enriched")
def list_monitors_enriched(
    hours: int = Query(24, le=720),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List monitors with per-monitor stats and recent response times for sparklines."""
    monitors = db.query(Monitor).filter(Monitor.user_id == user.id).order_by(Monitor.created_at.desc()).all()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = []
    for m in monitors:
        checks = (
            db.query(MonitorCheck)
            .filter(MonitorCheck.monitor_id == m.id, MonitorCheck.checked_at >= since)
            .order_by(MonitorCheck.checked_at.asc())
            .all()
        )
        total = len(checks)
        ok = sum(1 for c in checks if c.status == "up")
        failed = sum(1 for c in checks if c.status == "down")
        degraded = sum(1 for c in checks if c.status == "degraded")
        uptime_pct = round(ok / total * 100, 1) if total > 0 else None
        avg_ms = round(sum(c.response_ms for c in checks if c.response_ms > 0) / max(1, sum(1 for c in checks if c.response_ms > 0))) if total > 0 else None

        # Sparkline data: last 50 response times
        spark = []
        step = max(1, len(checks) // 50)
        for i in range(0, len(checks), step):
            c = checks[i]
            spark.append({"ms": c.response_ms, "s": c.status})
        spark = spark[-50:]

        result.append({
            "id": m.id,
            "name": m.name or m.target,
            "target": m.target,
            "check_type": m.check_type,
            "interval_seconds": m.interval_seconds,
            "is_active": m.is_active,
            "last_status": m.last_status,
            "last_response_ms": m.last_response_ms,
            "last_checked_at": str(m.last_checked_at) if m.last_checked_at else None,
            "total_checks": total,
            "ok_checks": ok,
            "failed_checks": failed,
            "degraded_checks": degraded,
            "uptime_pct": uptime_pct,
            "avg_ms": avg_ms,
            "sparkline": spark,
        })
    return result


@router.get("/summary")
def monitors_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """High-level summary for dashboard widget."""
    monitors = db.query(Monitor).filter(Monitor.user_id == user.id, Monitor.is_active == True).all()
    total = len(monitors)
    up = sum(1 for m in monitors if m.last_status == "up")
    down = sum(1 for m in monitors if m.last_status == "down")
    degraded = sum(1 for m in monitors if m.last_status == "degraded")
    unchecked = sum(1 for m in monitors if m.last_status is None)

    # Get recent incidents (status changes to down/degraded in last 24h)
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    incidents = []
    for m in monitors:
        recent_downs = (
            db.query(MonitorCheck)
            .filter(
                MonitorCheck.monitor_id == m.id,
                MonitorCheck.status.in_(["down", "degraded"]),
                MonitorCheck.checked_at >= day_ago,
            )
            .order_by(MonitorCheck.checked_at.desc())
            .limit(5)
            .all()
        )
        for chk in recent_downs:
            incidents.append({
                "monitor_name": m.name or m.target,
                "target": m.target,
                "status": chk.status,
                "error": chk.error,
                "checked_at": str(chk.checked_at),
                "response_ms": chk.response_ms,
            })

    incidents.sort(key=lambda x: x["checked_at"], reverse=True)

    return {
        "total": total,
        "up": up,
        "down": down,
        "degraded": degraded,
        "unchecked": unchecked,
        "incidents_24h": incidents[:10],
    }


@router.get("/{monitor_id}", response_model=MonitorResponse)
def get_monitor(monitor_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return monitor


@router.patch("/{monitor_id}", response_model=MonitorResponse)
def update_monitor(monitor_id: str, body: MonitorUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(monitor, field, value)
    db.commit()
    db.refresh(monitor)
    return monitor


@router.delete("/{monitor_id}")
def delete_monitor(monitor_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    db.delete(monitor)
    db.commit()
    return {"status": "deleted"}


@router.get("/{monitor_id}/checks", response_model=list[MonitorCheckResponse])
def get_checks(
    monitor_id: str,
    limit: int = Query(100, le=500),
    hours: int = Query(24, le=720),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get check history for a monitor."""
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    checks = (
        db.query(MonitorCheck)
        .filter(MonitorCheck.monitor_id == monitor_id, MonitorCheck.checked_at >= since)
        .order_by(MonitorCheck.checked_at.desc())
        .limit(limit)
        .all()
    )
    return checks


@router.get("/{monitor_id}/stats")
def get_stats(
    monitor_id: str,
    hours: int = Query(24, le=720),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get uptime statistics for a monitor."""
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    checks = (
        db.query(MonitorCheck)
        .filter(MonitorCheck.monitor_id == monitor_id, MonitorCheck.checked_at >= since)
        .all()
    )

    total = len(checks)
    if total == 0:
        return {
            "monitor_id": monitor_id,
            "period_hours": hours,
            "total_checks": 0,
            "uptime_percent": None,
            "avg_response_ms": None,
            "min_response_ms": None,
            "max_response_ms": None,
            "incidents": 0,
        }

    up_count = sum(1 for c in checks if c.status == "up")
    response_times = [c.response_ms for c in checks if c.response_ms > 0]
    down_checks = [c for c in checks if c.status in ("down", "degraded")]

    # Count incidents (consecutive down periods)
    incident_count = 0
    prev_down = False
    for c in sorted(checks, key=lambda x: x.checked_at):
        is_down = c.status in ("down", "degraded")
        if is_down and not prev_down:
            incident_count += 1
        prev_down = is_down

    return {
        "monitor_id": monitor_id,
        "period_hours": hours,
        "total_checks": total,
        "uptime_percent": round(up_count / total * 100, 2),
        "avg_response_ms": round(sum(response_times) / len(response_times)) if response_times else None,
        "min_response_ms": min(response_times) if response_times else None,
        "max_response_ms": max(response_times) if response_times else None,
        "incidents": incident_count,
        "down_checks": len(down_checks),
    }
