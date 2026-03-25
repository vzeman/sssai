"""API routes for scheduled/recurring scans."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Scan, ScheduledScan, User
from modules.api.schemas import ScheduledScanCreate, ScheduledScanUpdate, ScheduledScanResponse
from modules.api.auth import get_current_user
from modules.infra import get_queue

router = APIRouter()


import re

_INTERVAL_RE = re.compile(r"^(\d{1,4})([hmd])$")


def _paginated_response(items: list, total: int, skip: int, limit: int) -> dict:
    """Build a paginated response dict."""
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_next": skip + limit < total,
        "has_prev": skip > 0,
    }


def calc_first_run(cron_expression: str) -> datetime:
    """Calculate when the first run should happen."""
    now = datetime.utcnow()
    expr = cron_expression.strip().lower()
    if expr == "hourly":
        return now + timedelta(hours=1)
    elif expr == "daily":
        return now + timedelta(days=1)
    elif expr == "weekly":
        return now + timedelta(weeks=1)
    elif expr == "monthly":
        return now + timedelta(days=30)
    else:
        m = _INTERVAL_RE.match(expr)
        if m:
            val = min(int(m.group(1)), 9999)
            unit = m.group(2)
            if unit == "h":
                return now + timedelta(hours=val)
            elif unit == "m":
                return now + timedelta(minutes=val)
            elif unit == "d":
                return now + timedelta(days=val)
    return now + timedelta(days=1)


@router.post("/", response_model=ScheduledScanResponse)
def create_schedule(body: ScheduledScanCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    schedule = ScheduledScan(
        user_id=user.id,
        target=body.target,
        scan_type=body.scan_type,
        cron_expression=body.cron_expression,
        config=body.config,
        max_runs=body.max_runs,
        next_run_at=calc_first_run(body.cron_expression),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@router.get("/")
def list_schedules(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(ScheduledScan).filter(ScheduledScan.user_id == user.id).order_by(ScheduledScan.created_at.desc())
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return _paginated_response(items, total, skip, limit)


@router.get("/{schedule_id}", response_model=ScheduledScanResponse)
def get_schedule(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.patch("/{schedule_id}", response_model=ScheduledScanResponse)
def update_schedule(schedule_id: str, body: ScheduledScanUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if body.is_active is not None:
        schedule.is_active = body.is_active
    if body.cron_expression is not None:
        schedule.cron_expression = body.cron_expression
        schedule.next_run_at = calc_first_run(body.cron_expression)
    if body.config is not None:
        schedule.config = body.config
    if body.max_runs is not None:
        schedule.max_runs = body.max_runs

    db.commit()
    db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(schedule)
    db.commit()
    return {"status": "deleted"}


@router.post("/{schedule_id}/toggle")
def toggle_schedule(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Toggle a schedule between active and paused."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.is_active = not schedule.is_active
    if schedule.is_active:
        schedule.next_run_at = calc_first_run(schedule.cron_expression)
    db.commit()
    db.refresh(schedule)
    return {"status": "active" if schedule.is_active else "paused", "is_active": schedule.is_active}


@router.post("/{schedule_id}/run")
def run_schedule_now(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Immediately trigger a scan from this schedule."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    scan = Scan(
        user_id=user.id,
        target=schedule.target,
        scan_type=schedule.scan_type,
        config=schedule.config,
        schedule_id=schedule.id,
    )
    db.add(scan)
    schedule.run_count = (schedule.run_count or 0) + 1
    schedule.last_run_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)

    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": scan.config or {},
    })

    return {"scan_id": scan.id, "status": "queued", "target": scan.target}
