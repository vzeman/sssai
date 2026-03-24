"""API routes for scheduled/recurring scans."""

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import ScheduledScan, Scan, User
from modules.api.schemas import ScheduledScanCreate, ScheduledScanUpdate, ScheduledScanResponse
from modules.api.auth import get_current_user
from modules.infra import get_queue

router = APIRouter()


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
    elif expr.endswith("h"):
        return now + timedelta(hours=int(expr[:-1]))
    elif expr.endswith("m"):
        return now + timedelta(minutes=int(expr[:-1]))
    elif expr.endswith("d"):
        return now + timedelta(days=int(expr[:-1]))
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
        timezone=body.timezone,
        next_run_at=calc_first_run(body.cron_expression),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@router.get("/", response_model=list[ScheduledScanResponse])
def list_schedules(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ScheduledScan).filter(ScheduledScan.user_id == user.id).order_by(ScheduledScan.created_at.desc()).all()


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
    if body.timezone is not None:
        schedule.timezone = body.timezone

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


@router.post("/{schedule_id}/toggle", response_model=ScheduledScanResponse)
def toggle_schedule(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Toggle is_active on/off for a scheduled scan."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.is_active = not schedule.is_active
    db.commit()
    db.refresh(schedule)
    return schedule


@router.post("/{schedule_id}/run", response_model=dict)
def run_schedule_now(schedule_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Trigger the scheduled scan immediately as a manual test run."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        user_id=user.id,
        target=schedule.target,
        scan_type=schedule.scan_type,
        config=schedule.config,
        schedule_id=schedule.id,
    )
    db.add(scan)

    queue = get_queue()
    queue.send("scan-jobs", {
        "scan_id": scan_id,
        "target": schedule.target,
        "scan_type": schedule.scan_type,
        "config": schedule.config or {},
    })

    db.commit()
    return {"status": "triggered", "scan_id": scan_id}
