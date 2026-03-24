import json
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Scan, User
from modules.api.schemas import ScanCreate, ScanResponse, VerificationCreate
from modules.api.auth import get_current_user
from modules.infra import get_queue, get_storage

import redis as _redis

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
_STUCK_TIMEOUT = int(os.environ.get("STUCK_SCAN_TIMEOUT_SECONDS", "600"))

router = APIRouter()


@router.post("/", response_model=ScanResponse)
def create_scan(body: ScanCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = Scan(user_id=user.id, target=body.target, scan_type=body.scan_type, config=body.config)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": scan.config or {},
    })
    return scan


@router.get("/", response_model=list[ScanResponse])
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).all()


@router.get("/health/stuck")
def list_stuck_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List scans that appear stuck (running but no recent heartbeat)."""
    running = db.query(Scan).filter(
        Scan.user_id == user.id, Scan.status == "running"
    ).all()

    r = _redis.from_url(_REDIS_URL)
    result = []
    for scan in running:
        last_beat = r.get(f"scan:heartbeat:{scan.id}")
        if last_beat:
            silent_seconds = int(time.time() - float(last_beat))
        else:
            silent_seconds = int((datetime.now(timezone.utc) - scan.created_at).total_seconds()) if scan.created_at else 0

        result.append({
            "id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "silent_seconds": silent_seconds,
            "is_stuck": silent_seconds > _STUCK_TIMEOUT,
            "has_checkpoint": r.exists(f"scan:checkpoint:{scan.id}") > 0,
        })
    return result


@router.post("/force-retry/{scan_id}")
def force_retry_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Force-retry a stuck or failed scan, using checkpoint if available."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("running", "failed"):
        raise HTTPException(status_code=400, detail="Scan must be running or failed to force-retry")

    from modules.infra.checkpoint import load_checkpoint, build_resume_context
    checkpoint = load_checkpoint(scan_id)
    config = scan.config or {}
    if checkpoint:
        config = {**config, "resume_context": build_resume_context(checkpoint)}

    scan.status = "queued"
    db.commit()

    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": config,
    })
    return {"id": scan.id, "status": "queued", "had_checkpoint": checkpoint is not None}


@router.post("/force-fail/{scan_id}")
def force_fail_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Force-fail a stuck scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan.status = "failed"
    db.commit()

    get_storage().put_json(f"scans/{scan_id}/error.json", {
        "error": "Scan force-failed by user.",
        "scan_id": scan_id,
    })

    r = _redis.from_url(_REDIS_URL)
    r.delete(f"scan:heartbeat:{scan_id}")

    from modules.infra.checkpoint import delete_checkpoint
    delete_checkpoint(scan_id)

    return {"id": scan.id, "status": "failed"}


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/report")
def get_report(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = get_storage().get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Report not ready")
    return report


@router.post("/{scan_id}/retry")
def retry_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retry a failed or completed scan.

    For failed scans: re-queues the entire scan.
    For completed scans with errors: creates a follow-up scan that focuses on
    failed steps, providing the previous report as context so the AI agent can
    diagnose what went wrong and try alternative approaches.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    storage = get_storage()
    queue = get_queue()

    # Get existing report and error info
    report = storage.get_json(f"scans/{scan_id}/report.json")
    error = storage.get_json(f"scans/{scan_id}/error.json")

    # Build retry context for the AI agent
    retry_context = {
        "retry_of": scan_id,
        "original_status": scan.status,
    }

    if error:
        retry_context["previous_error"] = error.get("error", "Unknown error")

    if report:
        # Extract what succeeded and what failed/was missed
        retry_context["previous_findings_count"] = len(report.get("findings", []))
        retry_context["previous_risk_score"] = report.get("risk_score", 0)
        retry_context["previous_summary"] = report.get("summary", "")[:2000]

        # Get activity log to find failed tool calls
        import redis as _redis
        import os
        try:
            r = _redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379"))
            activities = r.lrange(f"scan:activity:{scan_id}", 0, -1)
            failed_steps = []
            for act_raw in activities:
                act = json.loads(act_raw)
                if "ERROR" in str(act.get("result", "")):
                    failed_steps.append(act)
            if failed_steps:
                retry_context["failed_steps"] = failed_steps[:20]
        except Exception:
            pass

    # Create a new scan for the retry
    new_scan = Scan(
        user_id=user.id,
        target=scan.target,
        scan_type=scan.scan_type,
        config={
            **(scan.config or {}),
            "retry_context": retry_context,
        },
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Queue it
    queue.send("scan-jobs", {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "scan_type": new_scan.scan_type,
        "config": new_scan.config or {},
    })

    return {
        "id": new_scan.id,
        "retry_of": scan_id,
        "status": "queued",
        "target": new_scan.target,
    }


@router.post("/{scan_id}/verify", response_model=ScanResponse)
def verify_scan(scan_id: str, body: VerificationCreate | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Create a targeted verification re-scan from a completed scan.

    Pulls the original scan's target and findings, then queues a new
    'verification' scan that only tests those specific issues.
    """
    original = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")
    if original.status != "completed":
        raise HTTPException(status_code=400, detail="Only completed scans can be verified")

    storage = get_storage()
    report = storage.get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Original scan has no report")

    findings = report.get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="Original scan has no findings to verify")

    body = body or VerificationCreate()

    # Optionally filter to a subset of findings
    if body.finding_ids:
        findings = [f for f in findings if f.get("id") in body.finding_ids]
        if not findings:
            raise HTTPException(status_code=400, detail="None of the specified finding_ids matched")

    verification_config = {
        **(body.config or {}),
        "verification_of": scan_id,
        "original_findings": findings,
        "original_created_at": original.created_at.isoformat() if original.created_at else None,
    }

    scan = Scan(
        user_id=user.id,
        target=original.target,
        scan_type="verification",
        config=verification_config,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": scan.config or {},
    })
    return scan


@router.post("/{scan_id}/stop")
def stop_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Stop a running scan by setting a Redis signal that the agent checks each iteration."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("running", "queued"):
        raise HTTPException(status_code=400, detail="Scan is not running")

    try:
        r = _redis.from_url(_REDIS_URL)
        r.set(f"scan:stop:{scan_id}", "1", ex=3600)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not signal stop: {e}")

    return {"scan_id": scan_id, "status": "stopping"}
