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
from modules.infra.checkpoint import load_checkpoint, build_resume_context, delete_checkpoint
from modules.infra.elasticsearch import search as es_search

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


@router.post("/{scan_id}/verify")
def verify_scan(
    scan_id: str,
    body: VerificationCreate | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a targeted re-scan to verify whether original findings have been remediated.

    The verification scan tests ONLY the specific findings from the original scan,
    not a full re-scan. Each finding receives a status of verified_fixed,
    still_vulnerable, partially_fixed, or new_regression.
    """
    original_scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not original_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if original_scan.status != "completed":
        raise HTTPException(status_code=400, detail="Original scan must be completed before verification")

    storage = get_storage()
    report = storage.get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Original scan report not found")

    findings = report.get("findings", [])

    # Build compact finding summaries for the verification context
    finding_summaries = []
    for f in findings:
        summary = {
            "title": f.get("title", ""),
            "severity": f.get("severity", "info"),
            "description": f.get("description", "")[:500],
            "evidence": f.get("evidence", "")[:300],
            "affected_urls": f.get("affected_urls", []),
            "category": f.get("category", ""),
        }
        finding_summaries.append(summary)

    verification_context = {
        "verification_of": scan_id,
        "original_scan_created_at": original_scan.created_at.isoformat() if original_scan.created_at else None,
        "original_risk_score": report.get("risk_score", 0),
        "findings": finding_summaries,
        "findings_count": len(finding_summaries),
    }

    extra_config = (body.config or {}) if body else {}
    new_scan = Scan(
        user_id=user.id,
        target=original_scan.target,
        scan_type="verification",
        config={
            **extra_config,
            "verification_context": verification_context,
        },
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    get_queue().send("scan-jobs", {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "scan_type": new_scan.scan_type,
        "config": new_scan.config or {},
    })

    return {
        "id": new_scan.id,
        "verification_of": scan_id,
        "target": new_scan.target,
        "scan_type": new_scan.scan_type,
        "status": new_scan.status,
        "findings_count": new_scan.findings_count,
        "created_at": new_scan.created_at.isoformat() if new_scan.created_at else None,
        "completed_at": None,
        "risk_score": None,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "estimated_cost": 0.0,
    }


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


_SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
_FINDINGS_INDEX = "scanner-scan-findings"


def _fetch_findings(scan_id: str) -> list[dict]:
    """Fetch all findings for a scan from Elasticsearch."""
    result = es_search(
        _FINDINGS_INDEX,
        {"bool": {"filter": [{"term": {"scan_id": scan_id}}]}},
        size=10000,
    )
    return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]


def _compute_risk_score(findings: list[dict]) -> float:
    """Compute a simple risk score from findings based on severity weights."""
    if not findings:
        return 0.0
    total = sum(_SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    return round(total, 2)


@router.get("/{scan_id}/compare/{baseline_scan_id}")
def compare_scans(
    scan_id: str,
    baseline_scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compare findings between a current scan and a baseline scan."""
    current_scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not current_scan:
        raise HTTPException(status_code=404, detail="Current scan not found")

    baseline_scan = db.query(Scan).filter(Scan.id == baseline_scan_id, Scan.user_id == user.id).first()
    if not baseline_scan:
        raise HTTPException(status_code=404, detail="Baseline scan not found")

    current_findings = _fetch_findings(scan_id)
    baseline_findings = _fetch_findings(baseline_scan_id)

    # Index by dedup_key
    current_by_key = {}
    for f in current_findings:
        key = f.get("dedup_key")
        if key:
            current_by_key[key] = f

    baseline_by_key = {}
    for f in baseline_findings:
        key = f.get("dedup_key")
        if key:
            baseline_by_key[key] = f

    current_keys = set(current_by_key.keys())
    baseline_keys = set(baseline_by_key.keys())

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    common_keys = current_keys & baseline_keys

    new_findings = [current_by_key[k] for k in new_keys]
    resolved_findings = [baseline_by_key[k] for k in resolved_keys]
    unchanged_findings = []
    changed_findings = []

    for k in common_keys:
        curr = current_by_key[k]
        base = baseline_by_key[k]
        if curr.get("severity") != base.get("severity"):
            changed_findings.append({"current": curr, "baseline": base})
        else:
            unchanged_findings.append(curr)

    current_risk = _compute_risk_score(current_findings)
    baseline_risk = _compute_risk_score(baseline_findings)

    return {
        "current_scan_id": scan_id,
        "baseline_scan_id": baseline_scan_id,
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
            "changed_count": len(changed_findings),
            "current_risk_score": current_risk,
            "baseline_risk_score": baseline_risk,
            "risk_delta": round(current_risk - baseline_risk, 2),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
        "changed_findings": changed_findings,
    }
