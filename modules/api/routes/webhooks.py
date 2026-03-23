"""Webhook-triggered scanning routes — CI/CD integration.

Authentication: X-API-Key header with a webhook API key (whk_...).
"""
import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from modules.api.auth import get_current_user, get_webhook_user, generate_api_key
from modules.api.database import get_db
from modules.api.models import Scan, User, WebhookConfig
from modules.infra import get_queue, get_storage

log = logging.getLogger(__name__)

router = APIRouter()


# ─── Pydantic schemas ──────────────────────────────────────────────────

class QualityGates(BaseModel):
    max_critical: int | None = None
    max_high: int | None = None
    max_risk_score: float | None = None
    required_compliance: list[str] = []


class WebhookScanRequest(BaseModel):
    target: str
    commit_sha: str = ""
    branch: str = ""
    environment: str = ""
    deployer: str = ""
    scan_type: str = "security"
    gates: QualityGates | None = None


class WebhookConfigCreate(BaseModel):
    name: str
    scan_type: str = "security"
    gates: QualityGates | None = None


class WebhookConfigResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scan_type: str
    gates: dict | None = None
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


class WebhookScanResponse(BaseModel):
    scan_id: str
    status: str
    gate_passed: bool | None = None
    gate_details: dict | None = None
    result_url: str = ""


# ─── Webhook config management (JWT auth) ─────────────────────────────

@router.post("/", response_model=dict)
def create_webhook_config(
    body: WebhookConfigCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new webhook API key. The plain key is returned ONCE — store it securely."""
    plain_key, key_prefix, key_hash = generate_api_key()

    wh = WebhookConfig(
        user_id=user.id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        scan_type=body.scan_type,
        gates=body.gates.model_dump() if body.gates else None,
    )
    db.add(wh)
    db.commit()
    db.refresh(wh)

    return {
        "id": wh.id,
        "name": wh.name,
        "api_key": plain_key,  # shown once — user must store this
        "key_prefix": key_prefix,
        "scan_type": wh.scan_type,
        "gates": wh.gates,
        "message": "Store this API key securely — it will not be shown again.",
    }


@router.get("/", response_model=list[WebhookConfigResponse])
def list_webhook_configs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all webhook configs for the current user."""
    return db.query(WebhookConfig).filter(WebhookConfig.user_id == user.id).all()


@router.delete("/{webhook_id}")
def delete_webhook_config(
    webhook_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke a webhook API key."""
    wh = db.query(WebhookConfig).filter(
        WebhookConfig.id == webhook_id,
        WebhookConfig.user_id == user.id,
    ).first()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook config not found")
    db.delete(wh)
    db.commit()
    return {"status": "deleted"}


@router.patch("/{webhook_id}")
def update_webhook_config(
    webhook_id: str,
    body: dict,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a webhook config (name, gates, scan_type, is_active)."""
    wh = db.query(WebhookConfig).filter(
        WebhookConfig.id == webhook_id,
        WebhookConfig.user_id == user.id,
    ).first()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook config not found")

    if "name" in body:
        wh.name = body["name"]
    if "scan_type" in body:
        wh.scan_type = body["scan_type"]
    if "gates" in body:
        wh.gates = body["gates"]
    if "is_active" in body:
        wh.is_active = body["is_active"]

    db.commit()
    db.refresh(wh)
    return {"id": wh.id, "name": wh.name, "is_active": wh.is_active}


# ─── Webhook scan trigger (API key auth) ──────────────────────────────

@router.post("/scan", response_model=WebhookScanResponse)
def trigger_webhook_scan(
    body: WebhookScanRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Trigger a security scan from CI/CD. Authenticated via X-API-Key header.

    Returns immediately with a scan_id. Poll GET /api/webhooks/scan/{scan_id}/result
    for gate evaluation once the scan completes.
    """
    user, wh = get_webhook_user(request, db)

    # Merge request gates with webhook config gates (request takes precedence)
    gates = dict(wh.gates or {})
    if body.gates:
        req_gates = body.gates.model_dump(exclude_none=True)
        gates.update(req_gates)

    scan_type = body.scan_type or wh.scan_type

    scan = Scan(
        user_id=user.id,
        target=body.target,
        scan_type=scan_type,
        config={
            "webhook_triggered": True,
            "webhook_id": wh.id,
            "commit_sha": body.commit_sha,
            "branch": body.branch,
            "environment": body.environment,
            "deployer": body.deployer,
            "gates": gates,
        },
    )
    db.add(scan)

    # Update last_used_at
    wh.last_used_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": scan.config or {},
    })

    log.info(
        "Webhook scan triggered: scan_id=%s target=%s commit=%s deployer=%s",
        scan.id, body.target, body.commit_sha, body.deployer,
    )

    return WebhookScanResponse(
        scan_id=scan.id,
        status="queued",
        gate_passed=None,
        result_url=f"/api/webhooks/scan/{scan.id}/result",
    )


@router.get("/scan/{scan_id}/result")
def get_webhook_scan_result(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Poll for scan result and gate evaluation.

    Returns gate_passed: true/false once the scan completes.
    Returns gate_passed: null while still running.
    """
    user, wh = get_webhook_user(request, db)

    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in ("queued", "running"):
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "gate_passed": None,
            "message": "Scan still in progress. Poll again shortly.",
        }

    if scan.status == "failed":
        return {
            "scan_id": scan_id,
            "status": "failed",
            "gate_passed": False,
            "gate_details": {"reason": "Scan failed to complete"},
        }

    # Scan completed — evaluate gates
    config = scan.config or {}
    gates = config.get("gates") or {}

    report = None
    try:
        report = get_storage().get_json(f"scans/{scan_id}/report.json")
    except Exception:
        pass

    gate_result = _evaluate_gates(scan, report, gates)

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "findings_count": scan.findings_count,
        "gate_passed": gate_result["passed"],
        "gate_details": gate_result,
        "commit_sha": config.get("commit_sha", ""),
        "branch": config.get("branch", ""),
        "environment": config.get("environment", ""),
    }


def _evaluate_gates(scan: Scan, report: dict | None, gates: dict) -> dict:
    """Evaluate quality gates against scan results. Returns gate evaluation dict."""
    if not gates:
        return {"passed": True, "reason": "No gates configured", "checks": []}

    findings = []
    if report:
        findings = report.get("findings") or []

    checks = []
    passed = True

    # Count severities
    critical_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    high_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "high")

    max_critical = gates.get("max_critical")
    if max_critical is not None:
        ok = critical_count <= max_critical
        if not ok:
            passed = False
        checks.append({
            "gate": "max_critical",
            "threshold": max_critical,
            "actual": critical_count,
            "passed": ok,
        })

    max_high = gates.get("max_high")
    if max_high is not None:
        ok = high_count <= max_high
        if not ok:
            passed = False
        checks.append({
            "gate": "max_high",
            "threshold": max_high,
            "actual": high_count,
            "passed": ok,
        })

    max_risk_score = gates.get("max_risk_score")
    if max_risk_score is not None:
        actual_risk = scan.risk_score or 0.0
        ok = actual_risk <= max_risk_score
        if not ok:
            passed = False
        checks.append({
            "gate": "max_risk_score",
            "threshold": max_risk_score,
            "actual": actual_risk,
            "passed": ok,
        })

    required_compliance = gates.get("required_compliance") or []
    if required_compliance and report:
        compliance_results = report.get("compliance") or {}
        for req in required_compliance:
            result = compliance_results.get(req)
            ok = result is not None and result.get("passed", False)
            if not ok:
                passed = False
            checks.append({
                "gate": f"required_compliance:{req}",
                "required": req,
                "passed": ok,
                "result": result,
            })

    return {
        "passed": passed,
        "checks": checks,
        "summary": f"{sum(1 for c in checks if c['passed'])}/{len(checks)} checks passed",
        "critical_count": critical_count,
        "high_count": high_count,
        "risk_score": scan.risk_score,
    }
