"""
Asset inventory routes — technology detection results and CVE alerts.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import AssetInventory, CveAlert, User
from modules.api.schemas import AssetInventoryResponse, CveAlertResponse
from modules.api.auth import get_current_user

router = APIRouter()


@router.get("/", response_model=list[AssetInventoryResponse])
def list_inventory(
    target: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all detected technologies in the asset inventory.
    Optionally filter by target URL/host.
    """
    q = db.query(AssetInventory).filter(AssetInventory.user_id == user.id)
    if target:
        q = q.filter(AssetInventory.target == target)
    return q.order_by(AssetInventory.last_seen.desc()).all()


@router.get("/targets")
def list_inventory_targets(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all unique targets that have technology inventory data."""
    rows = (
        db.query(AssetInventory.target)
        .filter(AssetInventory.user_id == user.id)
        .distinct()
        .all()
    )
    return {"targets": [r[0] for r in rows]}


@router.get("/cve-alerts", response_model=list[CveAlertResponse])
def list_cve_alerts(
    target: str | None = None,
    severity: str | None = None,
    unnotified_only: bool = False,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List CVE alerts for the authenticated user's assets.

    Query params:
    - target: filter by asset target
    - severity: filter by CVSS severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)
    - unnotified_only: return only alerts not yet notified
    """
    q = db.query(CveAlert).filter(CveAlert.user_id == user.id)

    if severity:
        q = q.filter(CveAlert.cvss_severity == severity.upper())
    if unnotified_only:
        q = q.filter(CveAlert.notification_sent == False)
    if target:
        # Join through asset inventory to filter by target
        q = q.join(AssetInventory, CveAlert.asset_id == AssetInventory.id).filter(
            AssetInventory.target == target
        )

    return q.order_by(CveAlert.created_at.desc()).all()


@router.get("/cve-alerts/{alert_id}", response_model=CveAlertResponse)
def get_cve_alert(
    alert_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific CVE alert by ID."""
    alert = db.query(CveAlert).filter(
        CveAlert.id == alert_id,
        CveAlert.user_id == user.id,
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="CVE alert not found")
    return alert


@router.post("/cve-alerts/{alert_id}/trigger-rescan")
def trigger_cve_rescan(
    alert_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manually trigger a targeted re-scan to verify CVE exposure."""
    import uuid
    from modules.api.models import Scan
    from modules.infra import get_queue

    alert = db.query(CveAlert).filter(
        CveAlert.id == alert_id,
        CveAlert.user_id == user.id,
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="CVE alert not found")

    asset = db.query(AssetInventory).filter(AssetInventory.id == alert.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        user_id=user.id,
        target=asset.target,
        scan_type="security",
        config={
            "cve_triggered": True,
            "cve_id": alert.cve_id,
            "technology": alert.technology_name,
            "technology_version": alert.technology_version,
        },
    )
    db.add(scan)

    get_queue().send("scan-jobs", {
        "scan_id": scan_id,
        "target": asset.target,
        "scan_type": "security",
        "config": scan.config,
    })

    alert.auto_rescan_triggered = True
    alert.rescan_id = scan_id
    db.commit()

    return {"scan_id": scan_id, "status": "queued", "target": asset.target, "cve_id": alert.cve_id}
