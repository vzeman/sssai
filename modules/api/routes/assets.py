"""Asset inventory endpoints — list, diff, and topology."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from modules.api.auth import get_current_user
from modules.api.database import get_db
from modules.api.models import Asset, Scan, User
from modules.api.schemas import AssetResponse

router = APIRouter()

VALID_ASSET_TYPES = {
    "domain", "subdomain", "ip", "api_endpoint", "service", "certificate", "dns_record"
}


@router.get("/", response_model=list[AssetResponse])
def list_assets(
    target: str | None = Query(None, description="Filter by target"),
    asset_type: str | None = Query(None, description="Filter by asset type"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all discovered assets with optional filters."""
    q = db.query(Asset).filter(Asset.user_id == user.id)
    if target:
        q = q.filter(Asset.target == target)
    if asset_type:
        if asset_type not in VALID_ASSET_TYPES:
            raise HTTPException(status_code=400, detail=f"Invalid asset_type. Valid: {sorted(VALID_ASSET_TYPES)}")
        q = q.filter(Asset.asset_type == asset_type)
    if is_active is not None:
        q = q.filter(Asset.is_active == is_active)
    return q.order_by(Asset.last_seen.desc()).all()


@router.get("/{target:path}/diff")
def asset_diff(
    target: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return asset changes (new / removed) since the previous scan of this target."""
    # Find the two most recent completed scans for this target
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == user.id, Scan.target == target, Scan.status == "completed")
        .order_by(Scan.completed_at.desc())
        .limit(2)
        .all()
    )

    if not scans:
        raise HTTPException(status_code=404, detail="No completed scans found for target")

    latest_scan = scans[0]
    previous_scan = scans[1] if len(scans) > 1 else None

    # Current assets (seen in latest scan)
    current_assets = (
        db.query(Asset)
        .filter(Asset.user_id == user.id, Asset.target == target, Asset.scan_id == latest_scan.id)
        .all()
    )

    new_assets = []
    updated_assets = []

    if previous_scan:
        prev_assets = (
            db.query(Asset)
            .filter(Asset.user_id == user.id, Asset.target == target, Asset.scan_id == previous_scan.id)
            .all()
        )
        prev_keys = {_asset_key(a) for a in prev_assets}
        curr_keys = {_asset_key(a) for a in current_assets}

        new_assets = [a for a in current_assets if _asset_key(a) not in prev_keys]
        removed_asset_keys = prev_keys - curr_keys
        removed_assets = [a for a in prev_assets if _asset_key(a) in removed_asset_keys]
        updated_assets = [
            a for a in current_assets
            if _asset_key(a) in prev_keys
            and any(
                getattr(a, f) != getattr(p, f)
                for p in prev_assets if _asset_key(p) == _asset_key(a)
                for f in ("service", "technology", "port")
            )
        ]
    else:
        new_assets = current_assets
        removed_assets = []

    return {
        "target": target,
        "latest_scan_id": latest_scan.id,
        "previous_scan_id": previous_scan.id if previous_scan else None,
        "new_count": len(new_assets),
        "removed_count": len(removed_assets) if previous_scan else 0,
        "updated_count": len(updated_assets),
        "new_assets": [_asset_dict(a) for a in new_assets],
        "removed_assets": [_asset_dict(a) for a in removed_assets] if previous_scan else [],
        "updated_assets": [_asset_dict(a) for a in updated_assets],
        "summary": _build_diff_summary(new_assets, removed_assets if previous_scan else [], updated_assets),
    }


@router.get("/{target:path}/topology")
def asset_topology(
    target: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return network topology map data for a target."""
    assets = (
        db.query(Asset)
        .filter(Asset.user_id == user.id, Asset.target == target, Asset.is_active == True)
        .all()
    )

    if not assets:
        raise HTTPException(status_code=404, detail="No assets found for target")

    # Build nodes and edges for topology graph
    nodes = []
    edges = []
    seen_ips: dict[str, str] = {}  # ip -> node_id

    # Root node (the target itself)
    root_id = f"target:{target}"
    nodes.append({
        "id": root_id,
        "label": target,
        "type": "target",
        "group": "root",
    })

    for asset in assets:
        node_id = asset.id
        label = asset.hostname or asset.ip or asset.service or asset.id[:8]
        nodes.append({
            "id": node_id,
            "label": label,
            "type": asset.asset_type,
            "hostname": asset.hostname,
            "ip": asset.ip,
            "port": asset.port,
            "service": asset.service,
            "technology": asset.technology,
            "is_active": asset.is_active,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        })

        # Link subdomains/domains to root
        if asset.asset_type in ("domain", "subdomain"):
            edges.append({"from": root_id, "to": node_id, "label": asset.asset_type})

        # Link IPs to their hostname nodes if both exist
        if asset.asset_type == "ip" and asset.ip:
            seen_ips[asset.ip] = node_id
        elif asset.asset_type in ("service", "api_endpoint") and asset.ip and asset.ip in seen_ips:
            edges.append({"from": seen_ips[asset.ip], "to": node_id, "label": asset.asset_type})
        elif asset.asset_type not in ("domain", "subdomain"):
            edges.append({"from": root_id, "to": node_id, "label": asset.asset_type})

    # Group assets by type for summary
    by_type: dict[str, int] = {}
    for a in assets:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1

    return {
        "target": target,
        "total_assets": len(assets),
        "by_type": by_type,
        "nodes": nodes,
        "edges": edges,
    }


def _asset_key(asset: Asset) -> str:
    """Unique key for deduplication/comparison."""
    return f"{asset.asset_type}:{asset.hostname or ''}:{asset.ip or ''}:{asset.port or ''}"


def _asset_dict(asset: Asset) -> dict:
    return {
        "id": asset.id,
        "target": asset.target,
        "asset_type": asset.asset_type,
        "hostname": asset.hostname,
        "ip": asset.ip,
        "port": asset.port,
        "service": asset.service,
        "technology": asset.technology,
        "extra": asset.extra,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "is_active": asset.is_active,
        "scan_id": asset.scan_id,
    }


def _build_diff_summary(new: list, removed: list, updated: list) -> str:
    parts = []
    if new:
        parts.append(f"{len(new)} new asset{'s' if len(new) != 1 else ''} discovered")
    if removed:
        parts.append(f"{len(removed)} asset{'s' if len(removed) != 1 else ''} no longer seen")
    if updated:
        parts.append(f"{len(updated)} asset{'s' if len(updated) != 1 else ''} changed")

    # Shadow IT detection
    shadow = [a for a in new if a.asset_type == "service" and a.port and a.port not in (80, 443, 22, 21, 25, 587)]
    if shadow:
        parts.append(f"⚠ {len(shadow)} unknown service{'s' if len(shadow) != 1 else ''} detected (possible shadow IT)")

    return "; ".join(parts) if parts else "No changes since last scan"
