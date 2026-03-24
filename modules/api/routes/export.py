"""Export endpoints for findings and scans data (CSV / JSON)."""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from modules.api.auth import get_current_user
from modules.api.database import get_db
from modules.api.models import Scan, User
from modules.infra.elasticsearch import search as es_search

router = APIRouter()

_FINDINGS_INDEX = "scanner-scan-findings"

_FINDING_CSV_COLUMNS = [
    "title",
    "severity",
    "category",
    "description",
    "affected_url",
    "cvss_score",
    "cve_id",
    "tool",
    "remediation",
    "confidence",
    "finding_status",
]

_SCAN_CSV_COLUMNS = [
    "scan_id",
    "target",
    "scan_type",
    "status",
    "risk_score",
    "findings_count",
    "created_at",
]


def _findings_to_rows(hits: list[dict]) -> list[dict]:
    rows = []
    for hit in hits:
        src = hit.get("_source", {})
        rows.append({col: src.get(col, "") for col in _FINDING_CSV_COLUMNS})
    return rows


def _build_csv(columns: list[str], rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


@router.get("/findings")
def export_findings(
    scan_id: str = Query(..., description="Scan ID to export findings for"),
    format: str = Query("csv", description="Export format: csv or json"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export findings for a scan as CSV or JSON."""
    # Verify the scan belongs to the user
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = es_search(
        _FINDINGS_INDEX,
        {"bool": {"filter": [{"term": {"scan_id": scan_id}}]}},
        size=10000,
    )
    hits = result.get("hits", {}).get("hits", [])

    if format == "json":
        findings = [hit["_source"] for hit in hits]
        return {"scan_id": scan_id, "count": len(findings), "findings": findings}

    # Default: CSV
    rows = _findings_to_rows(hits)
    csv_content = _build_csv(_FINDING_CSV_COLUMNS, rows)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"findings_{scan_id[:8]}_{timestamp}.csv"

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans")
def export_scans(
    format: str = Query("csv", description="Export format: csv or json"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export all scans for the current user as CSV or JSON."""
    scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).all()

    rows = []
    for s in scans:
        rows.append({
            "scan_id": s.id,
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "risk_score": s.risk_score if hasattr(s, "risk_score") else "",
            "findings_count": s.findings_count if hasattr(s, "findings_count") else "",
            "created_at": s.created_at.isoformat() if s.created_at else "",
        })

    if format == "json":
        return {"count": len(rows), "scans": rows}

    csv_content = _build_csv(_SCAN_CSV_COLUMNS, rows)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"scans_export_{timestamp}.csv"

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
