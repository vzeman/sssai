"""API routes for report generation and download."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Scan, User
from modules.api.auth import get_current_user, create_report_token, verify_report_token
from modules.infra import get_storage

router = APIRouter()


# ─── Executive Brief helpers ──────────────────────────────────────────


def _get_previous_scans(db: Session, user_id: str, current_scan_id: str, target: str) -> list[dict]:
    """Fetch up to 3 previous completed scans for the same target."""
    rows = (
        db.query(Scan)
        .filter(
            Scan.user_id == user_id,
            Scan.target == target,
            Scan.id != current_scan_id,
            Scan.status == "completed",
            Scan.risk_score.isnot(None),
        )
        .order_by(Scan.completed_at.desc())
        .limit(3)
        .all()
    )
    return [
        {
            "scan_id": r.id,
            "risk_score": r.risk_score,
            "date": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in rows
    ]


@router.get("/{scan_id}/json")
def get_report_json(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get scan report as JSON."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = get_storage().get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Report not ready")
    return report


@router.get("/{scan_id}/html/token")
def get_report_view_token(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a short-lived single-use token for viewing an HTML report in a browser tab."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    token = create_report_token(user.id, scan_id)
    return {"report_token": token, "url": f"/api/reports/{scan_id}/html?rt={token}"}


@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_report_html(scan_id: str, rt: str = Query("", description="Report access token"), db: Session = Depends(get_db)):
    """Get scan report as HTML. Requires a short-lived report token (rt) from /html/token endpoint."""
    if not rt:
        raise HTTPException(status_code=401, detail="Report token required. GET /api/reports/{scan_id}/html/token first.")

    user_id = verify_report_token(rt, scan_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired report token")

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    storage = get_storage()
    html = storage.get(f"scans/{scan_id}/report.html")
    if html:
        return HTMLResponse(content=html)

    report = storage.get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Report not ready")

    from modules.reports.generator import ReportGenerator
    generator = ReportGenerator()
    html = generator.generate_html(report, {
        "target": scan.target,
        "scan_type": scan.scan_type,
        "scan_id": scan_id,
    })
    return HTMLResponse(content=html)


@router.get("/{scan_id}/pdf")
def get_report_pdf(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get scan report as PDF."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = get_storage().get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Report not ready")

    from modules.reports.generator import ReportGenerator
    generator = ReportGenerator()
    pdf_bytes = generator.generate_pdf(report, {
        "target": scan.target,
        "scan_type": scan.scan_type,
        "scan_id": scan_id,
    })

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report-{scan_id[:8]}.pdf"},
    )


# ─── Executive Brief endpoints ────────────────────────────────────────


def _build_brief(scan: Scan, scan_id: str, db: Session, user_id: str) -> dict:
    """Load report JSON and generate executive brief data."""
    storage = get_storage()
    report = storage.get_json(f"scans/{scan_id}/report.json")
    if not report:
        raise HTTPException(status_code=404, detail="Report not ready")

    scan_info = {
        "target": scan.target,
        "scan_type": scan.scan_type,
        "scan_id": scan_id,
    }
    previous = _get_previous_scans(db, user_id, scan_id, scan.target)

    from modules.reports.executive_brief import ExecutiveBriefGenerator
    generator = ExecutiveBriefGenerator()
    return generator.generate_brief(report, scan_info, previous)


@router.get("/{scan_id}/executive-brief")
def get_executive_brief_json(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get AI-generated executive security brief as JSON."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    brief = _build_brief(scan, scan_id, db, user.id)
    # Exclude the SVG blob from the JSON response (available via HTML endpoint)
    brief.pop("risk_matrix_svg", None)
    return brief


@router.get("/{scan_id}/executive-brief/html/token")
def get_executive_brief_view_token(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a short-lived token for viewing the executive brief HTML in a browser tab."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    token = create_report_token(user.id, scan_id)
    return {
        "report_token": token,
        "url": f"/api/reports/{scan_id}/executive-brief/html?rt={token}",
    }


@router.get("/{scan_id}/executive-brief/html", response_class=HTMLResponse)
def get_executive_brief_html(
    scan_id: str,
    rt: str = Query("", description="Report access token"),
    db: Session = Depends(get_db),
):
    """Get AI-generated executive security brief as HTML. Requires a report token (rt)."""
    if not rt:
        raise HTTPException(
            status_code=401,
            detail="Report token required. GET /api/reports/{scan_id}/executive-brief/html/token first.",
        )

    user_id = verify_report_token(rt, scan_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired report token")

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    brief = _build_brief(scan, scan_id, db, user_id)

    from modules.reports.executive_brief import ExecutiveBriefGenerator
    generator = ExecutiveBriefGenerator()
    html = generator.generate_html(brief)
    return HTMLResponse(content=html)


@router.get("/{scan_id}/executive-brief/pdf")
def get_executive_brief_pdf(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get AI-generated executive security brief as PDF."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    brief = _build_brief(scan, scan_id, db, user.id)

    from modules.reports.executive_brief import ExecutiveBriefGenerator
    generator = ExecutiveBriefGenerator()
    try:
        pdf_bytes = generator.generate_pdf(brief)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="PDF generation unavailable")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=executive-brief-{scan_id[:8]}.pdf"
        },
    )
