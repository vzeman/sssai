"""API routes for report generation and download."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from jose import JWTError, jwt as jose_jwt
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Scan, User
from modules.api.auth import get_current_user, SECRET_KEY, ALGORITHM
from modules.infra import get_storage

router = APIRouter()


def _resolve_user(request: Request, token: Optional[str], db: Session) -> User:
    """Resolve user from Bearer header or ?token= query param."""
    # Try Authorization header first
    auth = request.headers.get("authorization", "")
    raw_token = None
    if auth.lower().startswith("bearer "):
        raw_token = auth[7:]
    elif token:
        raw_token = token
    if not raw_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jose_jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


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


@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_report_html(request: Request, scan_id: str, token: Optional[str] = Query(None), db: Session = Depends(get_db)):
    """Get scan report as HTML. Supports ?token= query param for direct browser access."""
    user = _resolve_user(request, token, db)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Try pre-generated HTML first
    storage = get_storage()
    html = storage.get(f"scans/{scan_id}/report.html")
    if html:
        return HTMLResponse(content=html)

    # Generate on-the-fly
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
