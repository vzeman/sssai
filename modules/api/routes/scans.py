from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Scan, User
from modules.api.schemas import ScanCreate, ScanResponse
from modules.api.auth import get_current_user
from modules.infra import get_queue, get_storage

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
