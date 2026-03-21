from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Monitor, User
from modules.api.schemas import MonitorCreate, MonitorResponse
from modules.api.auth import get_current_user

router = APIRouter()


@router.post("/", response_model=MonitorResponse)
def create_monitor(body: MonitorCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = Monitor(user_id=user.id, target=body.target, check_type=body.check_type, interval_seconds=body.interval_seconds)
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor


@router.get("/", response_model=list[MonitorResponse])
def list_monitors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Monitor).filter(Monitor.user_id == user.id).all()


@router.delete("/{monitor_id}")
def delete_monitor(monitor_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id, Monitor.user_id == user.id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    db.delete(monitor)
    db.commit()
    return {"status": "deleted"}
