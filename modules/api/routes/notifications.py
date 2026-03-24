"""API routes for notification channel management."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import NotificationChannel, User
from modules.api.schemas import NotificationChannelCreate, NotificationChannelUpdate, NotificationChannelResponse
from modules.api.auth import get_current_user

router = APIRouter()


def _paginated_response(items: list, total: int, skip: int, limit: int) -> dict:
    """Build a paginated response dict."""
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_next": skip + limit < total,
        "has_prev": skip > 0,
    }


@router.post("/", response_model=NotificationChannelResponse)
def create_channel(body: NotificationChannelCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    valid_types = {"email", "slack", "discord", "webhook", "openclaw", "jira", "linear", "github_issues"}
    if body.channel_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid channel type. Must be one of: {', '.join(sorted(valid_types))}")

    channel = NotificationChannel(
        user_id=user.id,
        name=body.name,
        channel_type=body.channel_type,
        config=body.config,
        min_severity=body.min_severity,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


@router.get("/")
def list_channels(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(NotificationChannel).filter(NotificationChannel.user_id == user.id)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return _paginated_response(items, total, skip, limit)


@router.get("/{channel_id}", response_model=NotificationChannelResponse)
def get_channel(channel_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id, NotificationChannel.user_id == user.id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel


@router.patch("/{channel_id}", response_model=NotificationChannelResponse)
def update_channel(channel_id: str, body: NotificationChannelUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id, NotificationChannel.user_id == user.id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    if body.name is not None:
        channel.name = body.name
    if body.config is not None:
        channel.config = body.config
    if body.min_severity is not None:
        channel.min_severity = body.min_severity
    if body.is_active is not None:
        channel.is_active = body.is_active

    db.commit()
    db.refresh(channel)
    return channel


@router.delete("/{channel_id}")
def delete_channel(channel_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id, NotificationChannel.user_id == user.id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    db.delete(channel)
    db.commit()
    return {"status": "deleted"}
