"""
REST API endpoints for audit logging and compliance reporting.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.auth import get_current_user
from modules.api.models import User
from modules.api.audit import (
    AuditLogger,
    AuditSearcher,
    ComplianceReporter,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/logs")
async def list_audit_logs(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None, pattern="^(success|failure)$"),
    ip_address: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List audit logs with optional filters.
    Only returns logs for the current user's account.
    """
    try:
        # Parse dates
        start = None
        end = None
        if start_date:
            try:
                start = datetime.fromisoformat(start_date)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format")
        if end_date:
            try:
                end = datetime.fromisoformat(end_date)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format")

        # Query logs
        logs, total = AuditSearcher.query_audit_logs(
            db=db,
            user_id=current_user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            status=status,
            start_date=start,
            end_date=end,
            limit=limit,
            offset=offset,
        )

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "logs": [
                {
                    "id": log.id,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "ip_address": log.ip_address,
                    "status": log.status,
                    "error_message": log.error_message,
                    "created_at": log.created_at.isoformat(),
                    "before_state": log.before_state,
                    "after_state": log.after_state,
                }
                for log in logs
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit logs")


@router.get("/logs/{log_id}")
async def get_audit_log(
    log_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get a specific audit log entry.
    """
    try:
        from modules.api.models import AuditLog

        log = db.query(AuditLog).filter(
            AuditLog.id == log_id,
            AuditLog.user_id == current_user.id,
        ).first()

        if not log:
            raise HTTPException(status_code=404, detail="Audit log not found")

        return {
            "id": log.id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "status": log.status,
            "error_message": log.error_message,
            "created_at": log.created_at.isoformat(),
            "before_state": log.before_state,
            "after_state": log.after_state,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching audit log: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit log")


@router.get("/activity")
async def get_user_activity(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get activity summary for the current user.
    """
    try:
        activity = AuditSearcher.get_user_activity(
            db=db,
            user_id=current_user.id,
            days=days,
        )

        return {
            "user_id": current_user.id,
            "days": days,
            "activity": activity,
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error getting user activity: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch activity")


@router.get("/anomalies")
async def get_anomalies(
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Detect and list suspicious activity patterns.
    """
    try:
        anomalies = AuditSearcher.get_anomalies(
            db=db,
            user_id=current_user.id,
            hours=hours,
        )

        return {
            "user_id": current_user.id,
            "hours": hours,
            "anomalies": anomalies,
            "detected_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        raise HTTPException(status_code=500, detail="Failed to detect anomalies")


@router.get("/reports/audit-summary")
async def get_audit_summary(
    start_date: str = Query(...),
    end_date: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate audit summary report for a date range.
    """
    try:
        # Parse dates
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format (use ISO format)")

        if start >= end:
            raise HTTPException(status_code=400, detail="start_date must be before end_date")

        report = ComplianceReporter.generate_audit_summary(db, start, end)

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating audit summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/reports/soc2")
async def get_soc2_report(
    start_date: str = Query(...),
    end_date: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate SOC 2 Type II compliance report.
    """
    try:
        # Parse dates
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format (use ISO format)")

        if start >= end:
            raise HTTPException(status_code=400, detail="start_date must be before end_date")

        report = ComplianceReporter.generate_soc2_report(db, start, end)

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating SOC 2 report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/reports/iso27001")
async def get_iso27001_report(
    start_date: str = Query(...),
    end_date: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate ISO 27001:2022 compliance report.
    """
    try:
        # Parse dates
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format (use ISO format)")

        if start >= end:
            raise HTTPException(status_code=400, detail="start_date must be before end_date")

        report = ComplianceReporter.generate_iso27001_report(db, start, end)

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating ISO 27001 report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


class ManualAuditEntry(BaseModel):
    action: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_\-]+$")
    resource_type: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_\-]+$")
    resource_id: str = Field(..., min_length=1, max_length=255)
    notes: str | None = Field(None, max_length=5000)


@router.post("/manual-entry")
async def create_manual_audit_entry(
    entry: ManualAuditEntry,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Manually create an audit log entry (for compliance reviews).
    """
    try:
        log_id = await AuditLogger.log_action(
            user_id=current_user.id,
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            after_state={"notes": entry.notes} if entry.notes else None,
            db=db,
        )

        if not log_id:
            raise HTTPException(status_code=500, detail="Failed to create audit entry")

        return {
            "id": log_id,
            "status": "created",
            "created_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error creating manual audit entry: {e}")
        raise HTTPException(status_code=500, detail="Failed to create audit entry")


@router.get("/export")
async def export_audit_logs(
    format: str = Query("json", pattern="^(json|csv)$"),
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Export audit logs in JSON or CSV format.
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=days)

        logs, _ = AuditSearcher.query_audit_logs(
            db=db,
            user_id=current_user.id,
            start_date=cutoff,
            limit=10000,
        )

        if format == "json":
            return {
                "export_date": datetime.utcnow().isoformat(),
                "user_id": current_user.id,
                "record_count": len(logs),
                "logs": [
                    {
                        "id": log.id,
                        "action": log.action,
                        "resource_type": log.resource_type,
                        "resource_id": log.resource_id,
                        "ip_address": log.ip_address,
                        "status": log.status,
                        "created_at": log.created_at.isoformat(),
                    }
                    for log in logs
                ],
            }

        # CSV export would be handled separately
        raise HTTPException(status_code=501, detail="CSV export not yet implemented")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to export logs")
