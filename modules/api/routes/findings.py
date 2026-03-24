"""Findings management routes — status workflow and false-positive marking."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from modules.api.auth import get_current_user
from modules.api.models import User
from modules.infra.elasticsearch import get_client as get_es, search as es_search

log = logging.getLogger(__name__)

router = APIRouter()

_FINDINGS_INDEX = "scanner-scan-findings"

VALID_STATUSES = frozenset({
    "new",
    "confirmed",
    "in_progress",
    "resolved",
    "false_positive",
    "accepted_risk",
})


class FindingStatusUpdate(BaseModel):
    """Body for PATCH /api/findings/{finding_id}/status."""
    status: str = Field(..., description="New status for the finding")
    reason: str = Field("", description="Reason for the status change")


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    user: User = Depends(get_current_user),
):
    """Update the workflow status of a finding in Elasticsearch."""
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{body.status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}",
        )

    es = get_es()

    # Verify the finding exists and belongs to this user
    try:
        doc = es.get(index=_FINDINGS_INDEX, id=finding_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Finding not found")

    source = doc.get("_source", {})
    if source.get("user_id") and source["user_id"] != str(user.id):
        raise HTTPException(status_code=404, detail="Finding not found")

    now = datetime.now(timezone.utc).isoformat()
    previous_status = source.get("finding_status", "new")

    # Build the audit entry
    audit_entry = {
        "changed_by": str(user.id),
        "changed_at": now,
        "previous_status": previous_status,
        "new_status": body.status,
        "reason": body.reason,
    }

    # Append to existing audit trail
    existing_audit = source.get("status_audit_trail", [])
    if not isinstance(existing_audit, list):
        existing_audit = []
    existing_audit.append(audit_entry)

    update_body = {
        "finding_status": body.status,
        "status_audit_trail": existing_audit,
        "status_updated_at": now,
        "status_updated_by": str(user.id),
    }

    try:
        es.update(index=_FINDINGS_INDEX, id=finding_id, body={"doc": update_body})
    except Exception as e:
        log.warning("Failed to update finding %s: %s", finding_id, e)
        raise HTTPException(status_code=500, detail="Failed to update finding status")

    return {
        "finding_id": finding_id,
        "status": body.status,
        "previous_status": previous_status,
        "reason": body.reason,
        "updated_at": now,
        "updated_by": str(user.id),
    }


@router.get("")
def list_findings(
    exclude_false_positives: bool = False,
    exclude_accepted_risk: bool = False,
    status: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    size: int = 100,
    from_: int = 0,
    user: User = Depends(get_current_user),
):
    """List findings with optional filtering."""
    filters: list[dict] = [{"term": {"user_id": str(user.id)}}]

    must_not: list[dict] = []
    if exclude_false_positives:
        must_not.append({"term": {"finding_status": "false_positive"}})
    if exclude_accepted_risk:
        must_not.append({"term": {"finding_status": "accepted_risk"}})

    if status:
        filters.append({"term": {"finding_status": status}})
    if severity:
        filters.append({"term": {"severity": severity}})
    if scan_id:
        filters.append({"term": {"scan_id": scan_id}})

    query: dict = {"bool": {"filter": filters}}
    if must_not:
        query["bool"]["must_not"] = must_not

    result = es_search(
        _FINDINGS_INDEX,
        query,
        size=size,
        from_=from_,
        sort=[{"timestamp": {"order": "desc"}}],
    )

    hits = result.get("hits", {})
    findings = []
    for hit in hits.get("hits", []):
        finding = hit["_source"]
        finding["id"] = hit["_id"]
        findings.append(finding)

    total = hits.get("total", {})
    total_count = total.get("value", 0) if isinstance(total, dict) else total

    return {
        "findings": findings,
        "total": total_count,
        "size": size,
        "from": from_,
    }
