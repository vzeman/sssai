"""Campaign scanning routes — multi-target scanning with cross-target analysis."""
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import Campaign, Scan, User
from modules.api.schemas import CampaignCreate, CampaignResponse
from modules.api.auth import get_current_user
from modules.infra import get_queue, get_storage
from modules.config import AI_MODEL

log = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", response_model=CampaignResponse)
def create_campaign(body: CampaignCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not body.targets:
        raise HTTPException(status_code=400, detail="At least one target is required")

    campaign = Campaign(
        user_id=user.id,
        name=body.name,
        scan_type=body.scan_type,
        targets=body.targets,
        config=body.config,
        status="running",
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    # Create all scan rows first, then enqueue — prevents dangling scans if queue fails
    scans = []
    for target in body.targets:
        scan = Scan(
            user_id=user.id,
            target=target,
            scan_type=body.scan_type,
            config=body.config,
            campaign_id=campaign.id,
        )
        db.add(scan)
        scans.append(scan)

    try:
        db.commit()
        for scan in scans:
            db.refresh(scan)
    except Exception:
        campaign.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to create scan records")

    queue = get_queue()
    try:
        for scan in scans:
            queue.send("scan-jobs", {
                "scan_id": scan.id,
                "target": scan.target,
                "scan_type": scan.scan_type,
                "config": scan.config or {},
            })
    except Exception as e:
        log.error("Failed to enqueue campaign scans for campaign %s: %s", campaign.id, e)
        campaign.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to enqueue scan jobs")

    db.refresh(campaign)
    return campaign


@router.get("/", response_model=list[CampaignResponse])
def list_campaigns(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Campaign).filter(Campaign.user_id == user.id).order_by(Campaign.created_at.desc()).all()


@router.get("/{campaign_id}", response_model=CampaignResponse)
def get_campaign(campaign_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id, Campaign.user_id == user.id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Refresh campaign status based on scan statuses
    scans = db.query(Scan).filter(Scan.campaign_id == campaign_id).all()
    _refresh_campaign_status(campaign, scans, db)

    return campaign


@router.get("/{campaign_id}/report")
def get_campaign_report(campaign_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id, Campaign.user_id == user.id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    scans = db.query(Scan).filter(Scan.campaign_id == campaign_id).all()
    _refresh_campaign_status(campaign, scans, db)

    # Return cached report if available
    storage = get_storage()
    cached = storage.get_json(f"campaigns/{campaign_id}/report.json")
    if cached:
        return cached

    completed = [s for s in scans if s.status == "completed"]
    if not completed:
        raise HTTPException(status_code=404, detail="No completed scans yet — report not ready")

    # Generate cross-target analysis report
    report = _generate_campaign_report(campaign, scans, completed, storage)
    storage.put_json(f"campaigns/{campaign_id}/report.json", report)

    # Update aggregate risk score
    scores = [s.risk_score for s in completed if s.risk_score is not None]
    if scores:
        campaign.aggregate_risk_score = round(sum(scores) / len(scores), 2)
        db.commit()

    return report


def _refresh_campaign_status(campaign: Campaign, scans: list[Scan], db: Session):
    """Update campaign status based on constituent scan statuses."""
    if not scans:
        return
    if all(s.status in ("completed", "failed") for s in scans):
        new_status = "completed" if any(s.status == "completed" for s in scans) else "failed"
        if campaign.status != new_status:
            campaign.status = new_status
            if new_status == "completed":
                campaign.completed_at = datetime.now(timezone.utc)
            scores = [s.risk_score for s in scans if s.status == "completed" and s.risk_score is not None]
            if scores:
                campaign.aggregate_risk_score = round(sum(scores) / len(scores), 2)
            db.commit()


def _generate_campaign_report(campaign: Campaign, scans: list[Scan], completed: list[Scan], storage) -> dict:
    """Build cross-target analysis report using AI or heuristics."""
    scan_reports = {}
    for scan in completed:
        try:
            report = storage.get_json(f"scans/{scan.id}/report.json")
            if report:
                scan_reports[scan.id] = {"target": scan.target, "report": report}
        except Exception:
            pass

    # Build base report structure
    all_findings = []
    for scan_id, data in scan_reports.items():
        for finding in data["report"].get("findings", []):
            all_findings.append({**finding, "_target": data["target"], "_scan_id": scan_id})

    scores = [s.risk_score for s in completed if s.risk_score is not None]
    aggregate_score = round(sum(scores) / len(scores), 2) if scores else None

    base_report = {
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "scan_type": campaign.scan_type,
        "targets": campaign.targets,
        "aggregate_risk_score": aggregate_score,
        "total_findings": len(all_findings),
        "scan_summaries": [
            {
                "scan_id": s.id,
                "target": s.target,
                "status": s.status,
                "risk_score": s.risk_score,
                "findings_count": s.findings_count,
            }
            for s in scans
        ],
        "cross_target_analysis": None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if not scan_reports:
        return base_report

    # Run AI cross-target analysis if reports are available
    try:
        analysis = _run_ai_cross_target_analysis(campaign, scan_reports)
        base_report["cross_target_analysis"] = analysis
    except Exception as e:
        log.warning("AI cross-target analysis failed: %s", e)
        base_report["cross_target_analysis"] = _heuristic_cross_target_analysis(scan_reports, all_findings)

    return base_report


def _heuristic_cross_target_analysis(scan_reports: dict, all_findings: list) -> dict:
    """Basic heuristic cross-target analysis when AI is unavailable."""
    # Group findings by title to find shared vulnerabilities
    title_to_targets: dict[str, list[str]] = {}
    for finding in all_findings:
        title = finding.get("title", "Unknown")
        target = finding.get("_target", "")
        title_to_targets.setdefault(title, []).append(target)

    shared = [
        {"title": title, "affected_targets": list(set(targets)), "count": len(targets)}
        for title, targets in title_to_targets.items()
        if len(set(targets)) > 1
    ]
    shared.sort(key=lambda x: x["count"], reverse=True)

    return {
        "shared_vulnerabilities": shared[:20],
        "inconsistencies": [],
        "lateral_movement_paths": [],
        "summary": (
            f"Analysis of {len(scan_reports)} targets found {len(shared)} shared vulnerability pattern(s)."
        ),
    }


def _run_ai_cross_target_analysis(campaign: Campaign, scan_reports: dict) -> dict:
    """Use Claude AI to perform deep cross-target analysis."""
    import anthropic

    # Build condensed context for AI
    context_parts = []
    for scan_id, data in scan_reports.items():
        report = data["report"]
        brief = {
            "target": data["target"],
            "risk_score": report.get("risk_score"),
            "summary": (report.get("summary") or "")[:800],
            "findings": [
                {"severity": f.get("severity"), "title": f.get("title"), "description": (f.get("description") or "")[:200]}
                for f in (report.get("findings") or [])[:15]
            ],
        }
        context_parts.append(json.dumps(brief, indent=1))

    context = "\n\n---\n\n".join(context_parts)
    if len(context) > 60000:
        context = context[:60000] + "\n... [truncated]"

    # Sanitize user-controlled fields before interpolation to limit prompt injection surface
    safe_name = (campaign.name or "Unnamed Campaign")[:200].replace("\n", " ").replace("\r", " ")
    safe_targets = ", ".join(t[:253].replace("\n", " ").replace("\r", " ") for t in campaign.targets[:50])

    prompt = f"""You are a security analyst performing cross-target analysis for a multi-target security campaign.

Campaign name: {safe_name}
Scan type: {campaign.scan_type}
Targets: {safe_targets}

Individual scan reports:
{context}

Perform a thorough cross-target analysis and return a JSON object with these exact keys:
- "shared_vulnerabilities": list of vulnerabilities found across multiple targets, each with "title", "affected_targets", "severity", "description"
- "inconsistencies": list of security inconsistencies between targets (e.g., staging has a fix that production doesn't), each with "title", "description", "targets_with_issue", "targets_without_issue"
- "lateral_movement_paths": list of potential lateral movement paths between targets, each with "title", "description", "path", "risk"
- "aggregate_risk_score": float 0-10 representing overall campaign risk
- "summary": 2-3 sentence executive summary of the campaign findings

Return ONLY valid JSON, no markdown or other text."""

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=AI_MODEL,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}],
    )

    reply = ""
    for block in response.content:
        if hasattr(block, "text"):
            reply += block.text

    # Parse JSON from response
    reply = reply.strip()
    if reply.startswith("```"):
        lines = reply.split("\n")
        reply = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

    return json.loads(reply)
