"""Continuous security posture score calculation.

After each scan completes, calculates a weighted 0-100 posture score per target
and stores daily snapshots in Elasticsearch (scanner-security-posture index).
"""

import logging
from datetime import datetime, timezone, timedelta

log = logging.getLogger(__name__)

# Severity penalty weights (subtracted from 100)
_SEVERITY_PENALTIES = {
    "critical": 25.0,
    "high": 10.0,
    "medium": 4.0,
    "low": 1.5,
    "info": 0.3,
}

# CVSS thresholds for additional penalty multiplier
_CVSS_HIGH_THRESHOLD = 7.0
_CVSS_CRITICAL_THRESHOLD = 9.0

# Finding age thresholds (days) for staleness penalty
_AGE_STALE_DAYS = 30
_AGE_CRITICAL_DAYS = 90


def _severity_base_penalty(findings: list[dict]) -> float:
    """Sum of severity penalties for all findings."""
    total = 0.0
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        total += _SEVERITY_PENALTIES.get(sev, 0.3)
    return total


def _cvss_factor(findings: list[dict]) -> float:
    """Extra penalty from high CVSS scores."""
    extra = 0.0
    for f in findings:
        cvss = f.get("cvss_score") or 0.0
        if cvss >= _CVSS_CRITICAL_THRESHOLD:
            extra += 5.0
        elif cvss >= _CVSS_HIGH_THRESHOLD:
            extra += 2.0
    return extra


def _age_penalty(findings: list[dict], scan_timestamp: datetime) -> float:
    """Penalty for old unfixed findings (older = worse posture)."""
    penalty = 0.0
    for f in findings:
        # Use finding timestamp if present, else use scan timestamp as proxy
        raw_ts = f.get("timestamp") or f.get("first_seen")
        if not raw_ts:
            continue
        try:
            if isinstance(raw_ts, str):
                # Strip timezone if needed for fromisoformat
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            else:
                ts = raw_ts
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_days = (scan_timestamp - ts).days
        except Exception:
            continue

        sev = (f.get("severity") or "info").lower()
        base = _SEVERITY_PENALTIES.get(sev, 0.3)
        if age_days >= _AGE_CRITICAL_DAYS:
            penalty += base * 1.0  # double the base penalty for very old findings
        elif age_days >= _AGE_STALE_DAYS:
            penalty += base * 0.5  # 50% extra for stale findings
    return penalty


def _remediation_velocity_bonus(target: str, user_id: str, current_count: int) -> float:
    """Bonus (0-10) for reducing finding count vs recent scans."""
    try:
        from modules.infra.elasticsearch import search as es_search

        # Look at last 5 completed scans for this target and user
        result = es_search(
            "scanner-security-posture",
            {
                "bool": {
                    "filter": [
                        {"term": {"target": target}},
                        {"term": {"user_id": user_id}},
                        {"exists": {"field": "finding_counts.total"}},
                    ]
                }
            },
            size=5,
            sort=[{"timestamp": "desc"}],
        )
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return 0.0

        prev_counts = [
            h["_source"].get("finding_counts", {}).get("total", 0)
            for h in hits
            if h["_source"].get("finding_counts", {}).get("total") is not None
        ]
        if not prev_counts:
            return 0.0

        avg_prev = sum(prev_counts) / len(prev_counts)
        if avg_prev == 0:
            return 5.0  # maintained zero findings
        reduction_pct = max(0.0, (avg_prev - current_count) / avg_prev)
        return min(10.0, reduction_pct * 10.0)
    except Exception:
        return 0.0


def _attack_chain_penalty(findings: list[dict]) -> float:
    """Extra penalty when multiple high/critical findings exist (attack chain risk)."""
    high_crit = sum(
        1
        for f in findings
        if (f.get("severity") or "").lower() in ("critical", "high")
    )
    if high_crit >= 5:
        return 15.0
    if high_crit >= 3:
        return 8.0
    if high_crit >= 2:
        return 4.0
    return 0.0


def calculate_posture_score(
    scan_id: str,
    target: str,
    user_id: str,
    findings: list[dict],
    scan_risk_score: float | None,
) -> dict:
    """Calculate a weighted security posture score (0-100).

    Returns a document ready for indexing into scanner-security-posture.
    Higher score = better security posture.
    """
    now = datetime.now(timezone.utc)

    # Count findings by severity
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    counts["total"] = len(findings)

    # Score components
    base_penalty = _severity_base_penalty(findings)
    cvss_penalty = _cvss_factor(findings)
    age_penalty = _age_penalty(findings, now)
    chain_penalty = _attack_chain_penalty(findings)
    velocity_bonus = _remediation_velocity_bonus(target, user_id, len(findings))

    # Incorporate existing risk_score (0-100 scale from agent) if available
    # risk_score represents vulnerability severity; convert to penalty
    risk_penalty = 0.0
    if scan_risk_score is not None:
        risk_penalty = scan_risk_score * 0.3  # up to 30 pts from raw risk score

    total_penalty = base_penalty + cvss_penalty + age_penalty + chain_penalty + risk_penalty
    raw_score = max(0.0, min(100.0, 100.0 - total_penalty + velocity_bonus))
    posture_score = round(raw_score, 2)

    # Determine trend vs. previous snapshot for this target
    trend, trend_delta = _compute_trend(target, user_id, posture_score)

    return {
        "timestamp": now.isoformat(),
        "scan_id": scan_id,
        "target": target,
        "user_id": user_id,
        "posture_score": posture_score,
        "trend": trend,
        "trend_delta": trend_delta,
        "components": {
            "base_penalty": round(base_penalty, 2),
            "cvss_penalty": round(cvss_penalty, 2),
            "age_penalty": round(age_penalty, 2),
            "chain_penalty": round(chain_penalty, 2),
            "risk_penalty": round(risk_penalty, 2),
            "velocity_bonus": round(velocity_bonus, 2),
        },
        "finding_counts": counts,
        "commentary": "",   # filled by generate_posture_commentary
        "forecast": "",     # filled by generate_posture_commentary
        "forecast_date": None,
    }


def _compute_trend(target: str, user_id: str, current_score: float) -> tuple[str, float]:
    """Compare current score against most recent snapshot. Returns (trend, delta)."""
    try:
        from modules.infra.elasticsearch import search as es_search

        result = es_search(
            "scanner-security-posture",
            {"bool": {"filter": [{"term": {"target": target}}, {"term": {"user_id": user_id}}]}},
            size=1,
            sort=[{"timestamp": "desc"}],
        )
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return "stable", 0.0

        prev_score = hits[0]["_source"].get("posture_score", current_score)
        delta = round(current_score - prev_score, 2)
        if delta > 2:
            return "improving", delta
        if delta < -2:
            return "degrading", delta
        return "stable", delta
    except Exception:
        return "stable", 0.0


def generate_posture_commentary(
    posture_doc: dict,
    scan_id: str,
    target: str,
    findings: list[dict],
) -> dict:
    """Use Claude to generate natural-language commentary and remediation forecast.

    Mutates posture_doc in place with 'commentary' and 'forecast' fields.
    Returns the updated doc.
    """
    try:
        import anthropic
        from modules.config import AI_MODEL

        score = posture_doc["posture_score"]
        counts = posture_doc["finding_counts"]
        trend = posture_doc["trend"]
        delta = posture_doc["trend_delta"]

        # Build a brief context string to keep tokens low
        top_findings = [
            f"{f.get('severity','?').upper()}: {f.get('title','unknown')}"
            for f in findings[:10]
        ]
        findings_text = "\n".join(top_findings) if top_findings else "No findings."

        prompt = (
            f"Security posture score for {target}: {score}/100 ({trend}, {delta:+.1f} pts).\n"
            f"Findings: {counts.get('critical',0)} critical, {counts.get('high',0)} high, "
            f"{counts.get('medium',0)} medium, {counts.get('low',0)} low, {counts.get('info',0)} info.\n"
            f"Top findings:\n{findings_text}\n\n"
            "Write two things:\n"
            "1. COMMENTARY: A 2-3 sentence plain-English summary of the security posture trend and key risks.\n"
            "2. FORECAST: One sentence estimating when all critical/high findings could be resolved "
            "if remediation continues at current velocity. Use approximate calendar date.\n"
            "Format: COMMENTARY: <text>\nFORECAST: <text>"
        )

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=AI_MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = ""
        for block in response.content:
            if hasattr(block, "text"):
                text += block.text

        commentary = ""
        forecast = ""
        for line in text.splitlines():
            if line.startswith("COMMENTARY:"):
                commentary = line[len("COMMENTARY:"):].strip()
            elif line.startswith("FORECAST:"):
                forecast = line[len("FORECAST:"):].strip()

        posture_doc["commentary"] = commentary or text[:500]
        posture_doc["forecast"] = forecast

        # Try to parse a forecast date from forecast text for structured storage
        if forecast:
            _try_parse_forecast_date(posture_doc, forecast)

    except Exception as e:
        log.warning("Posture commentary generation failed: %s", e)
        posture_doc["commentary"] = _fallback_commentary(posture_doc)
        posture_doc["forecast"] = ""

    return posture_doc


def _try_parse_forecast_date(posture_doc: dict, forecast_text: str) -> None:
    """Best-effort extraction of a date from the forecast text."""
    import re
    # Look for patterns like "by April 2026", "by 2026-05-01", "by Q2 2026"
    patterns = [
        r"\b(\d{4}-\d{2}-\d{2})\b",
        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, forecast_text)
        if match:
            try:
                if "-" in match.group(0):
                    posture_doc["forecast_date"] = match.group(1)
                else:
                    month_str, year_str = match.group(1), match.group(2)
                    month_num = datetime.strptime(month_str, "%B").month
                    posture_doc["forecast_date"] = f"{year_str}-{month_num:02d}-01"
                return
            except Exception:
                pass


def _fallback_commentary(posture_doc: dict) -> str:
    score = posture_doc["posture_score"]
    counts = posture_doc["finding_counts"]
    trend = posture_doc["trend"]
    if score >= 80:
        level = "strong"
    elif score >= 60:
        level = "moderate"
    elif score >= 40:
        level = "weak"
    else:
        level = "critical"
    return (
        f"Security posture is {level} at {score}/100 ({trend}). "
        f"{counts.get('critical',0)} critical and {counts.get('high',0)} high findings require attention."
    )


def run_posture_update(
    scan_id: str,
    target: str,
    user_id: str,
    findings: list[dict],
    scan_risk_score: float | None,
) -> dict | None:
    """Entry point: calculate posture, generate commentary, index to ES.

    Returns the indexed posture document or None on failure.
    """
    try:
        from modules.infra.elasticsearch import index_doc

        posture_doc = calculate_posture_score(
            scan_id, target, user_id, findings, scan_risk_score
        )
        posture_doc = generate_posture_commentary(posture_doc, scan_id, target, findings)

        doc_id = f"{target}:{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        index_doc("scanner-security-posture", posture_doc, doc_id=doc_id)

        log.info(
            "Posture score for %s: %.1f (%s %+.1f)",
            target,
            posture_doc["posture_score"],
            posture_doc["trend"],
            posture_doc["trend_delta"],
        )
        return posture_doc
    except Exception as e:
        log.warning("Posture update failed for %s: %s", target, e)
        return None
