"""
Intelligent scan scheduling — analyzes scan history to recommend
the optimal scan interval for a target.
"""

import logging
import os

log = logging.getLogger(__name__)

_DB_URL = os.environ.get("DATABASE_URL", "")

# Interval options in ascending frequency order
_INTERVALS = ["daily", "weekly", "biweekly", "monthly"]

# Target patterns that indicate high criticality (more frequent scanning)
_CRITICAL_TARGET_PATTERNS = [
    "payment", "checkout", "billing", "pay",
    "login", "signin", "auth", "oauth",
    "admin", "manage", "dashboard",
    "api", "graphql", "rest",
]

_MEDIUM_TARGET_PATTERNS = [
    "app", "portal", "user", "account",
    "search", "form", "upload",
]


def _classify_target_criticality(target: str) -> str:
    """Return 'critical', 'high', 'medium', or 'low' based on target URL patterns."""
    t = target.lower()
    for pattern in _CRITICAL_TARGET_PATTERNS:
        if pattern in t:
            return "critical"
    for pattern in _MEDIUM_TARGET_PATTERNS:
        if pattern in t:
            return "medium"
    return "low"


def _fetch_scan_history(target: str, limit: int = 10) -> list[dict]:
    """
    Fetch recent completed scans for a target from the database.
    Returns list of dicts with keys: scan_id, risk_score, findings_count, completed_at.
    """
    if not _DB_URL:
        return []
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            rows = conn.execute(text(
                """
                SELECT id, risk_score, findings_count, completed_at
                FROM scans
                WHERE target = :target
                  AND status = 'completed'
                ORDER BY completed_at DESC
                LIMIT :limit
                """
            ), {"target": target, "limit": limit}).fetchall()
        return [
            {
                "scan_id": str(row[0]),
                "risk_score": float(row[1]) if row[1] is not None else 0.0,
                "findings_count": int(row[2]) if row[2] is not None else 0,
                "completed_at": row[3],
            }
            for row in rows
        ]
    except Exception as e:
        log.warning("Could not fetch scan history for scheduling: %s", e)
        return []


def _compute_change_rate(history: list[dict]) -> float:
    """
    Compute the average change in findings_count across consecutive scans.
    Returns a positive float (higher = more volatile).
    """
    if len(history) < 2:
        return 0.0
    deltas = []
    for i in range(len(history) - 1):
        delta = abs(history[i]["findings_count"] - history[i + 1]["findings_count"])
        deltas.append(delta)
    return sum(deltas) / len(deltas) if deltas else 0.0


def _vulnerability_density(history: list[dict]) -> float:
    """Average findings count across recent scans."""
    if not history:
        return 0.0
    return sum(h["findings_count"] for h in history) / len(history)


def recommend_scan_interval(
    target: str,
    current_report: dict,
    scan_history: list[dict] | None = None,
) -> dict:
    """
    Analyze scan history and current results to recommend a scan interval.

    Returns:
        {
            "recommended_scan_interval": "weekly",
            "interval_reasoning": "...",
        }
    """
    if scan_history is None:
        scan_history = _fetch_scan_history(target)

    current_findings = current_report.get("findings", []) or []
    current_risk = current_report.get("risk_score", 0) or 0

    # Count high/critical findings in current scan
    high_critical = sum(
        1 for f in current_findings
        if f.get("severity", "info") in ("critical", "high")
    )

    target_criticality = _classify_target_criticality(target)
    change_rate = _compute_change_rate(scan_history)
    avg_density = _vulnerability_density(scan_history)

    reasons = []
    interval_score = 0  # higher = scan more frequently

    # Factor 1: Current severity
    if high_critical >= 3:
        interval_score += 3
        reasons.append(f"{high_critical} new high/critical findings in this scan")
    elif high_critical >= 1:
        interval_score += 2
        reasons.append(f"{high_critical} high/critical finding(s) detected")

    # Factor 2: Overall risk score
    if current_risk >= 70:
        interval_score += 2
        reasons.append(f"high risk score ({current_risk:.0f}/100)")
    elif current_risk >= 40:
        interval_score += 1
        reasons.append(f"moderate risk score ({current_risk:.0f}/100)")

    # Factor 3: Change rate across scans
    if change_rate >= 3:
        interval_score += 3
        reasons.append(f"high volatility — avg {change_rate:.1f} findings change per scan")
    elif change_rate >= 1:
        interval_score += 1
        reasons.append(f"moderate change rate ({change_rate:.1f} avg delta)")
    elif scan_history:
        reasons.append("stable target — minimal change between scans")

    # Factor 4: Target criticality
    if target_criticality == "critical":
        interval_score += 2
        reasons.append("target contains high-value components (auth/payment/API)")
    elif target_criticality == "medium":
        interval_score += 1
        reasons.append("target serves active users")

    # Factor 5: Historical vulnerability density
    if avg_density >= 10:
        interval_score += 1
        reasons.append(f"historically vulnerability-dense target ({avg_density:.0f} avg findings)")

    # Map score to interval
    if interval_score >= 7:
        interval = "daily"
    elif interval_score >= 5:
        interval = "weekly"
    elif interval_score >= 3:
        interval = "biweekly"
    else:
        interval = "monthly"

    # Build reasoning string
    if reasons:
        reasoning = f"Recommended '{interval}' scanning because: {'; '.join(reasons)}."
    else:
        reasoning = f"Recommended '{interval}' scanning — no significant risk signals detected."

    if not scan_history:
        reasoning += " (No prior scan history available; recommendation based on current scan only.)"

    return {
        "recommended_scan_interval": interval,
        "interval_reasoning": reasoning,
    }
