"""
Security posture score calculation.

Computes a weighted posture score based on:
- CVSS severity of findings (40%)
- Finding age — older unfixed findings weigh more (20%)
- Attack chain severity (15%)
- Remediation velocity — how fast findings get resolved (15%)
- Compliance status (10%)
"""

from datetime import datetime, timezone

WEIGHTS = {
    "severity": 0.40,
    "finding_age": 0.20,
    "attack_chains": 0.15,
    "remediation_velocity": 0.15,
    "compliance": 0.10,
}

SEVERITY_DEDUCTIONS = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
    "informational": 0,
}


def _severity_score(findings: list) -> float:
    """Start at 100, deduct per finding based on severity. Floor at 0."""
    score = 100.0
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        score -= SEVERITY_DEDUCTIONS.get(sev, 0)
    return max(score, 0.0)


def _finding_age_score(findings: list) -> float:
    """100 if no old findings. Deduct extra for findings older than 30/90 days."""
    if not findings:
        return 100.0

    now = datetime.now(timezone.utc)
    score = 100.0

    for f in findings:
        first_seen = f.get("first_seen")
        if not first_seen:
            continue
        try:
            if isinstance(first_seen, str):
                # Handle ISO format timestamps
                ts = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            elif isinstance(first_seen, (int, float)):
                ts = datetime.fromtimestamp(first_seen, tz=timezone.utc)
            else:
                continue

            age_days = (now - ts).days
            if age_days > 90:
                score -= 10
            elif age_days > 30:
                score -= 5
        except (ValueError, TypeError, OSError):
            continue

    return max(score, 0.0)


def _attack_chain_score(findings: list) -> float:
    """100 minus (number_of_chains * chain_avg_risk_score / 10).

    Looks for attack_chains embedded in findings or passed as top-level data.
    Individual findings may carry an `attack_chain` flag or a `chain_risk` score.
    """
    chains = []
    for f in findings:
        if f.get("attack_chain") or f.get("chain_id"):
            chains.append(f)

    if not chains:
        return 100.0

    avg_risk = sum(f.get("chain_risk", f.get("risk_score", 50)) for f in chains) / len(chains)
    score = 100.0 - (len(chains) * avg_risk / 10.0)
    return max(score, 0.0)


def _remediation_velocity_score(scan_history: list | None) -> float:
    """Compare current vs previous scan findings count.

    If findings decreased, score higher. Default 80 if no history.
    """
    if not scan_history or len(scan_history) < 2:
        return 80.0

    # scan_history assumed sorted chronologically (oldest first)
    current_count = scan_history[-1].get("findings_count", 0)
    previous_count = scan_history[-2].get("findings_count", 0)

    if previous_count == 0:
        return 100.0 if current_count == 0 else 60.0

    ratio = current_count / previous_count
    if ratio <= 0.5:
        return 100.0  # Findings halved or more — excellent
    elif ratio <= 0.8:
        return 90.0   # Good improvement
    elif ratio <= 1.0:
        return 80.0   # Stable or slight improvement
    elif ratio <= 1.2:
        return 60.0   # Slight increase
    else:
        return 40.0   # Significant increase


def _compliance_score(findings: list) -> float:
    """100 if all compliance checks pass, 50 if partial, 0 if all fail.

    Average across frameworks found in findings.
    """
    compliance_results = []
    for f in findings:
        status = f.get("compliance_status")
        if status is not None:
            if isinstance(status, bool):
                compliance_results.append(100.0 if status else 0.0)
            elif isinstance(status, str):
                s = status.lower()
                if s in ("pass", "passed", "compliant"):
                    compliance_results.append(100.0)
                elif s in ("partial", "warning"):
                    compliance_results.append(50.0)
                else:
                    compliance_results.append(0.0)

    if not compliance_results:
        return 100.0  # No compliance data — assume compliant

    return sum(compliance_results) / len(compliance_results)


def _compute_trend(posture_score: float, scan_history: list | None) -> tuple[str, float]:
    """Determine trend by comparing current score to previous scores."""
    if not scan_history:
        return "stable", 0.0

    previous_scores = [
        h.get("posture_score") for h in scan_history
        if h.get("posture_score") is not None
    ]
    if not previous_scores:
        return "stable", 0.0

    avg_previous = sum(previous_scores) / len(previous_scores)
    delta = posture_score - avg_previous

    if delta > 2.0:
        trend = "improving"
    elif delta < -2.0:
        trend = "degrading"
    else:
        trend = "stable"

    return trend, round(delta, 2)


def calculate_posture_score(
    findings: list,
    scan_history: list | None = None,
) -> dict:
    """Calculate posture score from findings.

    Args:
        findings: List of finding dicts from the scan report.
        scan_history: Optional list of previous scan summary dicts,
                      each with keys like ``posture_score``, ``findings_count``.

    Returns:
        {
            "posture_score": float (0-100, 100=most secure),
            "component_scores": {
                "severity": float,
                "finding_age": float,
                "attack_chains": float,
                "remediation_velocity": float,
                "compliance": float,
            },
            "trend": "improving" | "stable" | "degrading",
            "trend_delta": float,
        }
    """
    components = {
        "severity": _severity_score(findings),
        "finding_age": _finding_age_score(findings),
        "attack_chains": _attack_chain_score(findings),
        "remediation_velocity": _remediation_velocity_score(scan_history),
        "compliance": _compliance_score(findings),
    }

    posture_score = sum(
        components[k] * WEIGHTS[k] for k in WEIGHTS
    )
    posture_score = round(max(min(posture_score, 100.0), 0.0), 1)

    trend, trend_delta = _compute_trend(posture_score, scan_history)

    return {
        "posture_score": posture_score,
        "component_scores": {k: round(v, 1) for k, v in components.items()},
        "trend": trend,
        "trend_delta": trend_delta,
    }
