"""
Cross-scan vulnerability correlation — detects patterns across scan history.

Identifies:
- Persistent vulnerabilities that recur across scans
- Trending risk (improving/degrading over time)
- Correlated findings that appear together
"""

import logging
from collections import Counter, defaultdict

log = logging.getLogger(__name__)


def correlate_with_history(
    current_findings: list[dict],
    scan_history: list[dict],
    target: str,
) -> dict:
    """
    Compare current findings against historical scans of the same target.

    Args:
        current_findings: findings from the current scan
        scan_history: list of previous scan reports [{findings, risk_score, scan_id, timestamp}, ...]
        target: the target being scanned

    Returns:
        {
            "persistent_vulnerabilities": [...],  # findings that appear in multiple scans
            "new_vulnerabilities": [...],          # findings not seen before
            "resolved_vulnerabilities": [...],     # previously found but now gone
            "risk_trend": [...],                   # risk scores over time
            "correlation_patterns": [...],         # findings that co-occur
            "recurring_categories": {...},         # category frequency across scans
        }
    """
    if not scan_history:
        return {
            "persistent_vulnerabilities": [],
            "new_vulnerabilities": [f.get("title", "") for f in current_findings],
            "resolved_vulnerabilities": [],
            "risk_trend": [],
            "correlation_patterns": [],
            "recurring_categories": {},
        }

    # Track finding titles across all historical scans
    historical_titles: dict[str, int] = Counter()
    historical_categories: dict[str, int] = Counter()
    last_scan_titles: set[str] = set()
    risk_scores: list[dict] = []

    for scan in scan_history:
        findings = scan.get("findings", [])
        titles = {f.get("title", "") for f in findings}
        for t in titles:
            historical_titles[t] += 1
        for f in findings:
            cat = f.get("category", "unknown")
            historical_categories[cat] += 1
        risk_scores.append({
            "scan_id": scan.get("scan_id", ""),
            "risk_score": scan.get("risk_score", 0),
            "timestamp": scan.get("timestamp", ""),
            "findings_count": len(findings),
        })

    if scan_history:
        last_findings = scan_history[-1].get("findings", [])
        last_scan_titles = {f.get("title", "") for f in last_findings}

    current_titles = {f.get("title", "") for f in current_findings}

    # Persistent: found in current AND at least 2 previous scans
    persistent = [t for t in current_titles if historical_titles.get(t, 0) >= 2]

    # New: not seen in any previous scan
    new_vulns = [t for t in current_titles if t not in historical_titles]

    # Resolved: in last scan but not current
    resolved = list(last_scan_titles - current_titles)

    # Co-occurrence patterns (findings that appear together in >50% of scans)
    co_occurrence = defaultdict(int)
    total_scans = len(scan_history)
    for scan in scan_history:
        titles = sorted({f.get("title", "") for f in scan.get("findings", [])})
        for i, t1 in enumerate(titles):
            for t2 in titles[i + 1:]:
                co_occurrence[(t1, t2)] += 1

    patterns = []
    for (t1, t2), count in co_occurrence.items():
        if count >= max(2, total_scans * 0.5):
            patterns.append({
                "findings": [t1, t2],
                "co_occurrence_count": count,
                "frequency": round(count / total_scans, 2),
            })
    patterns.sort(key=lambda p: p["co_occurrence_count"], reverse=True)

    return {
        "persistent_vulnerabilities": persistent[:20],
        "new_vulnerabilities": new_vulns[:20],
        "resolved_vulnerabilities": resolved[:20],
        "risk_trend": risk_scores[-10:],  # last 10 scans
        "correlation_patterns": patterns[:10],
        "recurring_categories": dict(historical_categories.most_common(10)),
    }
