"""
Auto-triage module — enriches findings with exploitability, business impact,
exposure, and priority score, then buckets them into action categories.
"""

import logging
import re

log = logging.getLogger(__name__)

# Severity base scores
_SEVERITY_SCORE = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 2,
}

# Categories that indicate high business impact
_HIGH_IMPACT_PATTERNS = [
    r"auth", r"login", r"password", r"credential", r"session", r"token",
    r"payment", r"checkout", r"billing", r"credit.?card", r"ssn", r"pii",
    r"admin", r"privilege", r"injection", r"sqli", r"sql.?inject",
    r"remote.?code", r"rce", r"command.?inject", r"deseri", r"xxe",
    r"account.?takeover", r"csrf", r"xss.*stored", r"stored.*xss",
    r"api.?key", r"secret", r"jwt",
]

_MEDIUM_IMPACT_PATTERNS = [
    r"xss", r"cross.?site", r"open.?redirect", r"ssrf", r"idor",
    r"header", r"cors", r"csp", r"tls", r"ssl", r"certificate",
    r"rate.?limit", r"brute.?force", r"enumeration", r"disclosure",
]


def _score_business_impact(finding: dict) -> tuple[str, int]:
    """Return (impact_level, score) based on finding category/title/description."""
    text = " ".join([
        finding.get("title", ""),
        finding.get("category", ""),
        finding.get("description", ""),
        finding.get("owasp_category", ""),
    ]).lower()

    for pattern in _HIGH_IMPACT_PATTERNS:
        if re.search(pattern, text):
            return "critical", 30

    for pattern in _MEDIUM_IMPACT_PATTERNS:
        if re.search(pattern, text):
            return "medium", 15

    # Check severity as fallback
    severity = finding.get("severity", "info").lower()
    if severity in ("critical", "high"):
        return "medium", 15

    return "low", 5


def _score_exploitability(finding: dict) -> tuple[str, int]:
    """Return (exploitability_level, score) based on CVEs, CWEs, and evidence."""
    cve_ids = finding.get("cve_ids", []) or []
    cvss = finding.get("cvss_score")
    evidence = (finding.get("evidence", "") or "").lower()
    description = (finding.get("description", "") or "").lower()

    # Has a known CVE
    if cve_ids:
        # High CVSS CVE — likely has public exploit
        if cvss and float(cvss) >= 7.0:
            return "public_exploit", 25
        return "known_cve", 15

    # Evidence suggests active exploit
    exploit_keywords = ["exploit", "poc", "proof of concept", "metasploit", "public exploit"]
    if any(kw in evidence or kw in description for kw in exploit_keywords):
        return "public_exploit", 25

    # No known exploit
    severity = finding.get("severity", "info").lower()
    if severity in ("critical", "high"):
        return "theoretical", 10
    return "low_likelihood", 3


def _score_exposure(finding: dict, attack_surface: dict | None) -> tuple[str, int]:
    """Return (exposure_level, score) based on affected URLs and attack surface."""
    affected_urls = finding.get("affected_urls", []) or []
    entry_points = (attack_surface or {}).get("entry_points", []) or []

    # Check if affected URL matches any known external entry point
    if entry_points and affected_urls:
        for url in affected_urls:
            for ep in entry_points:
                if ep and url and (ep in url or url in ep):
                    return "internet_facing", 10

    # Heuristic: if URL looks external (not localhost/internal)
    internal_patterns = [r"localhost", r"127\.0\.0", r"10\.", r"192\.168\.", r"172\.(1[6-9]|2\d|3[01])\."]
    for url in affected_urls:
        if url:
            is_internal = any(re.search(p, url) for p in internal_patterns)
            if not is_internal:
                return "internet_facing", 10

    # Default: assume internet-facing for web findings
    category = (finding.get("category", "") or "").lower()
    if any(c in category for c in ["web", "http", "ssl", "header", "cors", "xss", "sqli"]):
        return "internet_facing", 10

    return "internal", 3


def enrich_findings(report: dict) -> list[dict]:
    """
    Enrich all findings with exploitability, business_impact, exposure, and priority_score.
    Returns sorted list (highest priority first).
    """
    findings = report.get("findings", []) or []
    attack_surface = report.get("attack_surface", {})

    enriched = []
    for finding in findings:
        f = dict(finding)  # shallow copy to avoid mutating original

        severity = f.get("severity", "info").lower()
        base_score = _SEVERITY_SCORE.get(severity, 2)

        exploitability, exploit_score = _score_exploitability(f)
        business_impact, impact_score = _score_business_impact(f)
        exposure, exposure_score = _score_exposure(f, attack_surface)

        priority_score = min(100, base_score + exploit_score + impact_score + exposure_score)

        f["exploitability"] = exploitability
        f["business_impact"] = business_impact
        f["exposure"] = exposure
        f["priority_score"] = priority_score

        enriched.append(f)

    # Sort by priority_score descending, then severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    enriched.sort(
        key=lambda x: (
            -x["priority_score"],
            severity_order.get(x.get("severity", "info"), 5),
        )
    )

    return enriched


def generate_triage_buckets(enriched_findings: list[dict]) -> dict:
    """
    Bucket findings into immediate_action, this_sprint, and backlog.
    Returns triage dict with labeled lists of finding summaries.
    """
    immediate_action = []
    this_sprint = []
    backlog = []

    for f in enriched_findings:
        score = f.get("priority_score", 0)
        severity = f.get("severity", "info").lower()
        title = f.get("title", "Unknown finding")
        exploitability = f.get("exploitability", "low_likelihood")
        business_impact = f.get("business_impact", "low")
        exposure = f.get("exposure", "internal")
        affected = f.get("affected_urls", [])
        affected_str = f" on {affected[0]}" if affected else ""

        # Build a descriptive label
        parts = []
        if exploitability == "public_exploit":
            parts.append("public exploit available")
        elif exploitability == "known_cve":
            cves = f.get("cve_ids", [])
            parts.append(f"CVE: {cves[0]}" if cves else "known CVE")
        if business_impact == "critical":
            parts.append(f"{f.get('category', 'critical')} component")
        if exposure == "internet_facing":
            parts.append("internet-facing")
        else:
            parts.append("internal only")

        reason = ", ".join(parts) if parts else severity
        label = f"{title}{affected_str} — {reason}"

        if score >= 75 or severity == "critical" or exploitability == "public_exploit":
            immediate_action.append(label)
        elif score >= 45 or severity == "high":
            this_sprint.append(label)
        else:
            backlog.append(label)

    return {
        "immediate_action": immediate_action,
        "this_sprint": this_sprint,
        "backlog": backlog,
    }


def apply_triage(report: dict) -> dict:
    """
    Main entry point: enrich findings and add triage section to the report.
    Returns the updated report dict.
    """
    try:
        enriched = enrich_findings(report)
        triage = generate_triage_buckets(enriched)
        report = dict(report)
        report["findings"] = enriched
        report["triage"] = triage
        log.info(
            "Triage complete: %d immediate, %d this sprint, %d backlog",
            len(triage["immediate_action"]),
            len(triage["this_sprint"]),
            len(triage["backlog"]),
        )
    except Exception as e:
        log.warning("Triage enrichment failed: %s", e)
    return report
