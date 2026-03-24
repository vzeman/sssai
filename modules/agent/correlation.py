"""
Vulnerability correlation engine — detects attack patterns, constructs
attack chains, and calculates combined risk from scan findings.

Uses rule-based heuristics (no external ML libraries) to:
  - Group related findings by target/host and category
  - Identify findings that enable other findings (attack chains)
  - Score combined risk when correlated findings are worse together
  - Detect persistent/recurring threat patterns across scan history
"""

import hashlib
import logging
import re
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# ── Severity helpers ────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1,
}

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _sev(finding: dict) -> str:
    return (finding.get("severity") or "info").lower()


def _category(finding: dict) -> str:
    return (finding.get("type") or finding.get("category") or "").lower()


def _target(finding: dict) -> str:
    return (finding.get("target") or "").lower()


def _host(finding: dict) -> str:
    """Extract host from target URL or return raw target."""
    raw = _target(finding)
    try:
        parsed = urlparse(raw)
        return parsed.hostname or raw
    except Exception:
        return raw


def _text(finding: dict) -> str:
    """Concatenate searchable text fields."""
    return " ".join([
        finding.get("type", ""),
        finding.get("category", ""),
        finding.get("description", ""),
        finding.get("cwe", ""),
    ]).lower()


def _finding_id(finding: dict) -> str:
    """Deterministic short ID for a finding."""
    blob = f"{_category(finding)}|{_target(finding)}|{finding.get('description', '')}"
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


# ── Attack chain rules ──────────────────────────────────────────────────

# Each rule: (precursor regex on category/text, successor regex, chain metadata)
_CHAIN_RULES: list[dict] = [
    {
        "name": "Auth Bypass -> RCE",
        "precursor": r"auth.?bypass|broken.?auth|weak.?auth",
        "successor": r"rce|remote.?code|command.?inject|deseri",
        "severity": "critical",
        "description": "Authentication bypass enables remote code execution.",
        "risk_multiplier": 2.0,
    },
    {
        "name": "SQL Injection -> Data Exfiltration",
        "precursor": r"sql.?inject|sqli|nosql.?inject",
        "successor": r"data.?exfil|data.?exposure|info.?disclos|sensitive.?data",
        "severity": "critical",
        "description": "SQL injection enables extraction of sensitive data.",
        "risk_multiplier": 1.8,
    },
    {
        "name": "SSRF -> Internal Service Access",
        "precursor": r"ssrf|server.?side.?request",
        "successor": r"internal.?service|cloud.?metadata|priv.?escal|lateral",
        "severity": "high",
        "description": "SSRF provides access to internal services and metadata.",
        "risk_multiplier": 1.7,
    },
    {
        "name": "XSS -> Session Hijack -> Account Takeover",
        "precursor": r"xss|cross.?site.?script",
        "successor": r"session.?hijack|account.?takeover|credential|cookie",
        "severity": "high",
        "description": "Cross-site scripting enables session hijacking and account takeover.",
        "risk_multiplier": 1.6,
    },
    {
        "name": "Subdomain Takeover -> Phishing",
        "precursor": r"subdomain.?takeover|dangling.?dns|unclaimed",
        "successor": r"phish|social.?eng|spoof",
        "severity": "high",
        "description": "Subdomain takeover enables convincing phishing attacks.",
        "risk_multiplier": 1.5,
    },
    {
        "name": "Misconfiguration -> Privilege Escalation",
        "precursor": r"misconfig|default.?cred|open.?permission|weak.?config",
        "successor": r"priv.*escal|privilege|admin.?access|elevat",
        "severity": "high",
        "description": "Security misconfiguration enables privilege escalation.",
        "risk_multiplier": 1.6,
    },
    {
        "name": "Info Disclosure -> RCE",
        "precursor": r"info.?disclos|version.?leak|stack.?trace|debug",
        "successor": r"rce|remote.?code|command.?inject",
        "severity": "critical",
        "description": "Information disclosure reveals details enabling remote code execution.",
        "risk_multiplier": 1.9,
    },
    {
        "name": "Injection -> Privilege Escalation",
        "precursor": r"inject|sqli|command.?inject|template.?inject",
        "successor": r"priv.*escal|privilege|admin|root|elevat",
        "severity": "critical",
        "description": "Injection vulnerability enables privilege escalation.",
        "risk_multiplier": 1.8,
    },
    {
        "name": "XXE -> Data Exposure",
        "precursor": r"xxe|xml.?external",
        "successor": r"data.?exposure|file.?read|file.?disclos|info.?disclos",
        "severity": "high",
        "description": "XXE vulnerability enables reading of sensitive files.",
        "risk_multiplier": 1.5,
    },
    {
        "name": "Weak Crypto -> Data Theft",
        "precursor": r"weak.?crypt|insecure.?cipher|weak.?hash|broken.?crypt",
        "successor": r"data.?exfil|data.?exposure|credential|token.?leak",
        "severity": "high",
        "description": "Weak cryptography enables theft of sensitive data.",
        "risk_multiplier": 1.4,
    },
]

# Patterns that indicate systematic issues when multiple findings match
_SYSTEMATIC_PATTERNS: list[dict] = [
    {
        "name": "Widespread Injection Flaws",
        "pattern": r"inject|sqli|xss|command.?inject|template.?inject",
        "min_count": 3,
        "description": "Multiple injection vulnerabilities suggest missing input validation.",
    },
    {
        "name": "Broken Access Control",
        "pattern": r"access.?control|idor|insecure.?direct|authz|priv.*escal|privilege",
        "min_count": 2,
        "description": "Multiple access control issues indicate systemic authorization flaws.",
    },
    {
        "name": "Security Misconfiguration",
        "pattern": r"misconfig|default|header.?miss|cors|csp|hsts",
        "min_count": 3,
        "description": "Multiple misconfigurations suggest lack of security hardening.",
    },
    {
        "name": "Cryptographic Failures",
        "pattern": r"crypt|cipher|tls|ssl|cert|hash|weak.?key",
        "min_count": 2,
        "description": "Multiple cryptographic issues indicate outdated security practices.",
    },
    {
        "name": "Information Exposure",
        "pattern": r"info.?disclos|leak|exposure|verbose.?error|stack.?trace|debug",
        "min_count": 3,
        "description": "Widespread information leakage across multiple endpoints.",
    },
]


# ── Core functions ──────────────────────────────────────────────────────

def detect_attack_chains(findings: list[dict]) -> list[dict]:
    """
    Scan all finding pairs for known attack-chain patterns.

    Returns a list of chain dicts, each with:
      - name, description, severity
      - precursor / successor (the two findings)
      - confidence  (0.0 – 1.0)
      - risk_multiplier
    """
    if len(findings) < 2:
        return []

    chains: list[dict] = []
    used_indices: set[int] = set()

    for rule in _CHAIN_RULES:
        precursor_re = re.compile(rule["precursor"], re.IGNORECASE)
        successor_re = re.compile(rule["successor"], re.IGNORECASE)

        # Find precursor candidates
        precursors = [
            (i, f) for i, f in enumerate(findings)
            if i not in used_indices and precursor_re.search(_text(f))
        ]
        # Find successor candidates
        successors = [
            (i, f) for i, f in enumerate(findings)
            if i not in used_indices and successor_re.search(_text(f))
        ]

        for pi, pf in precursors:
            for si, sf in successors:
                if pi == si:
                    continue

                confidence = _chain_confidence(pf, sf)
                if confidence < 0.3:
                    continue

                chains.append({
                    "name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "precursor": pf,
                    "successor": sf,
                    "confidence": round(confidence, 2),
                    "risk_multiplier": rule["risk_multiplier"],
                })
                used_indices.add(pi)
                used_indices.add(si)

    # Sort by confidence descending
    chains.sort(key=lambda c: c["confidence"], reverse=True)
    return chains


def _chain_confidence(precursor: dict, successor: dict) -> float:
    """Heuristic confidence score for a two-finding chain."""
    score = 0.0

    # Same host → stronger chain
    if _host(precursor) and _host(precursor) == _host(successor):
        score += 0.35

    # Both have meaningful severity
    pre_rank = _SEVERITY_RANK.get(_sev(precursor), 1)
    suc_rank = _SEVERITY_RANK.get(_sev(successor), 1)
    score += min(0.3, (pre_rank + suc_rank) * 0.04)

    # CWE overlap / presence boosts
    pre_cwe = (precursor.get("cwe") or "").strip()
    suc_cwe = (successor.get("cwe") or "").strip()
    if pre_cwe and suc_cwe:
        score += 0.15 if pre_cwe == suc_cwe else 0.05

    # Evidence of exploitability
    for f in (precursor, successor):
        desc = (f.get("description") or "").lower()
        if any(kw in desc for kw in ("exploit", "poc", "proof of concept", "verified")):
            score += 0.1

    return min(1.0, score)


def group_by_pattern(findings: list[dict]) -> dict:
    """
    Group findings into systematic-issue buckets.

    Returns dict keyed by pattern name, each value a dict with:
      - description
      - findings  (list of matched findings)
      - count
    """
    groups: dict[str, dict] = {}

    for sp in _SYSTEMATIC_PATTERNS:
        regex = re.compile(sp["pattern"], re.IGNORECASE)
        matched = [f for f in findings if regex.search(_text(f))]
        if len(matched) >= sp["min_count"]:
            groups[sp["name"]] = {
                "description": sp["description"],
                "findings": matched,
                "count": len(matched),
            }

    # Also group by host
    host_groups: dict[str, list[dict]] = {}
    for f in findings:
        h = _host(f)
        if h:
            host_groups.setdefault(h, []).append(f)

    for host, host_findings in host_groups.items():
        if len(host_findings) >= 3:
            groups[f"host:{host}"] = {
                "description": f"Multiple vulnerabilities on {host}.",
                "findings": host_findings,
                "count": len(host_findings),
            }

    return groups


def calculate_combined_risk(chain: list[dict]) -> dict:
    """
    Calculate combined risk score for an attack chain (list of findings).

    Returns:
      - individual_scores: list of per-finding severity weights
      - base_score: sum of individual weights
      - combined_score: escalated score (capped at 100)
      - escalation_factor: multiplier applied
      - severity: resulting severity label
      - explanation: human-readable reasoning
    """
    if not chain:
        return {
            "individual_scores": [],
            "base_score": 0,
            "combined_score": 0,
            "escalation_factor": 1.0,
            "severity": "info",
            "explanation": "No findings provided.",
        }

    individual = [_SEVERITY_WEIGHT.get(_sev(f), 1) for f in chain]
    base = sum(individual)

    # Escalation: more findings in a chain → bigger multiplier
    count = len(chain)
    if count >= 4:
        factor = 1.8
    elif count >= 3:
        factor = 1.5
    elif count >= 2:
        factor = 1.3
    else:
        factor = 1.0

    # Extra boost if chain contains a critical finding
    if any(_sev(f) == "critical" for f in chain):
        factor += 0.2

    combined = min(100, round(base * factor))

    # Map combined score to severity label
    if combined >= 40:
        sev_label = "critical"
    elif combined >= 25:
        sev_label = "high"
    elif combined >= 15:
        sev_label = "medium"
    elif combined >= 5:
        sev_label = "low"
    else:
        sev_label = "info"

    explanation_parts = [
        f"Chain of {count} finding(s) with base score {base}.",
        f"Escalation factor {factor:.1f}x applied.",
        f"Combined risk: {combined}/100 ({sev_label}).",
    ]

    return {
        "individual_scores": individual,
        "base_score": base,
        "combined_score": combined,
        "escalation_factor": round(factor, 2),
        "severity": sev_label,
        "explanation": " ".join(explanation_parts),
    }


def detect_persistent_threats(
    findings: list[dict],
    history: list[dict] | None = None,
) -> list[dict]:
    """
    Identify recurring vulnerability patterns by comparing current findings
    against historical findings.

    Each returned threat dict contains:
      - category, target, occurrences, first_seen, latest
      - is_persistent  (True if same issue found in history)
      - recommendation
    """
    history = history or []
    threats: list[dict] = []

    # Build a set of (normalised_category, host) from history
    historical_keys: dict[tuple[str, str], list[dict]] = {}
    for hf in history:
        key = (_category(hf), _host(hf))
        historical_keys.setdefault(key, []).append(hf)

    # Check current findings against history
    seen_keys: set[tuple[str, str]] = set()
    for f in findings:
        key = (_category(f), _host(f))
        if key in seen_keys:
            continue
        seen_keys.add(key)

        past = historical_keys.get(key, [])
        is_persistent = len(past) > 0
        occurrences = len(past) + 1  # +1 for the current finding

        threat: dict = {
            "category": _category(f),
            "target": _host(f),
            "occurrences": occurrences,
            "is_persistent": is_persistent,
            "latest": f,
        }

        if is_persistent:
            threat["first_seen"] = past[-1]  # oldest in list (history is chronological)
            threat["recommendation"] = (
                f"Recurring '{_category(f)}' issue on {_host(f)} "
                f"({occurrences} occurrences). Investigate root cause."
            )
        else:
            threat["first_seen"] = f
            threat["recommendation"] = (
                f"New '{_category(f)}' finding on {_host(f)}. Monitor for recurrence."
            )

        threats.append(threat)

    # Sort: persistent first, then by occurrences
    threats.sort(key=lambda t: (-int(t["is_persistent"]), -t["occurrences"]))
    return threats


# ── Main entry point ────────────────────────────────────────────────────

def correlate_findings(findings: list[dict]) -> dict:
    """
    Main entry point — run full correlation analysis on a list of findings.

    Each finding is a dict with keys like:
      severity, type/category, target, description, cwe

    Returns a dict with:
      - attack_chains: list of detected chains
      - patterns: grouped systematic issues
      - risk_summary: overall combined-risk calculation
      - persistent_threats: recurring patterns (empty without history)
      - stats: summary counts
    """
    if not findings:
        return {
            "attack_chains": [],
            "patterns": {},
            "risk_summary": calculate_combined_risk([]),
            "persistent_threats": [],
            "stats": {
                "total_findings": 0,
                "chains_detected": 0,
                "patterns_detected": 0,
                "max_chain_confidence": 0.0,
            },
        }

    chains = detect_attack_chains(findings)
    patterns = group_by_pattern(findings)
    risk = calculate_combined_risk(findings)
    persistent = detect_persistent_threats(findings)

    max_conf = max((c["confidence"] for c in chains), default=0.0)

    result = {
        "attack_chains": chains,
        "patterns": patterns,
        "risk_summary": risk,
        "persistent_threats": persistent,
        "stats": {
            "total_findings": len(findings),
            "chains_detected": len(chains),
            "patterns_detected": len(patterns),
            "max_chain_confidence": max_conf,
        },
    }

    log.info(
        "Correlation complete: %d findings, %d chains, %d patterns",
        len(findings),
        len(chains),
        len(patterns),
    )

    return result
