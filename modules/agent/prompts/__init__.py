"""Prompt loader — AI-first adaptive prompt system.

Loads the master prompt with scan-type focus hints instead of static templates.
Falls back to legacy {scan_type}.txt if master.txt is not found.
"""

import json
import os

_DIR = os.path.dirname(__file__)

# Focus hints — scan_type becomes a steering hint, not a straitjacket
_FOCUS_HINTS = {
    "adaptive": "Run a fully adaptive scan. Discover everything and test what you find.",
    "security": "Focus primarily on security vulnerabilities, but still do full discovery.",
    "pentest": "Focus on exploitable vulnerabilities and attack chains. Be aggressive in testing.",
    "chatbot": "The user believes there is a chatbot on this target. Prioritize chatbot discovery and testing.",
    "api_security": "The user wants API security testing prioritized. Discover and test all API endpoints.",
    "seo": "Focus primarily on SEO, performance, and accessibility after discovery.",
    "performance": "Focus primarily on performance and load testing after discovery.",
    "compliance": "Focus on compliance frameworks (OWASP, PCI-DSS, GDPR, SOC2, ISO27001, HIPAA) after discovery. Load relevant framework knowledge modules. Generate detailed per-requirement compliance reports with pass/fail status and evidence.",
    "compliance_audit": "This is a dedicated compliance audit. Load compliance, pci_dss_4, soc2, iso27001, and hipaa knowledge modules. Map every finding to specific compliance requirements. Generate compliance_reports with per-requirement pass/fail status, pass_rate, and critical_gaps for each applicable framework.",
    "full": "This is a comprehensive scan. Test EVERYTHING you discover. Be thorough.",
    "owasp": "Map all findings to OWASP Top 10 categories. Systematically test each A01-A10.",
    "recon": "Focus on deep reconnaissance and attack surface mapping. Be exhaustive in discovery.",
    "cloud": "Focus on cloud security and infrastructure after discovery.",
    "privacy": "Focus on privacy, data protection, cookie compliance, and GDPR signals.",
    "uptime": "Focus on availability, response times, and monitoring endpoints.",
}


def get_prompt(scan_type: str, *, target: str, config: dict | None = None) -> str:
    """Return the system prompt for a given scan type with variables substituted.

    Uses the master prompt (AI-first adaptive) with a focus hint from scan_type.
    Falls back to legacy {scan_type}.txt if master.txt doesn't exist.
    """
    # Work on a shallow copy so we do not mutate the caller's config dict.
    config = dict(config) if config else {}

    # Extract keys that must not be passed to template.format() — they contain
    # nested dicts with curly braces or are not template placeholders.
    retry_context = config.pop("retry_context", None)
    config.pop("auth", None)          # auth config: nested dict, not a template var
    config.pop("resume_context", None)  # resume_context also handled separately

    # Try master prompt first (AI-first adaptive mode)
    master_path = os.path.join(_DIR, "master.txt")
    if os.path.exists(master_path):
        with open(master_path) as f:
            template = f.read()

        prompt = template.format(target=target, **config)

        # Add focus hint based on scan_type
        hint = _FOCUS_HINTS.get(scan_type, _FOCUS_HINTS["security"])
        prompt += f"\n\n## Scan Focus\n{hint}\n"
    else:
        # Fallback to legacy per-type templates
        path = os.path.join(_DIR, f"{scan_type}.txt")
        if not os.path.exists(path):
            path = os.path.join(_DIR, "security.txt")

        with open(path) as f:
            template = f.read()

        prompt = template.format(target=target, **config)

    # Append retry instructions if this is a retry scan
    if retry_context:
        prompt += _build_retry_section(retry_context)

    return prompt


def _build_retry_section(ctx: dict) -> str:
    """Build a retry instruction section for the system prompt."""
    parts = [
        "\n\n## RETRY MODE — Previous Scan Failed or Had Errors",
        f"This is a retry of scan {ctx.get('retry_of', 'unknown')}.",
        f"Previous status: {ctx.get('original_status', 'unknown')}",
    ]

    if ctx.get("previous_error"):
        parts.append(f"\nPrevious error: {ctx['previous_error']}")

    if ctx.get("previous_summary"):
        parts.append(f"\nPrevious findings summary:\n{ctx['previous_summary']}")
        parts.append(f"Previous findings count: {ctx.get('previous_findings_count', 0)}")
        parts.append(f"Previous risk score: {ctx.get('previous_risk_score', 0)}")

    if ctx.get("failed_steps"):
        parts.append("\nFailed steps from previous attempt:")
        for step in ctx["failed_steps"][:10]:
            tool = step.get("tool", step.get("command", "unknown"))
            error = str(step.get("result", ""))[:200]
            parts.append(f"  - {tool}: {error}")

    parts.extend([
        "\n## Retry Instructions",
        "1. Analyze WHY the previous scan failed — was it a tool error, timeout, network issue, or wrong approach?",
        "2. Try ALTERNATIVE tools or approaches for the failed steps",
        "3. Do NOT re-run steps that already succeeded (their results are above)",
        "4. If a tool is broken or unavailable, skip it and use alternatives",
        "5. Focus on completing the areas that were missed",
        "6. Produce a COMPLETE report including both previous successful findings and new retry results",
        "7. If the previous scan found findings, include them in your report along with any new ones",
    ])

    return "\n".join(parts)
