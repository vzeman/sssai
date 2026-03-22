"""Prompt loader — reads scan-type prompt templates and fills in variables."""

import json
import os

_DIR = os.path.dirname(__file__)


def get_prompt(scan_type: str, *, target: str, config: dict | None = None) -> str:
    """Return the system prompt for a given scan type with variables substituted."""
    config = config or {}

    # Extract retry_context before passing to template format (it has curly braces)
    retry_context = config.pop("retry_context", None)

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
