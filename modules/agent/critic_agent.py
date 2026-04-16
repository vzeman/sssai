"""
Red-team critic sub-agent (Issue #170).

Challenges a single finding and returns a structured verdict the main
agent must address before including the finding in the final report.

Design:
  - Separate, short Claude call using the light model (cost guard)
  - Strict JSON response — deterministic to parse and act on
  - Three verdicts: accept | reject | needs_more_evidence
  - Results feed back into the main agent via tool_result

Integration:
  - Exposed as the `challenge_finding` tool (see tools.py)
  - Handler in scan_agent.py dispatches here
  - Critic-rejected findings are automatically removed before the
    exploitation gate runs (#167) unless the main agent pushes back
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "critic.txt"


def _load_prompt() -> str:
    try:
        return _PROMPT_PATH.read_text()
    except Exception:
        return (
            "You are an adversarial critic. Challenge the finding and respond "
            "with JSON: {verdict, confidence, counter_hypotheses, "
            "falsification_tests, missing_evidence, summary}."
        )


def _critic_model() -> str:
    """Pick a model for the critic. Default to the light model to keep cost low."""
    # Explicit override
    if os.environ.get("CRITIC_MODEL"):
        return os.environ["CRITIC_MODEL"]
    # Otherwise use the light model from config
    try:
        from modules.config import AI_MODEL_LIGHT
        return AI_MODEL_LIGHT
    except Exception:
        return "claude-haiku-4-5-20251001"


def _parse_verdict_json(text: str) -> dict:
    """Extract the JSON object from the critic's response. Tolerant of fencing."""
    # Find the first balanced {...} block
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        body = fenced.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return {
                "verdict": "needs_more_evidence",
                "confidence": 0.0,
                "counter_hypotheses": [],
                "falsification_tests": [],
                "missing_evidence": ["Critic returned no parseable JSON"],
                "summary": "Critic output unparseable — treat as needs_more_evidence",
                "raw": text[:2000],
            }
        body = text[start:end + 1]

    try:
        obj = json.loads(body)
        # Normalize keys
        obj.setdefault("verdict", "needs_more_evidence")
        obj.setdefault("confidence", 0.0)
        obj.setdefault("counter_hypotheses", [])
        obj.setdefault("falsification_tests", [])
        obj.setdefault("missing_evidence", [])
        obj.setdefault("summary", "")
        if obj["verdict"] not in ("accept", "reject", "needs_more_evidence"):
            obj["verdict"] = "needs_more_evidence"
        return obj
    except json.JSONDecodeError as e:
        return {
            "verdict": "needs_more_evidence",
            "confidence": 0.0,
            "counter_hypotheses": [],
            "falsification_tests": [],
            "missing_evidence": [f"JSON parse error: {e}"],
            "summary": "Critic output JSON-invalid — treat as needs_more_evidence",
            "raw": body[:2000],
        }


def challenge_finding(finding: dict) -> dict:
    """Run the critic against a single finding. Returns the structured verdict.

    Never raises — on any transport error returns a needs_more_evidence stub
    so the caller always gets a usable verdict object.
    """
    try:
        import anthropic
    except ImportError:
        return {
            "verdict": "needs_more_evidence",
            "confidence": 0.0,
            "summary": "anthropic SDK not available",
        }

    try:
        client = anthropic.Anthropic()
        # Keep the finding compact — strip huge response bodies and screenshots
        compact = {
            k: (v if len(json.dumps(v, default=str)) < 4000 else "<truncated>")
            for k, v in finding.items()
            if k not in ("screenshot", "screenshot_data", "raw_response")
        }

        user_msg = (
            "Challenge this finding. Return only the JSON verdict object.\n\n"
            + json.dumps(compact, default=str, indent=2)[:8000]
        )

        resp = client.messages.create(
            model=_critic_model(),
            max_tokens=1500,
            system=_load_prompt(),
            messages=[{"role": "user", "content": user_msg}],
        )

        text_blocks = [
            b.text for b in resp.content if getattr(b, "type", "") == "text"
        ]
        text = "\n".join(text_blocks) if text_blocks else ""
        verdict = _parse_verdict_json(text)
        verdict["model"] = _critic_model()
        return verdict

    except Exception as e:
        log.warning("Critic call failed: %s", e)
        return {
            "verdict": "needs_more_evidence",
            "confidence": 0.0,
            "summary": f"Critic error: {type(e).__name__}",
        }


def critique_all(findings: list[dict], max_findings: int = 20) -> list[dict]:
    """Run the critic over up to `max_findings` findings. Useful pre-report hook.
    Returns a list of {finding_id, verdict...} entries."""
    out = []
    for i, f in enumerate(findings[:max_findings]):
        if not isinstance(f, dict):
            continue
        v = challenge_finding(f)
        v["finding_id"] = f.get("id") or f.get("title") or f"finding_{i}"
        out.append(v)
    return out
