"""
Central configuration for AI model selection.

Set via environment variables:
  AI_MODEL        — primary model for scans and chat (default: claude-haiku-4-5-20251001)
  AI_MODEL_LIGHT  — lightweight model for heartbeat, monitors, summaries (default: claude-haiku-4-5-20251001)

Examples:
  AI_MODEL=claude-sonnet-4-20250514      # use Sonnet for scans
  AI_MODEL=claude-opus-4-20250514        # use Opus for scans
  AI_MODEL=claude-haiku-4-5-20251001     # use Haiku for scans (cheapest)
"""

import os

# Primary model — used for scan agent, chat, sub-agents
AI_MODEL = os.environ.get("AI_MODEL", "claude-haiku-4-5-20251001")

# Light model — used for heartbeat summaries, execution monitor, chain summarization
AI_MODEL_LIGHT = os.environ.get("AI_MODEL_LIGHT", "claude-haiku-4-5-20251001")

# Cost per 1M tokens (updated automatically based on model)
_PRICING = {
    "claude-opus-4-20250514":     (15.00, 75.00),
    "claude-sonnet-4-20250514":   (3.00, 15.00),
    "claude-haiku-4-5-20251001":  (0.80, 4.00),
}


def get_cost_per_1m(model: str | None = None) -> tuple[float, float]:
    """Return (input_cost, output_cost) per 1M tokens for the given model."""
    m = model or AI_MODEL
    # Match by prefix for flexibility
    for key, costs in _PRICING.items():
        if m.startswith(key.rsplit("-", 1)[0]):
            return costs
    # Default to Haiku pricing
    return (0.80, 4.00)
