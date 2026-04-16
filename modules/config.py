"""
Central configuration for AI model selection and agent feature flags.

Tier system (Issue #171):
  AI_MODEL_DISCOVERY  — routine tool dispatch, discovery, HTTP parsing (fast/cheap)
  AI_MODEL_REASONING  — adapt_plan, exploitation decisions, attack-chain analysis
  AI_MODEL_CRITICAL   — opt-in high-stakes scans (most capable model)
  AI_MODEL_LIGHT      — heartbeat, monitors, summaries

Back-compat:
  AI_MODEL            — alias for AI_MODEL_DISCOVERY (old single-model config)

Extended thinking:
  EXTENDED_THINKING_BUDGET  — thinking token budget on Sonnet/Opus calls (0 disables)
  Haiku models do NOT support extended thinking and skip the thinking block.

Feature flags:
  USE_AUTONOMOUS_AGENT — state-machine scan entry point in
                          modules/agent/autonomous_agent.py. Default false —
                          reserved for #173 migration (not currently wired).

Environment overrides:
  AI_MODEL_DISCOVERY=claude-haiku-4-5-20251001
  AI_MODEL_REASONING=claude-sonnet-4-6
  AI_MODEL_CRITICAL=claude-opus-4-6
  EXTENDED_THINKING_BUDGET=8000
"""

import os

# Discovery tier — fast and cheap; used for routine tool dispatch
AI_MODEL_DISCOVERY = os.environ.get("AI_MODEL_DISCOVERY") or os.environ.get(
    "AI_MODEL", "claude-haiku-4-5-20251001"
)

# Reasoning tier — used for adapt_plan, exploitation decisions, critic, attack chains
AI_MODEL_REASONING = os.environ.get("AI_MODEL_REASONING", "claude-sonnet-4-6")

# Critical tier — opt-in for highest-stakes scans
AI_MODEL_CRITICAL = os.environ.get("AI_MODEL_CRITICAL", "claude-opus-4-6")

# Light tier — heartbeat, monitors, summaries
AI_MODEL_LIGHT = os.environ.get("AI_MODEL_LIGHT", "claude-haiku-4-5-20251001")

# Back-compat alias
AI_MODEL = AI_MODEL_DISCOVERY

# Extended thinking budget (tokens). Default 0 = disabled.
# Enabling thinking on every main-loop turn with high budget triggers
# multi-minute turn latency on Sonnet 4.6 — avoid that unless the target
# justifies the spend. Recommended values when enabled: 2000-4000 tokens.
# Set to 8000+ only for heavy reasoning-intensive one-off runs.
EXTENDED_THINKING_BUDGET = int(os.environ.get("EXTENDED_THINKING_BUDGET", "0"))

# Feature flag for the state-machine agent (Issue #173) — NOT yet wired into
# the worker. Reserved for the future migration from while-loop to state
# machine. Leave false unless you are actively working on that migration.
USE_AUTONOMOUS_AGENT = os.environ.get("USE_AUTONOMOUS_AGENT", "false").lower() in (
    "1", "true", "yes", "on",
)

# Cost per 1M tokens: (input_cost, output_cost)
_PRICING = {
    "claude-opus-4-6":            (15.00, 75.00),
    "claude-opus-4-20250514":     (15.00, 75.00),
    "claude-sonnet-4-6":          (3.00, 15.00),
    "claude-sonnet-4-20250514":   (3.00, 15.00),
    "claude-haiku-4-5-20251001":  (0.80, 4.00),
}

# Model families that support extended thinking
_THINKING_CAPABLE_PREFIXES = ("claude-opus-4", "claude-sonnet-4")


def get_cost_per_1m(model: str | None = None) -> tuple[float, float]:
    """Return (input_cost, output_cost) per 1M tokens for the given model."""
    m = model or AI_MODEL_DISCOVERY
    if m in _PRICING:
        return _PRICING[m]
    for key, costs in _PRICING.items():
        if m.startswith(key.rsplit("-", 1)[0]):
            return costs
    return (0.80, 4.00)


def supports_thinking(model: str | None = None) -> bool:
    """Return True if the model supports the extended thinking block."""
    m = model or AI_MODEL_DISCOVERY
    return any(m.startswith(p) for p in _THINKING_CAPABLE_PREFIXES)


def thinking_param(model: str | None = None, budget: int | None = None) -> dict | None:
    """Return a `thinking={...}` kwarg dict for client.messages.create, or None to omit.

    Use as: `**({"thinking": thinking_param(model)} if thinking_param(model) else {})`
    """
    m = model or AI_MODEL_DISCOVERY
    b = budget if budget is not None else EXTENDED_THINKING_BUDGET
    if b <= 0 or not supports_thinking(m):
        return None
    return {"type": "enabled", "budget_tokens": b}
