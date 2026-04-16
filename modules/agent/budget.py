"""
Scan budget tracking and enforcement (Issue #172).

Replaces pure iteration-based stopping with a multi-axis budget:
  - Input + output tokens (cumulative across all model calls in a scan)
  - Estimated USD cost
  - Wall-clock duration (seconds)
  - Iteration cap (kept as a high ceiling for safety)

The main loop checks `budget.status()` before each iteration. At 80%
consumption the agent is nudged to wrap up; at 100% the loop force-calls
`report` with current findings.

Per-scan-type defaults allow `quick` scans a modest budget and `full`
scans a large one. Individual scans may override via the scan config.
"""

import os
import time
from dataclasses import dataclass, field, asdict
from typing import Literal

BudgetStatus = Literal["ok", "warn_80", "exhausted"]

# Per-1M-token pricing per model family. Keys match the start of the model id.
_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4":   (15.00, 75.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-haiku-4":  (0.80, 4.00),
}


def _cost_for_model(model: str) -> tuple[float, float]:
    for key, costs in _PRICING.items():
        if model.startswith(key):
            return costs
    return (0.80, 4.00)


# ── Default budgets by scan type ───────────────────────────────────────────
# Values are environment-overridable so operators can tune without code changes.
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


DEFAULT_BUDGETS: dict[str, dict] = {
    "quick": {
        "max_input_tokens":  _env_int("BUDGET_QUICK_TOKENS", 150_000),
        "max_output_tokens": _env_int("BUDGET_QUICK_OUTPUT_TOKENS", 40_000),
        "max_usd_cost":      _env_float("BUDGET_QUICK_USD", 0.50),
        "max_duration_seconds": _env_int("BUDGET_QUICK_DURATION", 900),
        "max_iterations":    _env_int("BUDGET_QUICK_ITERATIONS", 60),
    },
    "security": {
        "max_input_tokens":  _env_int("BUDGET_SECURITY_TOKENS", 500_000),
        "max_output_tokens": _env_int("BUDGET_SECURITY_OUTPUT_TOKENS", 120_000),
        "max_usd_cost":      _env_float("BUDGET_SECURITY_USD", 2.00),
        "max_duration_seconds": _env_int("BUDGET_SECURITY_DURATION", 3600),
        "max_iterations":    _env_int("BUDGET_SECURITY_ITERATIONS", 300),
    },
    "pentest": {
        "max_input_tokens":  _env_int("BUDGET_PENTEST_TOKENS", 1_000_000),
        "max_output_tokens": _env_int("BUDGET_PENTEST_OUTPUT_TOKENS", 250_000),
        "max_usd_cost":      _env_float("BUDGET_PENTEST_USD", 5.00),
        "max_duration_seconds": _env_int("BUDGET_PENTEST_DURATION", 7200),
        "max_iterations":    _env_int("BUDGET_PENTEST_ITERATIONS", 500),
    },
    "full": {
        "max_input_tokens":  _env_int("BUDGET_FULL_TOKENS", 2_000_000),
        "max_output_tokens": _env_int("BUDGET_FULL_OUTPUT_TOKENS", 500_000),
        "max_usd_cost":      _env_float("BUDGET_FULL_USD", 10.00),
        "max_duration_seconds": _env_int("BUDGET_FULL_DURATION", 14400),
        "max_iterations":    _env_int("BUDGET_FULL_ITERATIONS", 500),
    },
}

# Safety ceiling — regardless of scan-type budget, never loop past this.
HARD_ITERATION_CEILING = _env_int("BUDGET_HARD_ITERATION_CEILING", 500)


@dataclass
class ScanBudget:
    """Tracks cumulative consumption against configured limits."""

    max_input_tokens: int = 500_000
    max_output_tokens: int = 120_000
    max_usd_cost: float = 2.00
    max_duration_seconds: int = 3600
    max_iterations: int = 300

    # Consumed
    input_tokens: int = 0
    output_tokens: int = 0
    usd_cost: float = 0.0
    iterations: int = 0
    started_at: float = field(default_factory=time.time)

    # 80% warning only fires once
    _warned_80: bool = False

    @classmethod
    def for_scan_type(cls, scan_type: str, overrides: dict | None = None) -> "ScanBudget":
        base = DEFAULT_BUDGETS.get(scan_type, DEFAULT_BUDGETS["security"])
        merged = dict(base)
        if overrides:
            for k, v in overrides.items():
                if k in merged and v is not None:
                    merged[k] = v
        return cls(**merged)

    def record(self, input_tokens: int, output_tokens: int, model: str) -> None:
        """Record one model-call's consumption and update cost estimate."""
        self.input_tokens += max(0, int(input_tokens or 0))
        self.output_tokens += max(0, int(output_tokens or 0))
        inp_1m, out_1m = _cost_for_model(model)
        self.usd_cost += (input_tokens or 0) * inp_1m / 1_000_000
        self.usd_cost += (output_tokens or 0) * out_1m / 1_000_000

    def record_iteration(self) -> None:
        self.iterations += 1

    # ── Status checks ──────────────────────────────────────────────────────
    def fractions(self) -> dict[str, float]:
        dur = time.time() - self.started_at
        return {
            "input_tokens":     self.input_tokens / max(1, self.max_input_tokens),
            "output_tokens":    self.output_tokens / max(1, self.max_output_tokens),
            "usd_cost":         self.usd_cost / max(0.001, self.max_usd_cost),
            "duration_seconds": dur / max(1, self.max_duration_seconds),
            "iterations":       self.iterations / max(1, self.max_iterations),
        }

    def status(self) -> BudgetStatus:
        f = self.fractions()
        if any(v >= 1.0 for v in f.values()):
            return "exhausted"
        if self.iterations >= HARD_ITERATION_CEILING:
            return "exhausted"
        if any(v >= 0.80 for v in f.values()):
            return "warn_80"
        return "ok"

    def should_warn_once(self) -> bool:
        """Return True exactly once when we first cross 80%, else False."""
        if self.status() == "warn_80" and not self._warned_80:
            self._warned_80 = True
            return True
        return False

    def summary(self) -> dict:
        f = self.fractions()
        return {
            "input_tokens":      {"used": self.input_tokens, "limit": self.max_input_tokens, "fraction": round(f["input_tokens"], 3)},
            "output_tokens":     {"used": self.output_tokens, "limit": self.max_output_tokens, "fraction": round(f["output_tokens"], 3)},
            "usd_cost":          {"used": round(self.usd_cost, 4), "limit": self.max_usd_cost, "fraction": round(f["usd_cost"], 3)},
            "duration_seconds":  {"used": round(time.time() - self.started_at, 1), "limit": self.max_duration_seconds, "fraction": round(f["duration_seconds"], 3)},
            "iterations":        {"used": self.iterations, "limit": self.max_iterations, "fraction": round(f["iterations"], 3)},
            "status":            self.status(),
        }

    def most_consumed(self) -> str:
        f = self.fractions()
        return max(f.items(), key=lambda kv: kv[1])[0]
