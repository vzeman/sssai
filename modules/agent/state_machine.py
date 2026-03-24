"""
Scan state machine — tracks scan phases and transitions.

States: INIT → PLANNING → DISCOVERY → TESTING → EXPLOITATION → ANALYSIS → REPORTING → COMPLETE
Transitions are logged for audit trail.
"""

from enum import Enum
import time
import json
import logging

log = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    INIT = "init"
    PLANNING = "planning"
    DISCOVERY = "discovery"
    TESTING = "testing"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


# Valid transitions
_TRANSITIONS = {
    ScanPhase.INIT: [ScanPhase.PLANNING],
    ScanPhase.PLANNING: [ScanPhase.DISCOVERY],
    ScanPhase.DISCOVERY: [ScanPhase.TESTING, ScanPhase.PLANNING],
    ScanPhase.TESTING: [ScanPhase.EXPLOITATION, ScanPhase.ANALYSIS, ScanPhase.DISCOVERY],
    ScanPhase.EXPLOITATION: [ScanPhase.ANALYSIS, ScanPhase.TESTING],
    ScanPhase.ANALYSIS: [ScanPhase.REPORTING, ScanPhase.TESTING],
    ScanPhase.REPORTING: [ScanPhase.COMPLETE],
}

# Any state can transition to FAILED
for state in ScanPhase:
    if state not in (ScanPhase.COMPLETE, ScanPhase.FAILED):
        _TRANSITIONS.setdefault(state, []).append(ScanPhase.FAILED)


class ScanStateMachine:
    """Tracks scan phase transitions with audit trail."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.current_phase = ScanPhase.INIT
        self.history: list[dict] = []
        self._record_transition(None, ScanPhase.INIT)

    def transition(self, to_phase: ScanPhase, reason: str = "") -> bool:
        """Attempt a state transition. Returns True if valid."""
        valid_targets = _TRANSITIONS.get(self.current_phase, [])
        if to_phase not in valid_targets:
            log.warning(
                "Scan %s: invalid transition %s → %s (valid: %s)",
                self.scan_id, self.current_phase, to_phase, valid_targets,
            )
            return False
        old = self.current_phase
        self.current_phase = to_phase
        self._record_transition(old, to_phase, reason)
        return True

    def _record_transition(self, from_phase, to_phase, reason: str = ""):
        self.history.append({
            "from": from_phase.value if from_phase else None,
            "to": to_phase.value,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ts": time.time(),
        })

    def infer_phase_from_tool(self, tool_name: str) -> ScanPhase | None:
        """Infer scan phase from tool being used."""
        discovery_tools = {"dns_lookup", "http_request", "web_search", "update_attack_surface"}
        testing_tools = {"run_command", "delegate_to_pentester"}
        analysis_tools = {"compare_results", "exploit_search", "delegate_to_searcher"}
        planning_tools = {"adapt_plan", "load_knowledge"}

        if tool_name in planning_tools:
            return ScanPhase.PLANNING
        if tool_name in discovery_tools:
            return ScanPhase.DISCOVERY
        if tool_name in testing_tools:
            return ScanPhase.TESTING
        if tool_name in analysis_tools:
            return ScanPhase.ANALYSIS
        if tool_name == "report":
            return ScanPhase.REPORTING
        return None

    def try_auto_transition(self, tool_name: str):
        """Auto-transition based on tool usage."""
        target = self.infer_phase_from_tool(tool_name)
        if target and target != self.current_phase:
            self.transition(target, f"auto: tool={tool_name}")

    def summary(self) -> dict:
        return {
            "current_phase": self.current_phase.value,
            "transitions": len(self.history),
            "history": self.history,
        }
