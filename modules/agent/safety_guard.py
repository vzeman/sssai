"""
Safety guard for exploitation payload validation.

Blocks destructive patterns before they reach the sandbox executor.
Prevents accidental damage to targets during automated exploitation.
"""

import logging
import re
from urllib.parse import unquote

from modules.agent.exploitation_engine import ExploitType

log = logging.getLogger(__name__)

# Destructive SQL patterns — these modify or destroy data
_SQL_DESTRUCTIVE = [
    r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b",
    r"\bDELETE\s+FROM\b",
    r"\bTRUNCATE\s+",
    r"\bALTER\s+TABLE\b",
    r"\bUPDATE\s+\S+\s+SET\b",
    r"\bINSERT\s+INTO\b",
    r"\bCREATE\s+USER\b",
    r"\bGRANT\s+",
    r"\bSHUTDOWN\b",
]

# Destructive filesystem / OS patterns
_OS_DESTRUCTIVE = [
    r"\brm\s+-rf\b",
    r"\brm\s+-fr\b",
    r"\brm\s+--no-preserve-root\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bformat\s+[a-zA-Z]:",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bhalt\b",
    r"\binit\s+0\b",
    r"\bkill\s+-9\s+-1\b",
    r"\bkillall\b",
]

# Fork bombs and denial-of-service patterns
_DOS_PATTERNS = [
    r":\(\)\{.*:\|:.*\}",          # Bash fork bomb  :(){ :|:& };:
    r"\bfork\s*\(\s*\)\s*while\b",
    r"\bwhile\s+true.*do.*fork\b",
    r"import\s+os.*os\.fork",
    r"\bstress\b",
    r"\b/dev/zero\b",
    r"\b/dev/urandom\b.*>\s*/dev/",
]

# Network destructive patterns
_NETWORK_DESTRUCTIVE = [
    r"\biptables\s+-F\b",
    r"\biptables\s+--flush\b",
    r"\bnc\s+-l\b.*\bsh\b",       # Reverse shell listeners
    r"\bbash\s+-i\s+>&\s*/dev/tcp",
]


class SafetyGuard:
    """Validates exploitation payloads before execution.

    Blocks destructive patterns that could cause damage to targets
    such as DROP TABLE, rm -rf, fork bombs, etc.
    """

    def __init__(self):
        self._sql_patterns = [re.compile(p, re.IGNORECASE) for p in _SQL_DESTRUCTIVE]
        self._os_patterns = [re.compile(p, re.IGNORECASE) for p in _OS_DESTRUCTIVE]
        self._dos_patterns = [re.compile(p, re.IGNORECASE) for p in _DOS_PATTERNS]
        self._net_patterns = [re.compile(p, re.IGNORECASE) for p in _NETWORK_DESTRUCTIVE]

    def validate_payload(
        self, payload: str, exploit_type: ExploitType
    ) -> tuple[bool, str]:
        """Validate a payload before execution.

        Returns:
            (is_safe, reason) — True if safe to execute, or (False, reason) if blocked.
        """
        if not payload:
            return True, ""

        # Decode URL-encoded and hex-encoded payloads to prevent bypass
        decoded = unquote(payload)
        # Also handle double-encoding
        decoded = unquote(decoded)
        # Check both original and decoded forms
        check_payloads = {payload, decoded}

        for p in check_payloads:
            result = self._check_patterns(p)
            if result is not None:
                return result
        return True, ""

    def _check_patterns(self, payload: str) -> tuple[bool, str] | None:
        """Check a single payload string against all patterns. Returns (False, reason) if blocked, None if clean."""
        # Check SQL destructive patterns
        for pattern in self._sql_patterns:
            if pattern.search(payload):
                return False, f"Destructive SQL pattern detected: {pattern.pattern}"

        # Check OS destructive patterns
        for pattern in self._os_patterns:
            if pattern.search(payload):
                return False, f"Destructive OS command detected: {pattern.pattern}"

        # Check fork bombs / DoS patterns
        for pattern in self._dos_patterns:
            if pattern.search(payload):
                return False, f"Denial-of-service pattern detected: {pattern.pattern}"

        # Check network destructive patterns
        for pattern in self._net_patterns:
            if pattern.search(payload):
                return False, f"Destructive network pattern detected: {pattern.pattern}"

        return None


# Module-level singleton — avoids re-compiling 25 regexes on every call
_guard_instance: SafetyGuard | None = None


def get_safety_guard() -> SafetyGuard:
    """Return the module-level SafetyGuard singleton."""
    global _guard_instance
    if _guard_instance is None:
        _guard_instance = SafetyGuard()
    return _guard_instance
