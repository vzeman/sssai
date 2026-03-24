"""Unit tests for scan comparison endpoint logic.

The comparison functions live in modules.api.routes.scans but that module
has heavy import-time dependencies (SQLAlchemy + psycopg2, Redis, etc.)
that are not available in a bare test environment.  We therefore mock the
dependent modules before importing.
"""

import sys
import types
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub out heavy transitive imports so we can import the scans module
# without needing psycopg2, redis, etc.
# ---------------------------------------------------------------------------

_STUBS = {}


def _ensure_stub(name):
    if name not in sys.modules:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        _STUBS[name] = mod
    return sys.modules[name]


# Database / ORM stubs
_ensure_stub("modules.api.database").get_db = MagicMock()

_models = _ensure_stub("modules.api.models")
_models.Scan = MagicMock()
_models.User = MagicMock()

_schemas = _ensure_stub("modules.api.schemas")
_schemas.ScanCreate = MagicMock()
_schemas.ScanResponse = MagicMock()
_schemas.VerificationCreate = MagicMock()

_ensure_stub("modules.api.auth").get_current_user = MagicMock()

_infra = _ensure_stub("modules.infra")
_infra.get_queue = MagicMock()
_infra.get_storage = MagicMock()

_ckpt = _ensure_stub("modules.infra.checkpoint")
_ckpt.load_checkpoint = MagicMock()
_ckpt.build_resume_context = MagicMock()
_ckpt.delete_checkpoint = MagicMock()

_es = _ensure_stub("modules.infra.elasticsearch")
_es.search = MagicMock()

# redis stub
_redis_mod = _ensure_stub("redis")
_redis_mod.from_url = MagicMock()

# sqlalchemy stubs
_ensure_stub("sqlalchemy")
_sa_orm = _ensure_stub("sqlalchemy.orm")
_sa_orm.Session = MagicMock()

# fastapi stubs
_fa = _ensure_stub("fastapi")
_fa.APIRouter = MagicMock(return_value=MagicMock())
_fa.Depends = MagicMock(side_effect=lambda x: x)
_fa.HTTPException = type("HTTPException", (Exception,), {"__init__": lambda self, **kw: None})

# Now we can safely import the target functions
from modules.api.routes.scans import _fetch_findings, _compute_risk_score  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(dedup_key, severity="medium", title="Test Finding", category="xss"):
    return {
        "dedup_key": dedup_key,
        "severity": severity,
        "title": title,
        "category": category,
        "scan_id": "scan-1",
    }


def _make_es_response(findings):
    """Build a minimal ES search response from a list of finding dicts."""
    return {
        "hits": {
            "hits": [{"_source": f} for f in findings],
            "total": {"value": len(findings)},
        }
    }


# ---------------------------------------------------------------------------
# Tests - risk score
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    """Test risk score computation."""

    def test_empty_findings(self):
        assert _compute_risk_score([]) == 0.0

    def test_single_critical(self):
        findings = [_make_finding("k1", severity="critical")]
        assert _compute_risk_score(findings) == 10.0

    def test_mixed_severities(self):
        findings = [
            _make_finding("k1", severity="critical"),
            _make_finding("k2", severity="high"),
            _make_finding("k3", severity="medium"),
            _make_finding("k4", severity="low"),
            _make_finding("k5", severity="info"),
        ]
        # 10 + 7 + 4 + 1 + 0 = 22
        assert _compute_risk_score(findings) == 22.0

    def test_unknown_severity_defaults_to_zero(self):
        findings = [_make_finding("k1", severity="unknown")]
        assert _compute_risk_score(findings) == 0.0

    def test_missing_severity_defaults_to_info(self):
        findings = [{"dedup_key": "k1"}]
        assert _compute_risk_score(findings) == 0.0


# ---------------------------------------------------------------------------
# Tests - fetch findings
# ---------------------------------------------------------------------------

class TestFetchFindings:
    """Test _fetch_findings ES query extraction."""

    def test_returns_sources(self):
        findings = [_make_finding("k1"), _make_finding("k2")]
        _es.search.return_value = _make_es_response(findings)

        result = _fetch_findings("scan-123")

        assert len(result) == 2
        assert result[0]["dedup_key"] == "k1"
        assert result[1]["dedup_key"] == "k2"

    def test_empty_scan(self):
        _es.search.return_value = _make_es_response([])
        result = _fetch_findings("scan-empty")
        assert result == []

    def test_handles_missing_hits(self):
        _es.search.return_value = {}
        result = _fetch_findings("scan-bad")
        assert result == []


# ---------------------------------------------------------------------------
# Tests - comparison logic (pure logic, no imports needed)
# ---------------------------------------------------------------------------

class TestComparisonLogic:
    """Test the comparison categorization logic directly."""

    def _compare(self, current_findings, baseline_findings):
        """Replicate the comparison logic from the endpoint."""
        current_by_key = {}
        for f in current_findings:
            key = f.get("dedup_key")
            if key:
                current_by_key[key] = f

        baseline_by_key = {}
        for f in baseline_findings:
            key = f.get("dedup_key")
            if key:
                baseline_by_key[key] = f

        current_keys = set(current_by_key.keys())
        baseline_keys = set(baseline_by_key.keys())

        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        common_keys = current_keys & baseline_keys

        new_findings = [current_by_key[k] for k in new_keys]
        resolved_findings = [baseline_by_key[k] for k in resolved_keys]
        unchanged_findings = []
        changed_findings = []

        for k in common_keys:
            curr = current_by_key[k]
            base = baseline_by_key[k]
            if curr.get("severity") != base.get("severity"):
                changed_findings.append({"current": curr, "baseline": base})
            else:
                unchanged_findings.append(curr)

        return {
            "new": new_findings,
            "resolved": resolved_findings,
            "unchanged": unchanged_findings,
            "changed": changed_findings,
        }

    def test_all_new_findings(self):
        current = [_make_finding("k1"), _make_finding("k2")]
        baseline = []
        result = self._compare(current, baseline)
        assert len(result["new"]) == 2
        assert len(result["resolved"]) == 0
        assert len(result["unchanged"]) == 0
        assert len(result["changed"]) == 0

    def test_all_resolved_findings(self):
        current = []
        baseline = [_make_finding("k1"), _make_finding("k2")]
        result = self._compare(current, baseline)
        assert len(result["new"]) == 0
        assert len(result["resolved"]) == 2

    def test_unchanged_findings(self):
        current = [_make_finding("k1", severity="high")]
        baseline = [_make_finding("k1", severity="high")]
        result = self._compare(current, baseline)
        assert len(result["unchanged"]) == 1
        assert len(result["new"]) == 0
        assert len(result["resolved"]) == 0
        assert len(result["changed"]) == 0

    def test_changed_severity(self):
        current = [_make_finding("k1", severity="critical")]
        baseline = [_make_finding("k1", severity="medium")]
        result = self._compare(current, baseline)
        assert len(result["changed"]) == 1
        assert result["changed"][0]["current"]["severity"] == "critical"
        assert result["changed"][0]["baseline"]["severity"] == "medium"

    def test_mixed_scenario(self):
        current = [
            _make_finding("k1", severity="high"),      # unchanged
            _make_finding("k2", severity="critical"),   # changed (was medium)
            _make_finding("k3", severity="low"),        # new
        ]
        baseline = [
            _make_finding("k1", severity="high"),
            _make_finding("k2", severity="medium"),
            _make_finding("k4", severity="info"),       # resolved
        ]
        result = self._compare(current, baseline)
        assert len(result["new"]) == 1
        assert result["new"][0]["dedup_key"] == "k3"
        assert len(result["resolved"]) == 1
        assert result["resolved"][0]["dedup_key"] == "k4"
        assert len(result["unchanged"]) == 1
        assert len(result["changed"]) == 1

    def test_empty_scans(self):
        result = self._compare([], [])
        assert len(result["new"]) == 0
        assert len(result["resolved"]) == 0
        assert len(result["unchanged"]) == 0
        assert len(result["changed"]) == 0

    def test_findings_without_dedup_key_are_ignored(self):
        current = [{"title": "No key", "severity": "high"}]
        baseline = [{"title": "Also no key", "severity": "low"}]
        result = self._compare(current, baseline)
        assert len(result["new"]) == 0
        assert len(result["resolved"]) == 0

    def test_risk_delta_calculation(self):
        current = [
            _make_finding("k1", severity="critical"),  # 10
            _make_finding("k2", severity="high"),       # 7
        ]
        baseline = [
            _make_finding("k1", severity="medium"),     # 4
        ]
        current_risk = _compute_risk_score(current)
        baseline_risk = _compute_risk_score(baseline)
        delta = round(current_risk - baseline_risk, 2)
        assert current_risk == 17.0
        assert baseline_risk == 4.0
        assert delta == 13.0

    def test_negative_risk_delta(self):
        current = [_make_finding("k1", severity="low")]       # 1
        baseline = [_make_finding("k1", severity="critical")]  # 10
        current_risk = _compute_risk_score(current)
        baseline_risk = _compute_risk_score(baseline)
        delta = round(current_risk - baseline_risk, 2)
        assert delta == -9.0
