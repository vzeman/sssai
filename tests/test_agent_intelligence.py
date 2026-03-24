"""Tests for agent intelligence features — confidence scoring, phase tracking, scan history."""

import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

# Mock heavy third-party modules that aren't installed in the test environment
_mock_httpx = MagicMock()
_mock_httpx.__version__ = "0.28.0"
sys.modules.setdefault("anthropic", MagicMock())
sys.modules.setdefault("httpx", _mock_httpx)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.agent.scan_agent import (
    _apply_confidence_scores,
    _load_scan_history,
    _record_phase,
    _finalise_phase_timings,
)


# ── Confidence scoring tests ─────────────────────────────────────────────

class TestConfidenceScoring(unittest.TestCase):

    def test_high_confidence_with_all_evidence(self):
        """Finding with evidence, affected_url, CVE, and CVSS should get 1.0."""
        report = {
            "findings": [{
                "title": "SQL Injection",
                "evidence": "' OR 1=1 -- returned all rows",
                "affected_url": "https://example.com/login",
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 1.0)

    def test_medium_confidence_tool_report_only(self):
        """Finding with no evidence, no URL, no CVE, no CVSS gets base 0.5."""
        report = {
            "findings": [{
                "title": "Potential XSS",
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.5)

    def test_partial_evidence_intermediate_score(self):
        """Finding with evidence + URL but no CVE/CVSS gets 0.8."""
        report = {
            "findings": [{
                "title": "Open redirect",
                "evidence": "Redirected to attacker.com",
                "affected_url": "https://example.com/redirect?url=",
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.8)

    def test_preserves_existing_confidence(self):
        """If agent already set a confidence score, it should be kept."""
        report = {
            "findings": [{
                "title": "XSS",
                "confidence": 0.42,
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.42)

    def test_clamps_existing_confidence(self):
        """Existing confidence > 1.0 should be clamped."""
        report = {
            "findings": [{
                "title": "XSS",
                "confidence": 1.5,
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 1.0)

    def test_empty_findings(self):
        """No findings should not raise."""
        report = {"findings": []}
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"], [])

    def test_no_findings_key(self):
        """Missing findings key should not raise."""
        report = {}
        _apply_confidence_scores(report)

    def test_cve_ids_list(self):
        """Finding with cve_ids (list) should get the CVE bonus."""
        report = {
            "findings": [{
                "title": "Known vuln",
                "cve_ids": ["CVE-2024-0001"],
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.6)

    def test_affected_urls_list(self):
        """Finding with affected_urls (plural) should get the URL bonus."""
        report = {
            "findings": [{
                "title": "Info disclosure",
                "affected_urls": ["https://example.com/api/debug"],
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.65)

    def test_empty_evidence_string_no_bonus(self):
        """Empty evidence string should not count."""
        report = {
            "findings": [{
                "title": "Something",
                "evidence": "   ",
            }],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.5)

    def test_multiple_findings(self):
        """Each finding should get its own score independently."""
        report = {
            "findings": [
                {"title": "Low confidence"},
                {"title": "High confidence", "evidence": "proof", "affected_url": "/x",
                 "cve_id": "CVE-2024-1", "cvss_score": 7.5},
            ],
        }
        _apply_confidence_scores(report)
        self.assertEqual(report["findings"][0]["confidence"], 0.5)
        self.assertEqual(report["findings"][1]["confidence"], 1.0)


# ── Phase timing tests ───────────────────────────────────────────────────

class TestPhaseTimings(unittest.TestCase):

    def test_record_single_phase(self):
        ctx = {}
        _record_phase(ctx, "planning")
        self.assertIn("_phase_timings", ctx)
        self.assertIn("planning", ctx["_phase_timings"])
        self.assertEqual(ctx["_current_phase"], "planning")

    def test_phase_transition_closes_previous(self):
        ctx = {}
        _record_phase(ctx, "planning")
        time.sleep(0.15)  # 150ms — enough to show as > 0.0 with 1 decimal
        _record_phase(ctx, "scanning")

        timings = ctx["_phase_timings"]
        self.assertIn("end", timings["planning"])
        self.assertIn("duration_seconds", timings["planning"])
        self.assertGreater(timings["planning"]["duration_seconds"], 0)
        self.assertEqual(ctx["_current_phase"], "scanning")

    def test_finalise_closes_open_phase(self):
        ctx = {}
        _record_phase(ctx, "scanning")
        time.sleep(0.15)
        result = _finalise_phase_timings(ctx)

        self.assertIn("scanning", result)
        self.assertGreater(result["scanning"], 0)

    def test_finalise_multiple_phases(self):
        ctx = {}
        _record_phase(ctx, "planning")
        time.sleep(0.05)
        _record_phase(ctx, "scanning")
        time.sleep(0.05)
        _record_phase(ctx, "reporting")
        time.sleep(0.05)

        result = _finalise_phase_timings(ctx)
        self.assertEqual(set(result.keys()), {"planning", "scanning", "reporting"})
        for duration in result.values():
            self.assertGreaterEqual(duration, 0)

    def test_finalise_empty_context(self):
        ctx = {}
        result = _finalise_phase_timings(ctx)
        self.assertEqual(result, {})


# ── Scan history learning tests ──────────────────────────────────────────

class TestScanHistory(unittest.TestCase):

    def _mock_es_search(self, return_value):
        """Helper to patch the search function inside _load_scan_history."""
        return patch.dict("sys.modules", {
            "modules.infra.elasticsearch": MagicMock(search=MagicMock(return_value=return_value)),
        })

    @patch("modules.agent.scan_agent.log")
    def test_returns_none_when_no_hits(self, mock_log):
        """When ES returns no hits, should return None."""
        mock_es = MagicMock()
        mock_es.search.return_value = {
            "hits": {"hits": [], "total": {"value": 0}},
        }
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": mock_es}):
            result = _load_scan_history("example.com")
        self.assertIsNone(result)

    @patch("modules.agent.scan_agent.log")
    def test_formats_history_from_es_hits(self, mock_log):
        """Should format ES hits into a readable summary."""
        mock_hits = {
            "hits": {
                "hits": [
                    {"_source": {
                        "scan_id": "scan-aaa-111",
                        "timestamp": "2026-03-20T10:00:00Z",
                        "severity": "high",
                        "category": "injection",
                        "title": "SQL Injection in /login",
                    }},
                    {"_source": {
                        "scan_id": "scan-aaa-111",
                        "timestamp": "2026-03-20T10:00:00Z",
                        "severity": "medium",
                        "category": "xss",
                        "title": "Reflected XSS in /search",
                    }},
                    {"_source": {
                        "scan_id": "scan-bbb-222",
                        "timestamp": "2026-03-15T10:00:00Z",
                        "severity": "low",
                        "category": "info_disclosure",
                        "title": "Server version exposed",
                    }},
                ],
                "total": {"value": 3},
            },
        }
        mock_es = MagicMock()
        mock_es.search.return_value = mock_hits
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": mock_es}):
            result = _load_scan_history("example.com")

        self.assertIsNotNone(result)
        self.assertIn("Previous Scan History", result)
        self.assertIn("scan-aaa", result)
        self.assertIn("scan-bbb", result)
        self.assertIn("SQL Injection", result)
        self.assertIn("injection", result)

    @patch("modules.agent.scan_agent.log")
    def test_limits_to_3_scans(self, mock_log):
        """Should only include at most 3 scan IDs."""
        hits = []
        for i in range(4):
            hits.append({"_source": {
                "scan_id": f"scan-{i:03d}",
                "timestamp": f"2026-03-{20 - i}T10:00:00Z",
                "severity": "medium",
                "category": "misc",
                "title": f"Finding {i}",
            }})

        mock_es = MagicMock()
        mock_es.search.return_value = {
            "hits": {"hits": hits, "total": {"value": 4}},
        }
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": mock_es}):
            result = _load_scan_history("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(result.count("### Scan"), 3)

    @patch("modules.agent.scan_agent.log")
    def test_graceful_on_exception(self, mock_log):
        """Should return None on ES exception."""
        mock_es = MagicMock()
        mock_es.search.side_effect = Exception("ES connection refused")
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": mock_es}):
            result = _load_scan_history("example.com")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
