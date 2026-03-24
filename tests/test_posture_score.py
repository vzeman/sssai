"""Comprehensive tests for modules.agent.posture_score.

Covers severity penalties, CVSS factors, age penalties, attack chain
penalties, score calculation, trend computation, remediation velocity,
and commentary generation.
"""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from modules.agent.posture_score import (
    _severity_base_penalty,
    _cvss_factor,
    _age_penalty,
    _attack_chain_penalty,
    _remediation_velocity_bonus,
    _compute_trend,
    calculate_posture_score,
    generate_posture_commentary,
    _fallback_commentary,
    _try_parse_forecast_date,
)


class TestSeverityBasePenalty(unittest.TestCase):
    """Tests for _severity_base_penalty."""

    def test_empty_findings(self):
        self.assertEqual(_severity_base_penalty([]), 0.0)

    def test_single_critical(self):
        findings = [{"severity": "critical"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 25.0)

    def test_single_high(self):
        findings = [{"severity": "high"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 10.0)

    def test_single_medium(self):
        findings = [{"severity": "medium"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 4.0)

    def test_single_low(self):
        findings = [{"severity": "low"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 1.5)

    def test_single_info(self):
        findings = [{"severity": "info"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 0.3)

    def test_multiple_mixed(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        expected = 25.0 + 10.0 + 4.0 + 1.5 + 0.3
        self.assertAlmostEqual(_severity_base_penalty(findings), expected)

    def test_unknown_severity_defaults_to_info(self):
        findings = [{"severity": "unknown_value"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 0.3)

    def test_none_severity_defaults_to_info(self):
        findings = [{"severity": None}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 0.3)

    def test_missing_severity_defaults_to_info(self):
        findings = [{}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 0.3)

    def test_case_insensitive(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "High"}]
        self.assertAlmostEqual(_severity_base_penalty(findings), 35.0)


class TestCvssFactor(unittest.TestCase):
    """Tests for _cvss_factor."""

    def test_no_findings(self):
        self.assertEqual(_cvss_factor([]), 0.0)

    def test_no_cvss_scores(self):
        findings = [{"severity": "high"}]
        self.assertEqual(_cvss_factor(findings), 0.0)

    def test_critical_cvss_gte_9(self):
        findings = [{"cvss_score": 9.0}]
        self.assertAlmostEqual(_cvss_factor(findings), 5.0)

    def test_critical_cvss_10(self):
        findings = [{"cvss_score": 10.0}]
        self.assertAlmostEqual(_cvss_factor(findings), 5.0)

    def test_high_cvss_gte_7(self):
        findings = [{"cvss_score": 7.0}]
        self.assertAlmostEqual(_cvss_factor(findings), 2.0)

    def test_high_cvss_8_5(self):
        findings = [{"cvss_score": 8.5}]
        self.assertAlmostEqual(_cvss_factor(findings), 2.0)

    def test_low_cvss_below_7(self):
        findings = [{"cvss_score": 6.9}]
        self.assertEqual(_cvss_factor(findings), 0.0)

    def test_zero_cvss(self):
        findings = [{"cvss_score": 0.0}]
        self.assertEqual(_cvss_factor(findings), 0.0)

    def test_multiple_mixed_cvss(self):
        findings = [
            {"cvss_score": 9.5},   # +5.0
            {"cvss_score": 7.5},   # +2.0
            {"cvss_score": 3.0},   # +0.0
        ]
        self.assertAlmostEqual(_cvss_factor(findings), 7.0)

    def test_none_cvss_treated_as_zero(self):
        findings = [{"cvss_score": None}]
        self.assertEqual(_cvss_factor(findings), 0.0)


class TestAgePenalty(unittest.TestCase):
    """Tests for _age_penalty."""

    def setUp(self):
        self.now = datetime(2026, 3, 24, 12, 0, 0, tzinfo=timezone.utc)

    def test_no_findings(self):
        self.assertEqual(_age_penalty([], self.now), 0.0)

    def test_no_timestamps(self):
        findings = [{"severity": "critical"}]
        self.assertEqual(_age_penalty(findings, self.now), 0.0)

    def test_critical_finding_100_days_old(self):
        ts = (self.now - timedelta(days=100)).isoformat()
        findings = [{"severity": "critical", "timestamp": ts}]
        # base=25.0, age>=90 days -> penalty = 25.0 * 1.0 = 25.0
        self.assertAlmostEqual(_age_penalty(findings, self.now), 25.0)

    def test_high_finding_45_days_old(self):
        ts = (self.now - timedelta(days=45)).isoformat()
        findings = [{"severity": "high", "timestamp": ts}]
        # base=10.0, age>=30 days -> penalty = 10.0 * 0.5 = 5.0
        self.assertAlmostEqual(_age_penalty(findings, self.now), 5.0)

    def test_recent_finding_no_penalty(self):
        ts = (self.now - timedelta(days=10)).isoformat()
        findings = [{"severity": "critical", "timestamp": ts}]
        self.assertEqual(_age_penalty(findings, self.now), 0.0)

    def test_iso_timestamp_with_z_suffix(self):
        ts = (self.now - timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        findings = [{"severity": "high", "timestamp": ts}]
        # base=10.0, age>=90 -> 10.0 * 1.0 = 10.0
        self.assertAlmostEqual(_age_penalty(findings, self.now), 10.0)

    def test_invalid_timestamp_skipped(self):
        findings = [{"severity": "critical", "timestamp": "not-a-date"}]
        self.assertEqual(_age_penalty(findings, self.now), 0.0)

    def test_first_seen_field_used(self):
        ts = (self.now - timedelta(days=45)).isoformat()
        findings = [{"severity": "medium", "first_seen": ts}]
        # base=4.0, age>=30 -> 4.0 * 0.5 = 2.0
        self.assertAlmostEqual(_age_penalty(findings, self.now), 2.0)

    def test_datetime_object_timestamp(self):
        ts = self.now - timedelta(days=100)
        findings = [{"severity": "low", "timestamp": ts}]
        # base=1.5, age>=90 -> 1.5 * 1.0 = 1.5
        self.assertAlmostEqual(_age_penalty(findings, self.now), 1.5)

    def test_naive_datetime_gets_utc(self):
        ts = datetime(2025, 12, 14, 12, 0, 0)  # naive, ~100 days before self.now
        findings = [{"severity": "info", "timestamp": ts}]
        # base=0.3, age>=90 -> 0.3 * 1.0 = 0.3
        self.assertAlmostEqual(_age_penalty(findings, self.now), 0.3)


class TestAttackChainPenalty(unittest.TestCase):
    """Tests for _attack_chain_penalty."""

    def test_zero_high_critical(self):
        findings = [{"severity": "low"}, {"severity": "medium"}]
        self.assertEqual(_attack_chain_penalty(findings), 0.0)

    def test_one_high_critical(self):
        findings = [{"severity": "critical"}]
        self.assertEqual(_attack_chain_penalty(findings), 0.0)

    def test_two_high_critical(self):
        findings = [{"severity": "critical"}, {"severity": "high"}]
        self.assertAlmostEqual(_attack_chain_penalty(findings), 4.0)

    def test_three_high_critical(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
        ]
        self.assertAlmostEqual(_attack_chain_penalty(findings), 8.0)

    def test_four_high_critical(self):
        findings = [{"severity": "critical"}] * 4
        self.assertAlmostEqual(_attack_chain_penalty(findings), 8.0)

    def test_five_plus_high_critical(self):
        findings = [{"severity": "high"}] * 5
        self.assertAlmostEqual(_attack_chain_penalty(findings), 15.0)

    def test_six_high_critical(self):
        findings = [{"severity": "critical"}] * 6
        self.assertAlmostEqual(_attack_chain_penalty(findings), 15.0)

    def test_empty(self):
        self.assertEqual(_attack_chain_penalty([]), 0.0)

    def test_mixed_non_high_critical_ignored(self):
        findings = [
            {"severity": "critical"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        # Only 1 high/critical -> 0
        self.assertEqual(_attack_chain_penalty(findings), 0.0)


class TestCalculatePostureScore(unittest.TestCase):
    """Tests for calculate_posture_score."""

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_no_findings_score_near_100(self, mock_vel, mock_trend):
        result = calculate_posture_score("scan-1", "example.com", "user-1", [], None)
        self.assertEqual(result["posture_score"], 100.0)
        self.assertEqual(result["finding_counts"]["total"], 0)

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_all_critical_findings_score_near_zero(self, mock_vel, mock_trend):
        findings = [{"severity": "critical"}] * 5
        result = calculate_posture_score("scan-2", "example.com", "user-1", findings, None)
        # base penalty = 5*25=125, chain=15 -> total=140, score=max(0, 100-140)=0
        self.assertEqual(result["posture_score"], 0.0)
        self.assertEqual(result["finding_counts"]["critical"], 5)

    @patch("modules.agent.posture_score._compute_trend", return_value=("improving", 5.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_mixed_findings_reasonable_score(self, mock_vel, mock_trend):
        findings = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
        result = calculate_posture_score("scan-3", "example.com", "user-1", findings, None)
        # base=10+4+1.5=15.5, cvss=0, age=0, chain=0 -> score=84.5
        self.assertAlmostEqual(result["posture_score"], 84.5)

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_with_scan_risk_score(self, mock_vel, mock_trend):
        findings = [{"severity": "medium"}]
        result = calculate_posture_score("scan-4", "example.com", "user-1", findings, 50.0)
        # base=4.0, risk_penalty=50*0.3=15.0 -> total=19.0 -> score=81.0
        self.assertAlmostEqual(result["posture_score"], 81.0)

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_without_scan_risk_score_no_risk_penalty(self, mock_vel, mock_trend):
        findings = [{"severity": "medium"}]
        result = calculate_posture_score("scan-5", "example.com", "user-1", findings, None)
        self.assertEqual(result["components"]["risk_penalty"], 0.0)

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_return_structure(self, mock_vel, mock_trend):
        result = calculate_posture_score("scan-6", "target.io", "uid-1", [], None)
        self.assertIn("timestamp", result)
        self.assertEqual(result["scan_id"], "scan-6")
        self.assertEqual(result["target"], "target.io")
        self.assertEqual(result["user_id"], "uid-1")
        self.assertIn("posture_score", result)
        self.assertIn("trend", result)
        self.assertIn("trend_delta", result)
        self.assertIn("components", result)
        self.assertIn("finding_counts", result)
        self.assertIn("commentary", result)
        self.assertIn("forecast", result)
        self.assertIn("forecast_date", result)

    @patch("modules.agent.posture_score._compute_trend", return_value=("stable", 0.0))
    @patch("modules.agent.posture_score._remediation_velocity_bonus", return_value=0.0)
    def test_finding_counts_correct(self, mock_vel, mock_trend):
        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
            {"severity": "unknown"},  # counted as info
        ]
        result = calculate_posture_score("scan-7", "t.com", "u-1", findings, None)
        counts = result["finding_counts"]
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)
        self.assertEqual(counts["info"], 2)  # info + unknown
        self.assertEqual(counts["total"], 7)


class TestComputeTrend(unittest.TestCase):
    """Tests for _compute_trend with mocked ES."""

    def test_exception_returns_stable(self):
        with patch("modules.infra.elasticsearch.search", side_effect=Exception("no ES")):
            trend, delta = _compute_trend("target", "user", 80.0)
            self.assertEqual(trend, "stable")
            self.assertEqual(delta, 0.0)

    def test_import_failure_returns_stable(self):
        # If elasticsearch module not available at all
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": None}):
            trend, delta = _compute_trend("target", "user", 80.0)
            self.assertEqual(trend, "stable")
            self.assertEqual(delta, 0.0)

    @patch("modules.infra.elasticsearch.search")
    def test_no_hits_returns_stable(self, mock_search):
        mock_search.return_value = {"hits": {"hits": []}}
        trend, delta = _compute_trend("target", "user", 80.0)
        self.assertEqual(trend, "stable")
        self.assertEqual(delta, 0.0)

    @patch("modules.infra.elasticsearch.search")
    def test_improving_trend(self, mock_search):
        mock_search.return_value = {
            "hits": {"hits": [{"_source": {"posture_score": 70.0}}]}
        }
        trend, delta = _compute_trend("target", "user", 80.0)
        self.assertEqual(trend, "improving")
        self.assertAlmostEqual(delta, 10.0)

    @patch("modules.infra.elasticsearch.search")
    def test_degrading_trend(self, mock_search):
        mock_search.return_value = {
            "hits": {"hits": [{"_source": {"posture_score": 90.0}}]}
        }
        trend, delta = _compute_trend("target", "user", 80.0)
        self.assertEqual(trend, "degrading")
        self.assertAlmostEqual(delta, -10.0)

    @patch("modules.infra.elasticsearch.search")
    def test_stable_within_threshold(self, mock_search):
        mock_search.return_value = {
            "hits": {"hits": [{"_source": {"posture_score": 79.0}}]}
        }
        trend, delta = _compute_trend("target", "user", 80.0)
        self.assertEqual(trend, "stable")
        self.assertAlmostEqual(delta, 1.0)


class TestRemediationVelocityBonus(unittest.TestCase):
    """Tests for _remediation_velocity_bonus with mocked ES."""

    def test_exception_returns_zero(self):
        with patch.dict("sys.modules", {"modules.infra.elasticsearch": None}):
            bonus = _remediation_velocity_bonus("target", "user", 5)
            self.assertEqual(bonus, 0.0)

    @patch("modules.infra.elasticsearch.search")
    def test_no_hits_returns_zero(self, mock_search):
        mock_search.return_value = {"hits": {"hits": []}}
        bonus = _remediation_velocity_bonus("target", "user", 5)
        self.assertEqual(bonus, 0.0)

    @patch("modules.infra.elasticsearch.search")
    def test_zero_previous_avg_returns_5(self, mock_search):
        mock_search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"finding_counts": {"total": 0}}},
                ]
            }
        }
        bonus = _remediation_velocity_bonus("target", "user", 0)
        self.assertAlmostEqual(bonus, 5.0)

    @patch("modules.infra.elasticsearch.search")
    def test_full_reduction_gives_10(self, mock_search):
        mock_search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"finding_counts": {"total": 10}}},
                    {"_source": {"finding_counts": {"total": 10}}},
                ]
            }
        }
        # current_count=0, avg_prev=10, reduction=100% -> bonus=10.0
        bonus = _remediation_velocity_bonus("target", "user", 0)
        self.assertAlmostEqual(bonus, 10.0)

    @patch("modules.infra.elasticsearch.search")
    def test_partial_reduction(self, mock_search):
        mock_search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"finding_counts": {"total": 20}}},
                ]
            }
        }
        # current_count=10, avg_prev=20, reduction=50% -> bonus=5.0
        bonus = _remediation_velocity_bonus("target", "user", 10)
        self.assertAlmostEqual(bonus, 5.0)

    @patch("modules.infra.elasticsearch.search")
    def test_no_reduction_gives_zero(self, mock_search):
        mock_search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"finding_counts": {"total": 5}}},
                ]
            }
        }
        # current_count=10, avg_prev=5, reduction=negative -> max(0,neg)=0 -> 0
        bonus = _remediation_velocity_bonus("target", "user", 10)
        self.assertAlmostEqual(bonus, 0.0)


class TestGeneratePostureCommentary(unittest.TestCase):
    """Tests for generate_posture_commentary with mocked Anthropic."""

    def _make_posture_doc(self):
        return {
            "posture_score": 75.0,
            "finding_counts": {"critical": 1, "high": 2, "medium": 3, "low": 1, "info": 0, "total": 7},
            "trend": "improving",
            "trend_delta": 5.0,
            "commentary": "",
            "forecast": "",
            "forecast_date": None,
        }

    def test_exception_returns_doc_with_fallback(self):
        doc = self._make_posture_doc()
        with patch.dict("sys.modules", {"anthropic": None}):
            result = generate_posture_commentary(doc, "scan-1", "target.com", [])
        self.assertIs(result, doc)
        self.assertIn("moderate", result["commentary"])
        self.assertEqual(result["forecast"], "")

    @patch("modules.agent.posture_score._try_parse_forecast_date")
    def test_successful_commentary(self, mock_parse):
        doc = self._make_posture_doc()

        mock_block = MagicMock()
        mock_block.text = "COMMENTARY: Security posture is improving.\nFORECAST: By April 2026."

        mock_response = MagicMock()
        mock_response.content = [mock_block]

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with patch("modules.agent.posture_score.anthropic", mock_anthropic, create=True):
                with patch("modules.config.AI_MODEL", "test-model"):
                    result = generate_posture_commentary(doc, "scan-1", "t.com", [])

        self.assertEqual(result["commentary"], "Security posture is improving.")
        self.assertEqual(result["forecast"], "By April 2026.")


class TestFallbackCommentary(unittest.TestCase):
    """Tests for _fallback_commentary."""

    def test_strong_score(self):
        doc = {"posture_score": 85, "finding_counts": {"critical": 0, "high": 1}, "trend": "stable"}
        result = _fallback_commentary(doc)
        self.assertIn("strong", result)

    def test_moderate_score(self):
        doc = {"posture_score": 65, "finding_counts": {"critical": 1, "high": 2}, "trend": "improving"}
        result = _fallback_commentary(doc)
        self.assertIn("moderate", result)

    def test_weak_score(self):
        doc = {"posture_score": 45, "finding_counts": {"critical": 2, "high": 3}, "trend": "degrading"}
        result = _fallback_commentary(doc)
        self.assertIn("weak", result)

    def test_critical_score(self):
        doc = {"posture_score": 20, "finding_counts": {"critical": 5, "high": 10}, "trend": "degrading"}
        result = _fallback_commentary(doc)
        self.assertIn("critical", result)


class TestTryParseForecastDate(unittest.TestCase):
    """Tests for _try_parse_forecast_date."""

    def test_iso_date_format(self):
        doc = {"forecast_date": None}
        _try_parse_forecast_date(doc, "Expected resolution by 2026-05-01.")
        self.assertEqual(doc["forecast_date"], "2026-05-01")

    def test_month_year_format(self):
        doc = {"forecast_date": None}
        _try_parse_forecast_date(doc, "By April 2026 all issues should be resolved.")
        self.assertEqual(doc["forecast_date"], "2026-04-01")

    def test_no_date_found(self):
        doc = {"forecast_date": None}
        _try_parse_forecast_date(doc, "No specific date mentioned.")
        self.assertIsNone(doc["forecast_date"])


if __name__ == "__main__":
    unittest.main()
