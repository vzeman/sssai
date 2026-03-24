"""Tests for intelligent scan scheduling — interval recommendation logic."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.agent.scheduling import (
    _classify_target_criticality,
    _compute_change_rate,
    _vulnerability_density,
    recommend_scan_interval,
)


class TestTargetCriticality(unittest.TestCase):

    def test_payment_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://payment.example.com"), "critical")

    def test_login_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://example.com/login"), "critical")

    def test_auth_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://auth.example.com"), "critical")

    def test_api_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://api.example.com"), "critical")

    def test_graphql_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://example.com/graphql"), "critical")

    def test_admin_is_critical(self):
        self.assertEqual(_classify_target_criticality("https://admin.example.com"), "critical")

    def test_app_is_medium(self):
        self.assertEqual(_classify_target_criticality("https://app.example.com"), "medium")

    def test_portal_is_medium(self):
        self.assertEqual(_classify_target_criticality("https://portal.example.com"), "medium")

    def test_static_site_is_low(self):
        self.assertEqual(_classify_target_criticality("https://blog.example.com"), "low")

    def test_case_insensitive(self):
        self.assertEqual(_classify_target_criticality("https://PAYMENT.example.com"), "critical")


class TestChangeRate(unittest.TestCase):

    def test_no_history(self):
        self.assertEqual(_compute_change_rate([]), 0.0)

    def test_single_scan(self):
        self.assertEqual(_compute_change_rate([{"findings_count": 10}]), 0.0)

    def test_stable_target(self):
        history = [
            {"findings_count": 5},
            {"findings_count": 5},
            {"findings_count": 5},
        ]
        self.assertEqual(_compute_change_rate(history), 0.0)

    def test_volatile_target(self):
        history = [
            {"findings_count": 10},
            {"findings_count": 2},
            {"findings_count": 8},
        ]
        # deltas: |10-2|=8, |2-8|=6, avg=7
        self.assertEqual(_compute_change_rate(history), 7.0)

    def test_gradually_increasing(self):
        history = [
            {"findings_count": 3},
            {"findings_count": 2},
            {"findings_count": 1},
        ]
        # deltas: 1, 1, avg=1
        self.assertEqual(_compute_change_rate(history), 1.0)


class TestVulnerabilityDensity(unittest.TestCase):

    def test_empty_history(self):
        self.assertEqual(_vulnerability_density([]), 0.0)

    def test_single_scan(self):
        self.assertEqual(_vulnerability_density([{"findings_count": 15}]), 15.0)

    def test_average_calculation(self):
        history = [
            {"findings_count": 10},
            {"findings_count": 20},
        ]
        self.assertEqual(_vulnerability_density(history), 15.0)


class TestRecommendScanInterval(unittest.TestCase):

    def test_clean_static_site_gets_monthly(self):
        result = recommend_scan_interval(
            "https://blog.example.com",
            {"findings": [], "risk_score": 5},
            scan_history=[],
        )
        self.assertEqual(result["recommended_scan_interval"], "monthly")
        self.assertIn("recommended", result["interval_reasoning"].lower())

    def test_high_risk_auth_target_gets_daily(self):
        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
        ]
        history = [
            {"findings_count": 10},
            {"findings_count": 3},
        ]
        result = recommend_scan_interval(
            "https://auth.example.com/login",
            {"findings": findings, "risk_score": 85},
            scan_history=history,
        )
        self.assertEqual(result["recommended_scan_interval"], "daily")

    def test_moderate_risk_gets_weekly_or_biweekly(self):
        findings = [{"severity": "high"}, {"severity": "medium"}]
        result = recommend_scan_interval(
            "https://app.example.com",
            {"findings": findings, "risk_score": 45},
            scan_history=[],
        )
        self.assertIn(result["recommended_scan_interval"], ["weekly", "biweekly"])

    def test_no_history_note_in_reasoning(self):
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": [], "risk_score": 0},
            scan_history=[],
        )
        self.assertIn("No prior scan history", result["interval_reasoning"])

    def test_stable_target_with_history_mentions_stable(self):
        history = [
            {"findings_count": 3},
            {"findings_count": 3},
            {"findings_count": 3},
        ]
        result = recommend_scan_interval(
            "https://blog.example.com",
            {"findings": [], "risk_score": 10},
            scan_history=history,
        )
        self.assertIn("stable", result["interval_reasoning"].lower())

    def test_high_volatility_increases_frequency(self):
        history = [
            {"findings_count": 20},
            {"findings_count": 2},
            {"findings_count": 18},
        ]
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": [{"severity": "medium"}], "risk_score": 30},
            scan_history=history,
        )
        # High volatility should push toward more frequent scanning
        self.assertIn(result["recommended_scan_interval"], ["daily", "weekly", "biweekly"])
        self.assertIn("volatility", result["interval_reasoning"].lower())

    def test_vulnerability_dense_target(self):
        history = [{"findings_count": 15}, {"findings_count": 12}]
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": [{"severity": "medium"}], "risk_score": 30},
            scan_history=history,
        )
        self.assertIn("vulnerability-dense", result["interval_reasoning"])

    def test_return_structure(self):
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": []},
            scan_history=[],
        )
        self.assertIn("recommended_scan_interval", result)
        self.assertIn("interval_reasoning", result)
        self.assertIn(result["recommended_scan_interval"],
                       ["daily", "weekly", "biweekly", "monthly"])

    def test_none_findings_handled(self):
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": None, "risk_score": None},
            scan_history=[],
        )
        self.assertIn("recommended_scan_interval", result)

    def test_missing_severity_in_findings(self):
        result = recommend_scan_interval(
            "https://example.com",
            {"findings": [{"title": "no severity field"}]},
            scan_history=[],
        )
        self.assertIn("recommended_scan_interval", result)


if __name__ == "__main__":
    unittest.main()
