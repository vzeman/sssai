"""Tests for auto-triage module — finding enrichment and bucketing."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.agent.triage import (
    _score_business_impact,
    _score_exploitability,
    _score_exposure,
    enrich_findings,
    generate_triage_buckets,
    apply_triage,
)


class TestBusinessImpactScoring(unittest.TestCase):

    def test_auth_finding_is_critical(self):
        finding = {"title": "Broken Authentication", "category": "auth"}
        level, score = _score_business_impact(finding)
        self.assertEqual(level, "critical")
        self.assertEqual(score, 30)

    def test_sqli_finding_is_critical(self):
        finding = {"title": "SQL Injection on login form", "description": "SQLi detected"}
        level, score = _score_business_impact(finding)
        self.assertEqual(level, "critical")
        self.assertEqual(score, 30)

    def test_payment_finding_is_critical(self):
        finding = {"title": "Payment endpoint exposed", "category": "payment"}
        level, _ = _score_business_impact(finding)
        self.assertEqual(level, "critical")

    def test_xss_finding_is_medium(self):
        finding = {"title": "Reflected XSS", "category": "xss"}
        level, score = _score_business_impact(finding)
        self.assertEqual(level, "medium")
        self.assertEqual(score, 15)

    def test_cors_finding_is_medium(self):
        finding = {"title": "CORS Misconfiguration", "category": "cors"}
        level, _ = _score_business_impact(finding)
        self.assertEqual(level, "medium")

    def test_generic_info_finding_is_low(self):
        finding = {"title": "Server banner detected", "severity": "info"}
        level, score = _score_business_impact(finding)
        self.assertEqual(level, "low")
        self.assertEqual(score, 5)

    def test_high_severity_fallback_to_medium(self):
        finding = {"title": "Unknown issue", "severity": "high"}
        level, _ = _score_business_impact(finding)
        self.assertEqual(level, "medium")

    def test_empty_finding(self):
        level, score = _score_business_impact({})
        self.assertEqual(level, "low")


class TestExploitabilityScoring(unittest.TestCase):

    def test_high_cvss_cve_is_public_exploit(self):
        finding = {"cve_ids": ["CVE-2024-1234"], "cvss_score": 9.8}
        level, score = _score_exploitability(finding)
        self.assertEqual(level, "public_exploit")
        self.assertEqual(score, 25)

    def test_low_cvss_cve_is_known_cve(self):
        finding = {"cve_ids": ["CVE-2024-5678"], "cvss_score": 5.0}
        level, score = _score_exploitability(finding)
        self.assertEqual(level, "known_cve")
        self.assertEqual(score, 15)

    def test_exploit_keyword_in_evidence(self):
        finding = {"evidence": "Public exploit available on Metasploit"}
        level, _ = _score_exploitability(finding)
        self.assertEqual(level, "public_exploit")

    def test_exploit_keyword_in_description(self):
        finding = {"description": "POC demonstrates proof of concept attack"}
        level, _ = _score_exploitability(finding)
        self.assertEqual(level, "public_exploit")

    def test_critical_without_cve_is_theoretical(self):
        finding = {"severity": "critical"}
        level, score = _score_exploitability(finding)
        self.assertEqual(level, "theoretical")
        self.assertEqual(score, 10)

    def test_info_finding_is_low_likelihood(self):
        finding = {"severity": "info"}
        level, score = _score_exploitability(finding)
        self.assertEqual(level, "low_likelihood")
        self.assertEqual(score, 3)

    def test_empty_finding(self):
        level, _ = _score_exploitability({})
        self.assertEqual(level, "low_likelihood")


class TestExposureScoring(unittest.TestCase):

    def test_external_url_is_internet_facing(self):
        finding = {"affected_urls": ["https://example.com/api/users"]}
        level, score = _score_exposure(finding, None)
        self.assertEqual(level, "internet_facing")
        self.assertEqual(score, 10)

    def test_localhost_url_is_internal(self):
        finding = {"affected_urls": ["http://localhost:8080/test"]}
        level, _ = _score_exposure(finding, None)
        self.assertEqual(level, "internal")

    def test_private_ip_is_internal(self):
        finding = {"affected_urls": ["http://192.168.1.1/admin"]}
        level, _ = _score_exposure(finding, None)
        self.assertEqual(level, "internal")

    def test_web_category_defaults_to_internet_facing(self):
        finding = {"category": "web security"}
        level, _ = _score_exposure(finding, None)
        self.assertEqual(level, "internet_facing")

    def test_matching_entry_point(self):
        finding = {"affected_urls": ["https://app.example.com/api"]}
        surface = {"entry_points": ["https://app.example.com"]}
        level, _ = _score_exposure(finding, surface)
        self.assertEqual(level, "internet_facing")

    def test_empty_finding(self):
        level, _ = _score_exposure({}, None)
        self.assertEqual(level, "internal")


class TestEnrichFindings(unittest.TestCase):

    def test_enriches_all_fields(self):
        report = {"findings": [
            {"title": "SQLi", "severity": "critical", "category": "injection"}
        ]}
        enriched = enrich_findings(report)
        self.assertEqual(len(enriched), 1)
        f = enriched[0]
        self.assertIn("exploitability", f)
        self.assertIn("business_impact", f)
        self.assertIn("exposure", f)
        self.assertIn("priority_score", f)

    def test_sorted_by_priority_descending(self):
        report = {"findings": [
            {"title": "Info leak", "severity": "info"},
            {"title": "SQLi on login", "severity": "critical"},
            {"title": "Missing header", "severity": "medium"},
        ]}
        enriched = enrich_findings(report)
        scores = [f["priority_score"] for f in enriched]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_findings(self):
        result = enrich_findings({"findings": []})
        self.assertEqual(result, [])

    def test_none_findings(self):
        result = enrich_findings({})
        self.assertEqual(result, [])

    def test_priority_capped_at_100(self):
        report = {"findings": [
            {"title": "SQL injection on auth payment credential",
             "severity": "critical",
             "cve_ids": ["CVE-2024-9999"],
             "cvss_score": 10.0,
             "affected_urls": ["https://pay.example.com"]}
        ]}
        enriched = enrich_findings(report)
        self.assertLessEqual(enriched[0]["priority_score"], 100)

    def test_does_not_mutate_original(self):
        original = {"title": "Test", "severity": "high"}
        report = {"findings": [original]}
        enrich_findings(report)
        self.assertNotIn("priority_score", original)


class TestTriageBuckets(unittest.TestCase):

    def test_critical_goes_to_immediate(self):
        findings = [{"title": "SQLi", "severity": "critical", "priority_score": 80,
                      "exploitability": "public_exploit", "business_impact": "critical",
                      "exposure": "internet_facing"}]
        buckets = generate_triage_buckets(findings)
        self.assertEqual(len(buckets["immediate_action"]), 1)
        self.assertIn("SQLi", buckets["immediate_action"][0])

    def test_high_goes_to_this_sprint(self):
        findings = [{"title": "Open Redirect", "severity": "high", "priority_score": 50,
                      "exploitability": "theoretical", "business_impact": "medium",
                      "exposure": "internet_facing"}]
        buckets = generate_triage_buckets(findings)
        self.assertEqual(len(buckets["this_sprint"]), 1)

    def test_low_goes_to_backlog(self):
        findings = [{"title": "Server Banner", "severity": "info", "priority_score": 10,
                      "exploitability": "low_likelihood", "business_impact": "low",
                      "exposure": "internal"}]
        buckets = generate_triage_buckets(findings)
        self.assertEqual(len(buckets["backlog"]), 1)

    def test_empty_findings(self):
        buckets = generate_triage_buckets([])
        self.assertEqual(buckets["immediate_action"], [])
        self.assertEqual(buckets["this_sprint"], [])
        self.assertEqual(buckets["backlog"], [])

    def test_public_exploit_always_immediate(self):
        findings = [{"title": "Low sev but exploitable", "severity": "low",
                      "priority_score": 30, "exploitability": "public_exploit",
                      "business_impact": "low", "exposure": "internal"}]
        buckets = generate_triage_buckets(findings)
        self.assertEqual(len(buckets["immediate_action"]), 1)


class TestApplyTriage(unittest.TestCase):

    def test_adds_triage_to_report(self):
        report = {"findings": [
            {"title": "XSS", "severity": "high"},
            {"title": "Info", "severity": "info"},
        ]}
        result = apply_triage(report)
        self.assertIn("triage", result)
        self.assertIn("immediate_action", result["triage"])
        self.assertIn("this_sprint", result["triage"])
        self.assertIn("backlog", result["triage"])

    def test_enriches_findings_in_report(self):
        report = {"findings": [{"title": "Test", "severity": "medium"}]}
        result = apply_triage(report)
        self.assertIn("priority_score", result["findings"][0])

    def test_handles_empty_report(self):
        result = apply_triage({})
        self.assertIn("triage", result)

    def test_handles_malformed_findings(self):
        report = {"findings": [{}]}
        result = apply_triage(report)
        self.assertIn("triage", result)


if __name__ == "__main__":
    unittest.main()
