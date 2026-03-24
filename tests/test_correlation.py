"""
Tests for modules/agent/correlation — vulnerability correlation engine.

Covers attack chain detection, pattern grouping, combined risk scoring,
persistent threat detection, and the main correlate_findings entry point.
"""

import pytest

from modules.agent.correlation import (
    correlate_findings,
    detect_attack_chains,
    group_by_pattern,
    calculate_combined_risk,
    detect_persistent_threats,
)


# ── Helpers ─────────────────────────────────────────────────────────────

def _finding(
    severity="medium",
    type_="xss",
    target="https://example.com",
    description="",
    cwe="",
):
    return {
        "severity": severity,
        "type": type_,
        "target": target,
        "description": description,
        "cwe": cwe,
    }


# ── correlate_findings (main entry point) ───────────────────────────────

class TestCorrelateFindings:
    def test_empty_findings(self):
        result = correlate_findings([])
        assert result["attack_chains"] == []
        assert result["patterns"] == {}
        assert result["stats"]["total_findings"] == 0

    def test_single_finding(self):
        result = correlate_findings([_finding()])
        assert result["stats"]["total_findings"] == 1
        assert result["attack_chains"] == []

    def test_returns_expected_keys(self):
        result = correlate_findings([_finding(), _finding(type_="sqli")])
        for key in ("attack_chains", "patterns", "risk_summary", "persistent_threats", "stats"):
            assert key in result

    def test_stats_counts(self):
        findings = [_finding() for _ in range(5)]
        result = correlate_findings(findings)
        assert result["stats"]["total_findings"] == 5

    def test_chain_detected_in_full_run(self):
        findings = [
            _finding(type_="auth_bypass", severity="high", target="https://app.io"),
            _finding(type_="rce", severity="critical", target="https://app.io"),
        ]
        result = correlate_findings(findings)
        assert result["stats"]["chains_detected"] >= 1

    def test_many_findings(self):
        findings = [
            _finding(type_=f"type_{i}", severity="medium")
            for i in range(20)
        ]
        result = correlate_findings(findings)
        assert result["stats"]["total_findings"] == 20


# ── detect_attack_chains ────────────────────────────────────────────────

class TestDetectAttackChains:
    def test_empty(self):
        assert detect_attack_chains([]) == []

    def test_single_finding(self):
        assert detect_attack_chains([_finding()]) == []

    def test_auth_bypass_rce_chain(self):
        findings = [
            _finding(type_="auth_bypass", severity="high", target="https://app.io"),
            _finding(type_="rce", severity="critical", target="https://app.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1
        assert chains[0]["name"] == "Auth Bypass -> RCE"
        assert chains[0]["severity"] == "critical"

    def test_sqli_data_exfiltration_chain(self):
        findings = [
            _finding(type_="sql_injection", severity="high", target="https://db.io"),
            _finding(type_="data_exposure", severity="high", target="https://db.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1
        assert "SQL Injection" in chains[0]["name"]

    def test_ssrf_internal_access_chain(self):
        findings = [
            _finding(type_="ssrf", severity="high", target="https://api.io"),
            _finding(type_="internal_service_access", severity="high", target="https://api.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1

    def test_xss_session_hijack_chain(self):
        findings = [
            _finding(type_="xss", severity="medium", target="https://web.io"),
            _finding(type_="session_hijack", severity="high", target="https://web.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1
        assert "XSS" in chains[0]["name"]

    def test_subdomain_takeover_phishing_chain(self):
        findings = [
            _finding(type_="subdomain_takeover", severity="high", target="https://sub.io"),
            _finding(type_="phishing", severity="high", target="https://sub.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1

    def test_misconfig_privesc_chain(self):
        findings = [
            _finding(type_="misconfiguration", severity="high", target="https://srv.io"),
            _finding(type_="privilege_escalation", severity="high", target="https://srv.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) >= 1

    def test_no_chain_unrelated_findings(self):
        findings = [
            _finding(type_="missing_header", severity="low", target="https://a.io"),
            _finding(type_="slow_response", severity="info", target="https://b.io"),
        ]
        chains = detect_attack_chains(findings)
        assert len(chains) == 0

    def test_chain_has_confidence(self):
        findings = [
            _finding(type_="auth_bypass", severity="high", target="https://x.io"),
            _finding(type_="rce", severity="critical", target="https://x.io"),
        ]
        chains = detect_attack_chains(findings)
        assert chains[0]["confidence"] > 0.0
        assert chains[0]["confidence"] <= 1.0

    def test_chain_sorted_by_confidence(self):
        findings = [
            _finding(type_="auth_bypass", severity="high", target="https://a.io"),
            _finding(type_="rce", severity="critical", target="https://a.io"),
            _finding(type_="misconfiguration", severity="low", target="https://b.io"),
            _finding(type_="privilege_escalation", severity="medium", target="https://c.io"),
        ]
        chains = detect_attack_chains(findings)
        if len(chains) >= 2:
            assert chains[0]["confidence"] >= chains[1]["confidence"]


# ── group_by_pattern ────────────────────────────────────────────────────

class TestGroupByPattern:
    def test_empty(self):
        assert group_by_pattern([]) == {}

    def test_no_pattern_matches(self):
        findings = [_finding(type_="unique_thing")]
        assert group_by_pattern(findings) == {}

    def test_injection_pattern(self):
        findings = [
            _finding(type_="sql_injection"),
            _finding(type_="xss"),
            _finding(type_="command_injection"),
        ]
        groups = group_by_pattern(findings)
        assert "Widespread Injection Flaws" in groups
        assert groups["Widespread Injection Flaws"]["count"] >= 3

    def test_misconfig_pattern(self):
        findings = [
            _finding(type_="misconfiguration"),
            _finding(type_="cors_misconfiguration"),
            _finding(type_="missing_csp_header"),
        ]
        groups = group_by_pattern(findings)
        assert "Security Misconfiguration" in groups

    def test_host_grouping(self):
        findings = [
            _finding(target="https://app.io/a"),
            _finding(target="https://app.io/b"),
            _finding(target="https://app.io/c"),
        ]
        groups = group_by_pattern(findings)
        host_keys = [k for k in groups if k.startswith("host:")]
        assert len(host_keys) >= 1

    def test_host_grouping_below_threshold(self):
        findings = [
            _finding(target="https://a.io"),
            _finding(target="https://b.io"),
        ]
        groups = group_by_pattern(findings)
        host_keys = [k for k in groups if k.startswith("host:")]
        assert len(host_keys) == 0

    def test_info_exposure_pattern(self):
        findings = [
            _finding(type_="info_disclosure"),
            _finding(type_="stack_trace_leak"),
            _finding(type_="debug_endpoint_exposure"),
        ]
        groups = group_by_pattern(findings)
        assert "Information Exposure" in groups

    def test_crypto_failures_pattern(self):
        findings = [
            _finding(type_="weak_cipher"),
            _finding(type_="tls_misconfiguration"),
        ]
        groups = group_by_pattern(findings)
        assert "Cryptographic Failures" in groups


# ── calculate_combined_risk ─────────────────────────────────────────────

class TestCalculateCombinedRisk:
    def test_empty_chain(self):
        result = calculate_combined_risk([])
        assert result["combined_score"] == 0
        assert result["severity"] == "info"

    def test_single_finding_no_escalation(self):
        result = calculate_combined_risk([_finding(severity="medium")])
        assert result["escalation_factor"] == 1.0
        assert result["base_score"] == 5

    def test_two_findings_escalation(self):
        chain = [_finding(severity="high"), _finding(severity="high")]
        result = calculate_combined_risk(chain)
        assert result["escalation_factor"] > 1.0
        assert result["combined_score"] > result["base_score"]

    def test_critical_chain_boost(self):
        chain = [_finding(severity="critical"), _finding(severity="high")]
        result = calculate_combined_risk(chain)
        # critical adds 0.2 to factor on top of chain-length factor
        assert result["escalation_factor"] >= 1.5

    def test_large_chain_high_escalation(self):
        chain = [_finding(severity="high") for _ in range(4)]
        result = calculate_combined_risk(chain)
        assert result["escalation_factor"] >= 1.8

    def test_combined_score_capped_at_100(self):
        chain = [_finding(severity="critical") for _ in range(20)]
        result = calculate_combined_risk(chain)
        assert result["combined_score"] <= 100

    def test_severity_label_critical(self):
        chain = [
            _finding(severity="critical"),
            _finding(severity="critical"),
            _finding(severity="high"),
        ]
        result = calculate_combined_risk(chain)
        assert result["severity"] == "critical"

    def test_severity_label_low(self):
        result = calculate_combined_risk([
            _finding(severity="low"),
            _finding(severity="low"),
            _finding(severity="low"),
        ])
        assert result["severity"] == "low"

    def test_explanation_present(self):
        result = calculate_combined_risk([_finding()])
        assert isinstance(result["explanation"], str)
        assert len(result["explanation"]) > 0

    def test_individual_scores_match(self):
        chain = [_finding(severity="high"), _finding(severity="low")]
        result = calculate_combined_risk(chain)
        assert result["individual_scores"] == [8, 2]


# ── detect_persistent_threats ───────────────────────────────────────────

class TestDetectPersistentThreats:
    def test_no_findings(self):
        assert detect_persistent_threats([]) == []

    def test_no_history(self):
        threats = detect_persistent_threats([_finding()])
        assert len(threats) == 1
        assert threats[0]["is_persistent"] is False

    def test_persistent_match(self):
        current = [_finding(type_="sqli", target="https://app.io")]
        history = [_finding(type_="sqli", target="https://app.io")]
        threats = detect_persistent_threats(current, history)
        assert len(threats) == 1
        assert threats[0]["is_persistent"] is True
        assert threats[0]["occurrences"] == 2

    def test_non_persistent(self):
        current = [_finding(type_="xss", target="https://app.io")]
        history = [_finding(type_="sqli", target="https://other.io")]
        threats = detect_persistent_threats(current, history)
        assert all(not t["is_persistent"] for t in threats)

    def test_multiple_occurrences(self):
        current = [_finding(type_="sqli", target="https://app.io")]
        history = [
            _finding(type_="sqli", target="https://app.io"),
            _finding(type_="sqli", target="https://app.io"),
        ]
        threats = detect_persistent_threats(current, history)
        persistent = [t for t in threats if t["is_persistent"]]
        assert persistent[0]["occurrences"] == 3

    def test_sorted_persistent_first(self):
        current = [
            _finding(type_="xss", target="https://a.io"),
            _finding(type_="sqli", target="https://b.io"),
        ]
        history = [_finding(type_="sqli", target="https://b.io")]
        threats = detect_persistent_threats(current, history)
        assert threats[0]["is_persistent"] is True

    def test_recommendation_text(self):
        current = [_finding(type_="sqli", target="https://app.io")]
        history = [_finding(type_="sqli", target="https://app.io")]
        threats = detect_persistent_threats(current, history)
        assert "Recurring" in threats[0]["recommendation"]

    def test_new_finding_recommendation(self):
        threats = detect_persistent_threats([_finding(type_="xss")])
        assert "New" in threats[0]["recommendation"] or "Monitor" in threats[0]["recommendation"]

    def test_deduplicates_by_category_host(self):
        current = [
            _finding(type_="sqli", target="https://app.io/a"),
            _finding(type_="sqli", target="https://app.io/b"),
        ]
        threats = detect_persistent_threats(current)
        # Both have same (category, host) so should be deduplicated
        assert len(threats) == 1


# ── Risk escalation scenarios ───────────────────────────────────────────

class TestRiskEscalation:
    """End-to-end scenarios where combined risk is worse than individual."""

    def test_auth_bypass_plus_rce_is_critical(self):
        findings = [
            _finding(type_="auth_bypass", severity="high", target="https://app.io"),
            _finding(type_="rce", severity="critical", target="https://app.io"),
        ]
        result = correlate_findings(findings)
        assert result["risk_summary"]["severity"] in ("critical", "high")

    def test_many_medium_findings_escalate(self):
        findings = [_finding(severity="medium") for _ in range(5)]
        result = correlate_findings(findings)
        # 5 medium findings (weight 5 each) = base 25, factor ~1.8 = 45 → critical
        assert result["risk_summary"]["combined_score"] > 25

    def test_single_info_stays_low(self):
        result = correlate_findings([_finding(severity="info")])
        assert result["risk_summary"]["severity"] in ("info", "low")
