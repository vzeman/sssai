"""Unit tests for attack chain analysis and exploitation narratives."""

import pytest
from unittest.mock import patch, MagicMock

# We'll test the attack chain analysis module
from modules.agent.scan_agent import _run_attack_chain_analysis


class TestAttackChainAnalysis:
    """Test attack chain analysis for multi-vulnerability exploitation."""

    def test_insufficient_findings_returns_empty(self):
        """Less than 2 findings should return empty chain list."""
        client = MagicMock()
        report = {
            "findings": [
                {
                    "title": "Single Finding",
                    "severity": "high",
                    "category": "web",
                    "description": "A single vulnerability",
                }
            ]
        }
        chains = _run_attack_chain_analysis(client, report)
        assert chains == []

    def test_two_findings_no_patterns_returns_empty(self):
        """Two findings with no chainable patterns should return empty."""
        client = MagicMock()
        report = {
            "findings": [
                {
                    "title": "Typo Detected",
                    "severity": "low",
                    "category": "grammar",
                    "description": "Minor typo in help text",
                },
                {
                    "title": "Missing Alt Text",
                    "severity": "low",
                    "category": "accessibility",
                    "description": "Image missing alt attribute",
                },
            ]
        }
        chains = _run_attack_chain_analysis(client, report)
        assert chains == []

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_chainable_patterns_trigger_analysis(self, mock_anthropic_class):
        """When findings match attack chain patterns, LLM should be called."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='[{"title":"XSS to Account Takeover","chain_risk_score":85,"steps":[{"finding_ref":"Reflected XSS","action":"Inject malicious script"},{"finding_ref":"Missing CSRF Token","action":"Perform unwanted action"}],"impact":"Account compromise","likelihood":"high","prerequisites":"Victim must click link"}]')]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {
                    "title": "Reflected XSS",
                    "severity": "high",
                    "category": "web",
                    "description": "XSS vulnerability in search parameter",
                },
                {
                    "title": "Missing CSRF Token",
                    "severity": "medium",
                    "category": "web",
                    "description": "Form lacks CSRF protection",
                },
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)

        # LLM should be called since patterns match
        assert mock_client.messages.create.called

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_three_findings_triggers_analysis_regardless_of_patterns(self, mock_anthropic_class):
        """With 3+ findings, always attempt LLM analysis."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="[]")]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": f"Finding {i}", "severity": "info", "category": "misc", "description": "Test"}
                for i in range(3)
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert mock_client.messages.create.called

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_chain_response_parsing(self, mock_anthropic_class):
        """Verify proper parsing of LLM chain response."""
        mock_client = MagicMock()
        chain_json = '''[
            {
                "title": "Open Redirect + Phishing",
                "chain_risk_score": 92,
                "steps": [
                    {"finding_ref": "Open Redirect", "action": "Attacker creates malicious URL pointing to evil site"},
                    {"finding_ref": "Missing SameSite Cookie", "action": "Session cookie is sent to attacker domain"}
                ],
                "impact": "Session hijacking and credential theft",
                "likelihood": "high",
                "prerequisites": "Victim clicks attacker-supplied link"
            }
        ]'''
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=chain_json)]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Open Redirect", "severity": "high", "category": "web", "description": "Unvalidated redirect"},
                {"title": "Missing SameSite Cookie", "severity": "medium", "category": "web", "description": "Cookie vulnerability"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 1
        assert chains[0]["title"] == "Open Redirect + Phishing"
        assert chains[0]["chain_risk_score"] == 92
        assert len(chains[0]["steps"]) == 2
        assert chains[0]["impact"] == "Session hijacking and credential theft"

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_multiple_chains_detection(self, mock_anthropic_class):
        """Multiple attack chains in a single response should all be captured."""
        mock_client = MagicMock()
        chain_json = '''[
            {
                "title": "Chain 1",
                "chain_risk_score": 80,
                "steps": [{"finding_ref": "Finding 1", "action": "Step 1"}],
                "impact": "Impact 1",
                "likelihood": "high",
                "prerequisites": "Prereq 1"
            },
            {
                "title": "Chain 2",
                "chain_risk_score": 75,
                "steps": [{"finding_ref": "Finding 2", "action": "Step 2"}],
                "impact": "Impact 2",
                "likelihood": "medium",
                "prerequisites": "Prereq 2"
            }
        ]'''
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=chain_json)]
        mock_response.usage = MagicMock(input_tokens=200, output_tokens=100)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Finding 1", "severity": "high", "category": "web", "description": "Test 1"},
                {"title": "Finding 2", "severity": "high", "category": "web", "description": "Test 2"},
                {"title": "Finding 3", "severity": "high", "category": "web", "description": "Test 3"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 2
        assert chains[0]["title"] == "Chain 1"
        assert chains[1]["title"] == "Chain 2"

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_chain_risk_score_defaults_when_missing(self, mock_anthropic_class):
        """If chain_risk_score is missing, should default to reasonable value."""
        mock_client = MagicMock()
        chain_json = '''[
            {
                "title": "Missing Score Chain",
                "steps": [{"finding_ref": "Finding 1", "action": "Action"}],
                "impact": "Bad impact",
                "likelihood": "high",
                "prerequisites": "Some prereq"
            }
        ]'''
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=chain_json)]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Finding 1", "severity": "high", "category": "web", "description": "Test 1"},
                {"title": "Finding 2", "severity": "high", "category": "web", "description": "Test 2"},
                {"title": "Finding 3", "severity": "high", "category": "web", "description": "Test 3"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 1
        assert chains[0].get("chain_risk_score") is not None
        assert 0 <= chains[0]["chain_risk_score"] <= 100

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_sql_injection_plus_misconfigured_db_chain(self, mock_anthropic_class):
        """Real-world scenario: SQL injection + misconfigured DB → data exfiltration."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='''[
            {
                "title": "SQL Injection → Data Exfiltration",
                "chain_risk_score": 95,
                "steps": [
                    {"finding_ref": "SQL Injection in search", "action": "Execute SELECT query to dump database"},
                    {"finding_ref": "Misconfigured DB", "action": "Database returns sensitive user data without access controls"}
                ],
                "impact": "Complete database compromise - PII, passwords, API keys exposed",
                "likelihood": "high",
                "prerequisites": "SQL injection vulnerability exists"
            }
        ]''')]
        mock_response.usage = MagicMock(input_tokens=150, output_tokens=80)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "SQL Injection in search", "severity": "critical", "category": "database", "description": "Unsanitized user input"},
                {"title": "Misconfigured DB", "severity": "high", "category": "infrastructure", "description": "No row-level security"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 1
        assert chains[0]["chain_risk_score"] == 95
        assert "data exfiltration" in chains[0]["impact"].lower()

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_idor_plus_pii_exposure_chain(self, mock_anthropic_class):
        """Real-world scenario: IDOR + PII disclosure → mass breach."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='''[
            {
                "title": "IDOR + PII Exposure → Mass Breach",
                "chain_risk_score": 98,
                "steps": [
                    {"finding_ref": "Broken Object-Level Authorization", "action": "Change user ID in request to enumerate all user accounts"},
                    {"finding_ref": "PII Exposure in API Response", "action": "Access SSN, phone, email for thousands of users"}
                ],
                "impact": "Mass data breach affecting entire user base",
                "likelihood": "high",
                "prerequisites": "Valid user account to make initial request"
            }
        ]''')]
        mock_response.usage = MagicMock(input_tokens=150, output_tokens=80)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Broken Object-Level Authorization", "severity": "critical", "category": "api", "description": "User ID in URL"},
                {"title": "PII Exposure in API Response", "severity": "critical", "category": "data", "description": "SSN/email exposed"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 1
        assert chains[0]["chain_risk_score"] == 98
        assert "mass data breach" in chains[0]["impact"].lower()

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_stored_xss_plus_admin_context_chain(self, mock_anthropic_class):
        """Real-world scenario: Stored XSS + admin access → privilege escalation."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='''[
            {
                "title": "Stored XSS in Admin Panel → Account Takeover",
                "chain_risk_score": 96,
                "steps": [
                    {"finding_ref": "Stored XSS in comments", "action": "Store malicious JavaScript in database"},
                    {"finding_ref": "Admin views user comments", "action": "JavaScript executes in admin session"},
                    {"finding_ref": "Missing SameSite Cookie", "action": "Attacker steals admin session"}
                ],
                "impact": "Full platform compromise with admin privileges",
                "likelihood": "high",
                "prerequisites": "Admin must view comments within reasonable timeframe"
            }
        ]''')]
        mock_response.usage = MagicMock(input_tokens=150, output_tokens=80)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Stored XSS in comments", "severity": "high", "category": "web", "description": "User input not sanitized"},
                {"title": "Admin views user comments", "severity": "medium", "category": "design", "description": "Admin panel feature"},
                {"title": "Missing SameSite Cookie", "severity": "medium", "category": "web", "description": "Cookie vulnerability"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        assert len(chains) == 1
        assert "account takeover" in chains[0]["title"].lower()


class TestAttackChainPatterns:
    """Test the pre-defined attack chain pattern matching."""

    def test_open_redirect_xss_pattern(self):
        """Open redirect + XSS is a known pattern."""
        from modules.agent.scan_agent import _ATTACK_CHAIN_PATTERNS

        patterns = _ATTACK_CHAIN_PATTERNS
        assert ("open redirect", "xss") in patterns

    def test_sql_injection_database_pattern(self):
        """SQL injection + database is a known pattern."""
        from modules.agent.scan_agent import _ATTACK_CHAIN_PATTERNS

        patterns = _ATTACK_CHAIN_PATTERNS
        assert ("sql injection", "database") in patterns

    def test_idor_patterns(self):
        """IDOR chains are recognized."""
        from modules.agent.scan_agent import _ATTACK_CHAIN_PATTERNS

        patterns = _ATTACK_CHAIN_PATTERNS
        assert ("idor", "authorization") in patterns
        assert ("idor", "pii") in patterns

    def test_all_patterns_are_tuples(self):
        """All patterns should be 2-tuples of strings."""
        from modules.agent.scan_agent import _ATTACK_CHAIN_PATTERNS

        for pattern in _ATTACK_CHAIN_PATTERNS:
            assert isinstance(pattern, tuple)
            assert len(pattern) == 2
            assert isinstance(pattern[0], str)
            assert isinstance(pattern[1], str)


class TestAttackChainIntegration:
    """Integration tests for attack chain analysis in full scan context."""

    @patch("modules.agent.scan_agent.anthropic.Anthropic")
    def test_attack_chain_included_in_final_report(self, mock_anthropic_class):
        """Attack chains should be available in scan report structure."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='[{"title":"Test Chain","chain_risk_score":80,"steps":[],"impact":"Test impact","likelihood":"high","prerequisites":"Test"}]')]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_response

        report = {
            "findings": [
                {"title": "Finding 1", "severity": "high", "category": "web", "description": "Test"},
                {"title": "Finding 2", "severity": "high", "category": "web", "description": "Test"},
                {"title": "Finding 3", "severity": "high", "category": "web", "description": "Test"},
            ]
        }

        chains = _run_attack_chain_analysis(mock_client, report)
        report["attack_chains"] = chains

        assert "attack_chains" in report
        assert isinstance(report["attack_chains"], list)
        assert len(report["attack_chains"]) >= 0

    def test_empty_chains_when_no_findings(self):
        """Empty findings list should produce empty chains."""
        client = MagicMock()
        report = {"findings": []}
        chains = _run_attack_chain_analysis(client, report)
        assert chains == []
        assert client.messages.create.call_count == 0
