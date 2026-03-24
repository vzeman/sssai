"""Unit tests for webhook-triggered scanning and CI/CD integration."""

import pytest
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, Mock
from pydantic import ValidationError

# Import the models and functions we'll test
from modules.api.routes.webhooks import (
    WebhookScanRequest,
    QualityGates,
    WebhookConfigCreate,
    WebhookConfigUpdate,
    _evaluate_gates,
)


class TestQualityGates:
    """Test quality gates configuration model."""

    def test_create_with_max_critical(self):
        gates = QualityGates(max_critical=1)
        assert gates.max_critical == 1
        assert gates.max_high is None

    def test_create_with_all_fields(self):
        gates = QualityGates(
            max_critical=0,
            max_high=5,
            max_risk_score=75.0,
            required_compliance=["pci-dss", "hipaa"],
        )
        assert gates.max_critical == 0
        assert gates.max_high == 5
        assert gates.max_risk_score == 75.0
        assert "pci-dss" in gates.required_compliance

    def test_empty_gates_allowed(self):
        gates = QualityGates()
        assert gates.max_critical is None
        assert gates.max_high is None

    def test_required_compliance_defaults_to_empty(self):
        gates = QualityGates()
        assert gates.required_compliance == []


class TestWebhookScanRequest:
    """Test webhook scan trigger request model."""

    def test_minimal_request(self):
        req = WebhookScanRequest(target="https://example.com")
        assert req.target == "https://example.com"
        assert req.commit_sha == ""
        assert req.scan_type == "security"

    def test_full_request(self):
        req = WebhookScanRequest(
            target="https://example.com",
            commit_sha="abc123def456",
            branch="main",
            environment="staging",
            deployer="github-actions",
            scan_type="comprehensive",
            gates=QualityGates(max_critical=0),
        )
        assert req.target == "https://example.com"
        assert req.commit_sha == "abc123def456"
        assert req.branch == "main"
        assert req.environment == "staging"
        assert req.deployer == "github-actions"
        assert req.scan_type == "comprehensive"
        assert req.gates.max_critical == 0

    def test_target_required(self):
        """Target is a required field."""
        with pytest.raises(ValidationError):
            WebhookScanRequest()


class TestWebhookConfigCreate:
    """Test webhook config creation request."""

    def test_minimal_config(self):
        cfg = WebhookConfigCreate(name="staging-scanner")
        assert cfg.name == "staging-scanner"
        assert cfg.scan_type == "security"
        assert cfg.gates is None

    def test_config_with_gates(self):
        cfg = WebhookConfigCreate(
            name="prod-scanner",
            scan_type="comprehensive",
            gates=QualityGates(max_critical=0, max_high=3),
        )
        assert cfg.name == "prod-scanner"
        assert cfg.gates.max_critical == 0
        assert cfg.gates.max_high == 3

    def test_name_required(self):
        with pytest.raises(ValidationError):
            WebhookConfigCreate()


class TestWebhookConfigUpdate:
    """Test webhook config update request."""

    def test_partial_update(self):
        update = WebhookConfigUpdate(name="new-name")
        assert update.name == "new-name"
        assert update.scan_type is None
        assert update.is_active is None

    def test_disable_webhook(self):
        update = WebhookConfigUpdate(is_active=False)
        assert update.is_active is False
        assert update.name is None

    def test_all_none_allowed(self):
        update = WebhookConfigUpdate()
        assert update.name is None
        assert update.scan_type is None
        assert update.gates is None
        assert update.is_active is None


class TestQualityGateEvaluation:
    """Test quality gate evaluation logic."""

    def test_no_gates_configured(self):
        """No gates = automatic pass."""
        scan = MagicMock(risk_score=50.0)
        result = _evaluate_gates(scan, {}, {})
        assert result["passed"] is True
        assert result["reason"] == "No gates configured"

    def test_max_critical_gate_pass(self):
        """Critical count below threshold."""
        scan = MagicMock(risk_score=50.0)
        report = {
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "high"},
            ]
        }
        gates = {"max_critical": 2}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True
        assert result["critical_count"] == 1

    def test_max_critical_gate_fail(self):
        """Critical count exceeds threshold."""
        scan = MagicMock(risk_score=80.0)
        report = {
            "findings": [
                {"severity": "critical"},
                {"severity": "critical"},
                {"severity": "critical"},
            ]
        }
        gates = {"max_critical": 0}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False
        assert result["critical_count"] == 3
        critical_check = next(c for c in result["checks"] if c["gate"] == "max_critical")
        assert critical_check["passed"] is False

    def test_max_high_gate_pass(self):
        """High count within threshold."""
        scan = MagicMock(risk_score=40.0)
        report = {
            "findings": [
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "medium"},
            ]
        }
        gates = {"max_high": 5}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True
        assert result["high_count"] == 2

    def test_max_high_gate_fail(self):
        """High count exceeds threshold."""
        scan = MagicMock(risk_score=60.0)
        report = {
            "findings": [
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "high"},
            ]
        }
        gates = {"max_high": 1}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False
        assert result["high_count"] == 3

    def test_max_risk_score_gate_pass(self):
        """Risk score below threshold."""
        scan = MagicMock(risk_score=45.5)
        report = {"findings": []}
        gates = {"max_risk_score": 50.0}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True

    def test_max_risk_score_gate_fail(self):
        """Risk score exceeds threshold."""
        scan = MagicMock(risk_score=75.0)
        report = {"findings": []}
        gates = {"max_risk_score": 60.0}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False
        score_check = next(c for c in result["checks"] if c["gate"] == "max_risk_score")
        assert score_check["passed"] is False
        assert score_check["actual"] == 75.0

    def test_multiple_gates_all_pass(self):
        """All gates pass."""
        scan = MagicMock(risk_score=40.0)
        report = {
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
            ]
        }
        gates = {
            "max_critical": 2,
            "max_high": 3,
            "max_risk_score": 50.0,
        }

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True
        assert len(result["checks"]) == 3
        assert all(c["passed"] for c in result["checks"])

    def test_multiple_gates_one_fails(self):
        """Multiple gates, one fails."""
        scan = MagicMock(risk_score=70.0)
        report = {
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
            ]
        }
        gates = {
            "max_critical": 1,
            "max_high": 1,
            "max_risk_score": 50.0,  # This one fails
        }

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False
        failed_checks = [c for c in result["checks"] if not c["passed"]]
        assert len(failed_checks) >= 1

    def test_case_insensitive_severity(self):
        """Severity matching should be case-insensitive."""
        scan = MagicMock(risk_score=40.0)
        report = {
            "findings": [
                {"severity": "CRITICAL"},
                {"severity": "High"},
                {"severity": "medium"},
            ]
        }
        gates = {"max_critical": 1, "max_high": 1}

        result = _evaluate_gates(scan, report, gates)
        assert result["critical_count"] == 1
        assert result["high_count"] == 1

    def test_missing_severity_in_findings(self):
        """Findings without severity should be ignored."""
        scan = MagicMock(risk_score=30.0)
        report = {
            "findings": [
                {"title": "Something"},  # No severity
                {"severity": "critical"},
                {"severity": None},
            ]
        }
        gates = {"max_critical": 1}

        result = _evaluate_gates(scan, report, gates)
        assert result["critical_count"] == 1
        assert result["passed"] is True

    def test_empty_report_findings(self):
        """Empty findings list = 0 critical and high."""
        scan = MagicMock(risk_score=0.0)
        report = {"findings": []}
        gates = {"max_critical": 0, "max_high": 0}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True
        assert result["critical_count"] == 0
        assert result["high_count"] == 0

    def test_no_report_provided(self):
        """Scan without report should pass count-based gates."""
        scan = MagicMock(risk_score=0.0)
        gates = {"max_critical": 0, "max_high": 0}

        result = _evaluate_gates(scan, None, gates)
        assert result["passed"] is True
        assert result["critical_count"] == 0
        assert result["high_count"] == 0

    def test_required_compliance_gate_pass(self):
        """Required compliance frameworks must be met."""
        scan = MagicMock(risk_score=30.0)
        report = {
            "findings": [],
            "compliance": {
                "pci-dss": {"passed": True, "coverage": 98},
                "hipaa": {"passed": True, "coverage": 95},
            },
        }
        gates = {"required_compliance": ["pci-dss", "hipaa"]}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is True
        compliance_checks = [c for c in result["checks"] if "compliance" in c["gate"]]
        assert len(compliance_checks) == 2
        assert all(c["passed"] for c in compliance_checks)

    def test_required_compliance_gate_fail_missing(self):
        """Required compliance missing should fail."""
        scan = MagicMock(risk_score=30.0)
        report = {
            "findings": [],
            "compliance": {
                "pci-dss": {"passed": True},
            },
        }
        gates = {"required_compliance": ["pci-dss", "hipaa"]}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False
        hipaa_check = next(c for c in result["checks"] if "hipaa" in c["gate"])
        assert hipaa_check["passed"] is False

    def test_required_compliance_gate_fail_not_passed(self):
        """Compliance framework present but not passed should fail."""
        scan = MagicMock(risk_score=30.0)
        report = {
            "findings": [],
            "compliance": {
                "pci-dss": {"passed": False},
            },
        }
        gates = {"required_compliance": ["pci-dss"]}

        result = _evaluate_gates(scan, report, gates)
        assert result["passed"] is False

    def test_gate_evaluation_summary(self):
        """Summary should show passed vs total checks."""
        scan = MagicMock(risk_score=45.0)
        report = {"findings": [{"severity": "high"}]}
        gates = {
            "max_critical": 0,
            "max_high": 1,
            "max_risk_score": 50.0,
        }

        result = _evaluate_gates(scan, report, gates)
        assert result["summary"] == "3/3 checks passed"

    def test_gate_checks_include_threshold_and_actual(self):
        """Each check should include threshold and actual values."""
        scan = MagicMock(risk_score=25.0)
        report = {"findings": [{"severity": "high"}]}
        gates = {"max_high": 3}

        result = _evaluate_gates(scan, report, gates)
        check = result["checks"][0]
        assert "threshold" in check
        assert "actual" in check
        assert check["threshold"] == 3
        assert check["actual"] == 1


class TestWebhookIntegration:
    """Integration tests for webhook scanning workflow."""

    def test_webhook_scan_request_with_gates(self):
        """Webhook scan can include inline gate overrides."""
        gates = QualityGates(max_critical=0, max_high=2)
        req = WebhookScanRequest(
            target="https://prod.example.com",
            commit_sha="abc123",
            branch="main",
            environment="production",
            deployer="github-actions",
            scan_type="comprehensive",
            gates=gates,
        )

        assert req.gates.max_critical == 0
        assert req.gates.max_high == 2

    def test_typical_ci_cd_gate_configuration(self):
        """Typical CI/CD pipeline gate configuration."""
        gates = QualityGates(
            max_critical=0,  # Zero critical vulnerabilities allowed in prod
            max_high=5,  # Up to 5 high-severity issues
            max_risk_score=70.0,  # Risk score must be below 70%
            required_compliance=["owasp-top-10"],
        )

        assert gates.max_critical == 0
        assert gates.max_high == 5
        assert gates.max_risk_score == 70.0
        assert "owasp-top-10" in gates.required_compliance

    def test_staging_vs_production_gates(self):
        """Different gate thresholds for staging vs production."""
        staging_gates = QualityGates(max_critical=5, max_high=20)
        prod_gates = QualityGates(max_critical=0, max_high=5)

        assert staging_gates.max_critical > prod_gates.max_critical
        assert staging_gates.max_high > prod_gates.max_high
