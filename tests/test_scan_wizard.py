"""Tests for scan wizard: target detection, templates, validation, and builder."""

import pytest

from modules.api.scan_wizard import (
    TargetDetector,
    TargetType,
    ScanTemplates,
    ScanWizardValidator,
    ScanWizardBuilder,
)


# ── Target Detection ────────────────────────────────────────────────────


class TestTargetDetector:
    """Test target type detection from input strings."""

    def test_detect_domain(self):
        result = TargetDetector.detect("example.com")
        assert result.type == TargetType.DOMAIN
        assert result.normalized == "example.com"
        assert result.confidence >= 0.9

    def test_detect_subdomain(self):
        result = TargetDetector.detect("api.example.com")
        assert result.type == TargetType.SUBDOMAIN
        assert result.confidence >= 0.9

    def test_detect_deep_subdomain(self):
        result = TargetDetector.detect("a.b.c.example.com")
        assert result.type == TargetType.SUBDOMAIN

    def test_detect_ipv4(self):
        result = TargetDetector.detect("192.168.1.1")
        assert result.type == TargetType.IPV4
        assert result.confidence == 1.0

    def test_detect_ipv4_edge_cases(self):
        result = TargetDetector.detect("0.0.0.0")
        assert result.type == TargetType.IPV4

        result = TargetDetector.detect("255.255.255.255")
        assert result.type == TargetType.IPV4

    def test_detect_cidr(self):
        result = TargetDetector.detect("10.0.0.0/24")
        assert result.type == TargetType.CIDR
        assert result.metadata["network"] == "10.0.0.0"
        assert result.metadata["mask"] == "24"

    def test_detect_url_http(self):
        result = TargetDetector.detect("http://example.com/path")
        assert result.type == TargetType.URL
        assert result.normalized == "example.com"

    def test_detect_url_https(self):
        result = TargetDetector.detect("https://secure.example.com:8443/api")
        assert result.type == TargetType.URL
        assert result.normalized == "secure.example.com"

    def test_detect_email(self):
        result = TargetDetector.detect("admin@example.com")
        assert result.type == TargetType.EMAIL
        assert result.normalized == "example.com"
        assert result.metadata["email"] == "admin@example.com"

    def test_detect_host_port(self):
        result = TargetDetector.detect("example.com:8080")
        assert result.type == TargetType.PORT
        assert result.metadata["host"] == "example.com"
        assert result.metadata["port"] == 8080

    def test_detect_unknown(self):
        result = TargetDetector.detect("not a valid target!!!")
        assert result.type == TargetType.UNKNOWN
        assert result.confidence == 0.0

    def test_strips_whitespace(self):
        result = TargetDetector.detect("  example.com  ")
        assert result.type == TargetType.DOMAIN
        assert result.normalized == "example.com"

    def test_lowercases_input(self):
        result = TargetDetector.detect("EXAMPLE.COM")
        assert result.type == TargetType.DOMAIN
        assert result.normalized == "example.com"


# ── Templates ────────────────────────────────────────────────────────────


class TestScanTemplates:
    """Test scan template registry."""

    def test_list_templates_returns_all(self):
        templates = ScanTemplates.list_templates()
        ids = [t["id"] for t in templates]
        assert "quick" in ids
        assert "thorough" in ids
        assert "compliance" in ids
        assert "pentest" in ids
        assert "ecommerce" in ids
        assert "full" in ids

    def test_list_templates_structure(self):
        templates = ScanTemplates.list_templates()
        for t in templates:
            assert "id" in t
            assert "name" in t
            assert "description" in t
            assert "duration" in t
            assert "modules_count" in t
            assert "depth" in t
            assert t["modules_count"] > 0

    def test_get_template_exists(self):
        template = ScanTemplates.get_template("thorough")
        assert template is not None
        assert template.name == "Thorough Scan (15 min)"
        assert template.timeout_minutes == 15

    def test_get_template_case_insensitive(self):
        template = ScanTemplates.get_template("THOROUGH")
        assert template is not None

    def test_get_template_nonexistent(self):
        assert ScanTemplates.get_template("nonexistent") is None

    def test_ecommerce_template_config(self):
        template = ScanTemplates.get_template("ecommerce")
        assert template is not None
        assert template.config["scan_type"] == "ecommerce"
        assert "commerce_protocol" in template.enabled_modules

    def test_all_templates_have_scan_type(self):
        for name, config in ScanTemplates.TEMPLATES.items():
            assert "scan_type" in config.config, f"Template '{name}' missing scan_type"

    def test_recommend_domain(self):
        rec = ScanTemplates.recommend_template(TargetType.DOMAIN)
        assert rec == "thorough"

    def test_recommend_ip(self):
        rec = ScanTemplates.recommend_template(TargetType.IPV4)
        assert rec == "quick"

    def test_recommend_cidr(self):
        rec = ScanTemplates.recommend_template(TargetType.CIDR)
        assert rec == "pentest"

    def test_recommend_api(self):
        rec = ScanTemplates.recommend_template(TargetType.API)
        assert rec == "compliance"

    def test_recommend_unknown_fallback(self):
        rec = ScanTemplates.recommend_template(TargetType.UNKNOWN)
        assert rec == "quick"


# ── Validation ───────────────────────────────────────────────────────────


class TestScanWizardValidator:
    """Test wizard input validation."""

    def test_valid_target_domain(self):
        valid, error = ScanWizardValidator.validate_target("example.com")
        assert valid
        assert error == ""

    def test_empty_target(self):
        valid, error = ScanWizardValidator.validate_target("")
        assert not valid
        assert "empty" in error.lower()

    def test_whitespace_target(self):
        valid, error = ScanWizardValidator.validate_target("   ")
        assert not valid

    def test_too_long_target(self):
        valid, error = ScanWizardValidator.validate_target("a" * 1001)
        assert not valid
        assert "long" in error.lower()

    def test_unknown_target(self):
        valid, error = ScanWizardValidator.validate_target("!!!invalid!!!")
        assert not valid
        assert "could not determine" in error.lower()

    def test_valid_template(self):
        valid, error = ScanWizardValidator.validate_template("thorough")
        assert valid

    def test_empty_template(self):
        valid, error = ScanWizardValidator.validate_template("")
        assert not valid

    def test_invalid_template(self):
        valid, error = ScanWizardValidator.validate_template("nonexistent")
        assert not valid
        assert "invalid template" in error.lower()

    def test_validate_wizard_all_valid(self):
        is_valid, errors = ScanWizardValidator.validate_wizard_input(
            "example.com", "thorough"
        )
        assert is_valid
        assert errors == {}

    def test_validate_wizard_bad_target(self):
        is_valid, errors = ScanWizardValidator.validate_wizard_input(
            "", "thorough"
        )
        assert not is_valid
        assert "target" in errors

    def test_validate_wizard_bad_template(self):
        is_valid, errors = ScanWizardValidator.validate_wizard_input(
            "example.com", "invalid"
        )
        assert not is_valid
        assert "template" in errors

    def test_validate_wizard_both_bad(self):
        is_valid, errors = ScanWizardValidator.validate_wizard_input(
            "", "invalid"
        )
        assert not is_valid
        assert "target" in errors
        assert "template" in errors

    def test_validate_wizard_with_custom_config(self):
        is_valid, errors = ScanWizardValidator.validate_wizard_input(
            "example.com", "quick", {"crawl_depth": 3}
        )
        assert is_valid


# ── Builder ──────────────────────────────────────────────────────────────


class TestScanWizardBuilder:
    """Test scan configuration builder."""

    def test_build_basic(self):
        config = ScanWizardBuilder.build("example.com", "quick")
        assert config["target"] == "example.com"
        assert "scan_type" in config

    def test_build_with_custom_config(self):
        config = ScanWizardBuilder.build(
            "example.com", "thorough", {"crawl_depth": 5}
        )
        assert config["crawl_depth"] == 5

    def test_build_ecommerce(self):
        config = ScanWizardBuilder.build("shop.example.com", "ecommerce")
        assert config["scan_type"] == "ecommerce"

    def test_build_preserves_template_config(self):
        config = ScanWizardBuilder.build("example.com", "pentest")
        assert config.get("scan_type") == "pentest"

    def test_build_url_target(self):
        config = ScanWizardBuilder.build("https://example.com/app", "quick")
        assert "target" in config
