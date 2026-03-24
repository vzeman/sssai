"""
Scan Wizard - Guided workflow for creating security scans.
Includes target type detection and scan templates.
"""

import re
from typing import Optional, Dict, List, Literal
from dataclasses import dataclass
from enum import Enum


class TargetType(str, Enum):
    """Supported target types."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    PORT = "port"
    URL = "url"
    EMAIL = "email"
    MOBILE_APP = "mobile_app"
    API = "api"
    UNKNOWN = "unknown"


class ScanTemplate(str, Enum):
    """Predefined scan templates."""
    QUICK = "quick"  # 5 minutes
    THOROUGH = "thorough"  # 15 minutes
    COMPLIANCE = "compliance"  # 20 minutes
    PENTEST = "pentest"  # 30+ minutes
    FULL = "full"  # All modules


@dataclass
class TargetDetectionResult:
    """Result of target type detection."""
    target: str
    type: TargetType
    normalized: str  # Normalized form of target
    confidence: float  # 0.0 to 1.0
    metadata: Dict  # Additional metadata


@dataclass
class ScanTemplateConfig:
    """Scan template configuration."""
    name: str
    description: str
    duration_estimate: str
    enabled_modules: List[str]
    depth: Literal["shallow", "medium", "deep"]
    timeout_minutes: int
    parallelization: int
    config: Dict


class TargetDetector:
    """Detect target type and normalize input."""
    
    # Regex patterns for target detection
    PATTERNS = {
        "ipv4": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        "ipv6": r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$",
        "cidr": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$",
        "domain": r"^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$",
        "subdomain": r"^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.){2,}[a-z]{2,}$",
        "url": r"^https?://",
        "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        "port": r"^(\d{1,5})$",
    }
    
    @staticmethod
    def detect(target: str) -> TargetDetectionResult:
        """
        Detect target type from input string.
        
        Args:
            target: Target string (domain, IP, URL, etc.)
        
        Returns:
            TargetDetectionResult with detected type and metadata
        """
        target = target.strip().lower()
        
        # Check each pattern
        results = []
        
        # URL - extract domain
        if re.match(TargetDetector.PATTERNS["url"], target):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.netloc.split(":")[0]
            return TargetDetectionResult(
                target=target,
                type=TargetType.URL,
                normalized=domain,
                confidence=1.0,
                metadata={"original_url": target, "extracted_domain": domain}
            )
        
        # IPv4
        if re.match(TargetDetector.PATTERNS["ipv4"], target):
            return TargetDetectionResult(
                target=target,
                type=TargetType.IPV4,
                normalized=target,
                confidence=1.0,
                metadata={"version": 4}
            )
        
        # IPv6
        if re.match(TargetDetector.PATTERNS["ipv6"], target):
            return TargetDetectionResult(
                target=target,
                type=TargetType.IPV6,
                normalized=target,
                confidence=1.0,
                metadata={"version": 6}
            )
        
        # CIDR
        if re.match(TargetDetector.PATTERNS["cidr"], target):
            cidr_parts = target.split("/")
            return TargetDetectionResult(
                target=target,
                type=TargetType.CIDR,
                normalized=target,
                confidence=1.0,
                metadata={"network": cidr_parts[0], "mask": cidr_parts[1]}
            )
        
        # Email
        if re.match(TargetDetector.PATTERNS["email"], target):
            domain = target.split("@")[1]
            return TargetDetectionResult(
                target=target,
                type=TargetType.EMAIL,
                normalized=domain,
                confidence=1.0,
                metadata={"email": target, "domain": domain}
            )
        
        # Port (with IP)
        if ":" in target and not re.match(TargetDetector.PATTERNS["ipv6"], target):
            parts = target.rsplit(":", 1)
            if len(parts) == 2 and re.match(r"^\d+$", parts[1]):
                port = int(parts[1])
                if 1 <= port <= 65535:
                    return TargetDetectionResult(
                        target=target,
                        type=TargetType.PORT,
                        normalized=parts[0],
                        confidence=0.9,
                        metadata={"host": parts[0], "port": port}
                    )
        
        # Domain / Subdomain
        if re.match(TargetDetector.PATTERNS["domain"], target):
            # Count dots to distinguish domain vs subdomain
            dot_count = target.count(".")
            target_type = TargetType.SUBDOMAIN if dot_count >= 2 else TargetType.DOMAIN
            
            return TargetDetectionResult(
                target=target,
                type=target_type,
                normalized=target,
                confidence=0.95,
                metadata={"dot_count": dot_count}
            )
        
        # Unknown
        return TargetDetectionResult(
            target=target,
            type=TargetType.UNKNOWN,
            normalized=target,
            confidence=0.0,
            metadata={"reason": "Could not detect target type"}
        )


class ScanTemplates:
    """Predefined scan templates."""
    
    TEMPLATES: Dict[str, ScanTemplateConfig] = {
        "quick": ScanTemplateConfig(
            name="Quick Scan (5 min)",
            description="Fast surface-level scan. Good for quick health checks and basic vulnerability detection.",
            duration_estimate="5 minutes",
            enabled_modules=["dns", "http", "ssl", "common_cves"],
            depth="shallow",
            timeout_minutes=5,
            parallelization=1,
            config={
                "scan_type": "security",
                "quick_scan": True,
                "check_ssl": True,
                "dns_enum": True,
                "http_test": True,
                "vuln_scan": "basic",
            }
        ),
        "thorough": ScanTemplateConfig(
            name="Thorough Scan (15 min)",
            description="Comprehensive scan with subdomain enumeration and content discovery. Best for web applications.",
            duration_estimate="15 minutes",
            enabled_modules=["dns", "http", "ssl", "subdomains", "content_discovery", "web_vulns", "cves"],
            depth="medium",
            timeout_minutes=15,
            parallelization=3,
            config={
                "scan_type": "security",
                "subdomain_enum": True,
                "content_discovery": True,
                "check_ssl": True,
                "web_testing": True,
                "vuln_scan": "standard",
                "crawl_depth": 2,
            }
        ),
        "compliance": ScanTemplateConfig(
            name="Compliance Scan (20 min)",
            description="Focused on compliance frameworks (OWASP, CWE, CVSS). Generates compliance reports.",
            duration_estimate="20 minutes",
            enabled_modules=["ssl", "crypto", "authentication", "data_exposure", "api_testing", "compliance_check"],
            depth="deep",
            timeout_minutes=20,
            parallelization=2,
            config={
                "scan_type": "compliance",
                "frameworks": ["owasp_top_10", "cwe", "pci_dss"],
                "authentication_testing": True,
                "crypto_analysis": True,
                "data_classification": True,
                "compliance_report": True,
            }
        ),
        "pentest": ScanTemplateConfig(
            name="Pentest Scan (30+ min)",
            description="Deep penetration testing with exploitation attempts. For authorized testing only.",
            duration_estimate="30+ minutes",
            enabled_modules=["enum", "vulns", "exploit", "post_exploit", "reporting"],
            depth="deep",
            timeout_minutes=60,
            parallelization=4,
            config={
                "scan_type": "pentest",
                "aggressive": True,
                "exploitation": True,
                "post_exploitation": True,
                "privilege_escalation": True,
                "evidence_collection": True,
                "detailed_reporting": True,
            }
        ),
        "ecommerce": ScanTemplateConfig(
            name="E-Commerce Scan (20 min)",
            description="Validates UCP/ACP commerce protocols, payment security, PCI-DSS checks, and checkout flow testing.",
            duration_estimate="20 minutes",
            enabled_modules=["ssl", "http", "commerce_protocol", "api_testing", "web_vulns", "seo", "performance"],
            depth="deep",
            timeout_minutes=20,
            parallelization=3,
            config={
                "scan_type": "ecommerce",
                "check_ssl": True,
                "commerce_protocol_validation": True,
                "payment_security": True,
                "checkout_flow_testing": True,
                "pci_dss_checks": True,
                "seo_audit": True,
                "performance_check": True,
            }
        ),
        "full": ScanTemplateConfig(
            name="Full Audit (60+ min)",
            description="Complete security audit with all modules. Most comprehensive analysis.",
            duration_estimate="60+ minutes",
            enabled_modules=[
                "dns", "http", "ssl", "subdomains", "content_discovery",
                "web_vulns", "api_testing", "auth_testing", "crypto",
                "cves", "exploit", "compliance_check", "posture_score"
            ],
            depth="deep",
            timeout_minutes=120,
            parallelization=5,
            config={
                "scan_type": "full",
                "all_modules": True,
                "max_parallelization": True,
                "detailed_reporting": True,
                "evidence_collection": True,
                "remediation_suggestions": True,
            }
        ),
    }
    
    @staticmethod
    def get_template(template_name: str) -> Optional[ScanTemplateConfig]:
        """Get scan template by name."""
        return ScanTemplates.TEMPLATES.get(template_name.lower())
    
    @staticmethod
    def list_templates() -> List[Dict]:
        """List all available templates."""
        return [
            {
                "id": name,
                "name": config.name,
                "description": config.description,
                "duration": config.duration_estimate,
                "modules_count": len(config.enabled_modules),
                "depth": config.depth,
            }
            for name, config in ScanTemplates.TEMPLATES.items()
        ]
    
    @staticmethod
    def recommend_template(target_type: TargetType) -> str:
        """Recommend template based on target type."""
        recommendations = {
            TargetType.DOMAIN: "thorough",
            TargetType.SUBDOMAIN: "thorough",
            TargetType.URL: "thorough",
            TargetType.IPV4: "quick",
            TargetType.IPV6: "quick",
            TargetType.CIDR: "pentest",
            TargetType.API: "compliance",
            TargetType.EMAIL: "quick",
            TargetType.PORT: "quick",
            TargetType.MOBILE_APP: "thorough",
            TargetType.UNKNOWN: "quick",
        }
        return recommendations.get(target_type, "quick")


class ScanWizardValidator:
    """Validate scan wizard inputs."""
    
    @staticmethod
    def validate_target(target: str) -> tuple[bool, str]:
        """
        Validate target input.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not target or not target.strip():
            return False, "Target cannot be empty"
        
        if len(target) > 1000:
            return False, "Target too long (max 1000 characters)"
        
        # Detect type
        detection = TargetDetector.detect(target)
        
        if detection.type == TargetType.UNKNOWN:
            return False, f"Could not determine target type: {detection.metadata.get('reason')}"
        
        return True, ""
    
    @staticmethod
    def validate_template(template_name: str) -> tuple[bool, str]:
        """
        Validate template selection.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not template_name or not template_name.strip():
            return False, "Template cannot be empty"
        
        if template_name.lower() not in ScanTemplates.TEMPLATES:
            valid_templates = ", ".join(ScanTemplates.TEMPLATES.keys())
            return False, f"Invalid template. Choose from: {valid_templates}"
        
        return True, ""
    
    @staticmethod
    def validate_wizard_input(
        target: str,
        template: str,
        custom_config: Optional[Dict] = None
    ) -> tuple[bool, Dict]:
        """
        Validate complete wizard input.
        
        Returns:
            Tuple of (is_valid, errors_dict)
        """
        errors = {}
        
        # Validate target
        target_valid, target_error = ScanWizardValidator.validate_target(target)
        if not target_valid:
            errors["target"] = target_error
        
        # Validate template
        template_valid, template_error = ScanWizardValidator.validate_template(template)
        if not template_valid:
            errors["template"] = template_error
        
        # Validate custom config
        if custom_config:
            if not isinstance(custom_config, dict):
                errors["custom_config"] = "Custom config must be a JSON object"
        
        return len(errors) == 0, errors


class ScanWizardBuilder:
    """Build scan configuration from wizard input."""
    
    @staticmethod
    def build(
        target: str,
        template_name: str,
        custom_config: Optional[Dict] = None
    ) -> Dict:
        """
        Build complete scan configuration.
        
        Args:
            target: Target to scan
            template_name: Template name (quick, thorough, etc.)
            custom_config: Optional overrides
        
        Returns:
            Complete scan configuration
        """
        # Detect target type
        detection = TargetDetector.detect(target)
        
        # Get template
        template = ScanTemplates.get_template(template_name)
        
        # Build config
        config = {
            "target": detection.normalized,
            "target_type": detection.type.value,
            "target_original": target,
            "template": template_name,
            "scan_type": template.config.get("scan_type", "security"),
            **template.config,
        }
        
        # Apply custom overrides
        if custom_config:
            config.update(custom_config)
        
        return config
