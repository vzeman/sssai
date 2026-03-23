"""
Integration module for exploitation_engine and correlation_engine with AutonomousAgent

This module provides the integration hooks between the autonomous agent, exploitation
framework, and correlation engine to enable:
1. Automated exploitation (Issue #51)
2. Real-time vulnerability correlation (Issue #52)
"""

import logging
from typing import Dict, List, Any, Optional

from modules.agent.autonomous_agent import AutonomousAgent, DecisionContext
from modules.agent.exploitation_engine import ExploitationFramework
from modules.agent.correlation_engine import (
    VulnerabilityCorrelator,
    create_vulnerability_from_finding,
)

log = logging.getLogger(__name__)


class EnhancedAutonomousAgent(AutonomousAgent):
    """
    Enhanced autonomous agent with exploitation and correlation capabilities.
    
    Extends the base AutonomousAgent to:
    - Automatically generate and execute exploits for findings
    - Correlate vulnerabilities across scans to detect attack chains
    - Track exploit success rates
    - Collect evidence from exploitation
    """
    
    def __init__(self, scan_id: str, target: str, scan_type: str = "standard"):
        """Initialize enhanced agent with exploitation and correlation engines."""
        super().__init__(scan_id, target, scan_type)
        
        self.exploitation_framework = ExploitationFramework(target)
        self.vulnerability_correlator = VulnerabilityCorrelator(target)
        self.exploitation_reports = []
        self.correlation_report = None
    
    def run_with_exploitation(self, max_findings_to_exploit: int = 10) -> Dict[str, Any]:
        """
        Run autonomous scan with automated exploitation.
        
        Args:
            max_findings_to_exploit: Maximum number of findings to attempt exploitation on
        
        Returns:
            Extended report including exploitation results
        """
        # Run standard autonomous scan
        base_report = self.run()
        
        # Extract findings from report
        findings = base_report.get("findings", [])
        
        if findings:
            log.info(f"Running exploitation on {min(len(findings), max_findings_to_exploit)} findings")
            
            # Filter findings that should be exploited
            exploitable = self._filter_exploitable_findings(findings)[:max_findings_to_exploit]
            
            # Run exploitation
            exploitation_reports = self.exploitation_framework.exploit_findings(
                exploitable
            )
            
            self.exploitation_reports = exploitation_reports
            
            # Add exploitation data to report
            base_report["exploitation"] = {
                "total_findings_exploited": len(exploitation_reports),
                "total_successful_exploits": sum(
                    r.successful_attempts for r in exploitation_reports
                ),
                "overall_success_rate": self.exploitation_framework.get_success_rates()["overall_rate"],
                "reports": [self._serialize_exploitation_report(r) for r in exploitation_reports],
            }
        else:
            log.warning("No findings to exploit")
            base_report["exploitation"] = {
                "total_findings_exploited": 0,
                "total_successful_exploits": 0,
                "overall_success_rate": 0.0,
                "reports": [],
            }
        
        return base_report
    
    def run_with_correlation(self) -> Dict[str, Any]:
        """
        Run autonomous scan with vulnerability correlation analysis.
        
        Returns:
            Report including correlation analysis and attack chain detection
        """
        # Run standard autonomous scan
        base_report = self.run()
        
        # Extract findings
        findings = base_report.get("findings", [])
        
        if findings and len(findings) >= 2:
            log.info(f"Performing correlation analysis on {len(findings)} findings")
            
            # Convert findings to Vulnerability objects
            vulns = [create_vulnerability_from_finding(f) for f in findings]
            
            # Run correlation analysis
            self.vulnerability_correlator.add_vulnerabilities(vulns)
            self.correlation_report = self.vulnerability_correlator.analyze()
            
            # Add correlation data to report
            base_report["correlation"] = {
                "total_vulnerabilities_analyzed": self.correlation_report.total_vulnerabilities,
                "attack_chains_detected": len(self.correlation_report.attack_chains),
                "patterns_detected": len(self.correlation_report.patterns_detected),
                "anomalies_detected": len(self.correlation_report.anomalies),
                "overall_risk_increase": self.correlation_report.overall_risk_increase,
                "attack_chains": self._serialize_attack_chains(self.correlation_report.attack_chains),
                "anomalies": self._serialize_anomalies(self.correlation_report.anomalies),
            }
        else:
            log.warning("Need at least 2 findings for correlation analysis")
            base_report["correlation"] = {
                "total_vulnerabilities_analyzed": len(findings),
                "attack_chains_detected": 0,
                "patterns_detected": 0,
                "anomalies_detected": 0,
                "overall_risk_increase": 0.0,
            }
        
        return base_report
    
    def run_with_full_phase2(self, max_findings_to_exploit: int = 10) -> Dict[str, Any]:
        """
        Run complete Phase 2 autonomous security assessment.
        
        Combines:
        1. Autonomous agent (Discovery → Exploitation → Reporting)
        2. Exploitation framework (POC generation and execution)
        3. Correlation engine (Attack chain detection)
        
        Args:
            max_findings_to_exploit: Maximum findings to attempt exploitation
        
        Returns:
            Comprehensive Phase 2 report
        """
        log.info(f"Starting Phase 2 full assessment for {self.context.target}")
        
        # Run with both exploitation and correlation
        report = self.run()
        findings = report.get("findings", [])
        
        # Exploitation phase
        if findings:
            log.info(f"Phase 2A: Exploitation - {len(findings)} findings")
            exploitable = self._filter_exploitable_findings(findings)[:max_findings_to_exploit]
            
            if exploitable:
                exploitation_reports = self.exploitation_framework.exploit_findings(exploitable)
                self.exploitation_reports = exploitation_reports
                
                report["exploitation"] = {
                    "findings_exploited": len(exploitation_reports),
                    "successful": sum(r.successful_attempts for r in exploitation_reports),
                    "success_rate": self.exploitation_framework.get_success_rates()["overall_rate"],
                    "by_type": self.exploitation_framework.get_success_rates()["by_type"],
                }
            else:
                report["exploitation"] = {
                    "findings_exploited": 0,
                    "successful": 0,
                    "success_rate": 0.0,
                }
        
        # Correlation phase
        if findings and len(findings) >= 2:
            log.info(f"Phase 2B: Correlation - {len(findings)} findings")
            vulns = [create_vulnerability_from_finding(f) for f in findings]
            
            self.vulnerability_correlator.add_vulnerabilities(vulns)
            self.correlation_report = self.vulnerability_correlator.analyze()
            
            report["correlation"] = {
                "vulnerabilities_analyzed": self.correlation_report.total_vulnerabilities,
                "attack_chains": len(self.correlation_report.attack_chains),
                "chains_data": self._serialize_attack_chains(self.correlation_report.attack_chains),
                "anomalies": len(self.correlation_report.anomalies),
                "anomalies_data": self._serialize_anomalies(self.correlation_report.anomalies),
                "risk_increase": self.correlation_report.overall_risk_increase,
            }
        
        # Summary
        report["phase2_summary"] = {
            "autonomous_agent_complete": True,
            "exploitation_complete": "exploitation" in report,
            "correlation_complete": "correlation" in report,
            "timestamp": report.get("timestamp"),
        }
        
        log.info("Phase 2 assessment complete")
        return report
    
    def _filter_exploitable_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter findings that should be exploited."""
        exploitable = []
        
        # Only exploit findings that are safe and research-oriented
        safe_categories = {
            "xss", "sqli", "idor", "ssrf", "csrf", "xxe",
            "path traversal", "authentication", "information disclosure"
        }
        
        for finding in findings:
            category = finding.get("category", "").lower()
            finding_type = finding.get("type", "").lower()
            severity = finding.get("severity", "").lower()
            
            # Check if category is safe to exploit
            if any(cat in category or cat in finding_type for cat in safe_categories):
                # Only exploit high/critical severity by default
                if severity in ["critical", "high"]:
                    exploitable.append(finding)
        
        return exploitable
    
    @staticmethod
    def _serialize_exploitation_report(report) -> Dict[str, Any]:
        """Serialize exploitation report for JSON output."""
        return {
            "finding_id": report.finding_id,
            "target": report.target,
            "total_attempts": report.total_attempts,
            "successful_attempts": report.successful_attempts,
            "success_rate": report.success_rate,
            "overall_success": report.overall_success,
            "timestamp": report.timestamp,
        }
    
    @staticmethod
    def _serialize_attack_chains(chains) -> List[Dict[str, Any]]:
        """Serialize attack chains for JSON output."""
        return [
            {
                "chain_id": chain.chain_id,
                "chain_type": chain.chain_type,
                "severity": chain.severity.value,
                "description": chain.description,
                "confidence": chain.confidence,
                "impact": chain.impact,
                "vulnerabilities": [v.id for v in chain.vulnerabilities],
                "steps": chain.steps,
            }
            for chain in chains
        ]
    
    @staticmethod
    def _serialize_anomalies(anomalies) -> List[Dict[str, Any]]:
        """Serialize anomalies for JSON output."""
        return [
            {
                "anomaly_id": anomaly.anomaly_id,
                "anomaly_type": anomaly.anomaly_type,
                "severity": anomaly.severity,
                "description": anomaly.description,
                "confidence": anomaly.confidence,
                "recommendation": anomaly.recommendation,
            }
            for anomaly in anomalies
        ]


def run_phase2_assessment(
    scan_id: str,
    target: str,
    scan_type: str = "standard",
    exploit: bool = True,
    correlate: bool = True,
    max_findings_to_exploit: int = 10,
) -> Dict[str, Any]:
    """
    Run a complete Phase 2 security assessment.
    
    Args:
        scan_id: Unique scan identifier
        target: Target URL or system
        scan_type: Type of scan ('standard', 'aggressive', 'passive')
        exploit: Enable automated exploitation (Issue #51)
        correlate: Enable vulnerability correlation (Issue #52)
        max_findings_to_exploit: Maximum findings to attempt exploitation
    
    Returns:
        Comprehensive Phase 2 report
    """
    agent = EnhancedAutonomousAgent(scan_id, target, scan_type)
    
    if exploit and correlate:
        return agent.run_with_full_phase2(max_findings_to_exploit)
    elif exploit:
        return agent.run_with_exploitation(max_findings_to_exploit)
    elif correlate:
        return agent.run_with_correlation()
    else:
        return agent.run()
