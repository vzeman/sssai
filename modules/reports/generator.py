"""
Report generator — produces HTML and PDF reports from scan results.
Uses Jinja2 for templating and WeasyPrint for PDF.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates formatted reports from scan JSON data."""

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["severity_badge"] = self._severity_badge
        self.env.filters["risk_color"] = self._risk_color

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }.get(severity, "#6c757d")

    @staticmethod
    def _severity_badge(severity: str) -> str:
        color = ReportGenerator._severity_color(severity)
        return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{severity.upper()}</span>'

    @staticmethod
    def _risk_color(score: float) -> str:
        if score >= 80:
            return "#dc3545"
        if score >= 60:
            return "#fd7e14"
        if score >= 40:
            return "#ffc107"
        if score >= 20:
            return "#17a2b8"
        return "#28a745"

    def _build_compliance_reports(self, report: dict) -> dict:
        """Generate compliance reports, using agent-provided data or auto-mapping from findings."""
        # If agent already provided detailed compliance_reports, use them
        if report.get("compliance_reports"):
            return report["compliance_reports"]
        # Auto-generate from findings using the compliance mapper
        try:
            from modules.reports.compliance_mapper import generate_compliance_reports
            return generate_compliance_reports(report)
        except Exception as e:
            log.warning("compliance_mapper failed: %s", e)
            return {}

    def generate_html(self, report: dict, scan_info: dict | None = None) -> str:
        """Generate an HTML report from scan data."""
        template = self.env.get_template("report.html")

        # Prepare context
        findings = report.get("findings", [])
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Build compliance reports for compliance scan types or when compliance data exists
        scan_type = (scan_info or {}).get("scan_type", "")
        has_compliance_data = bool(
            report.get("compliance_summary") or
            report.get("compliance_reports") or
            scan_type in ("compliance", "compliance_audit", "full")
        )
        compliance_reports = self._build_compliance_reports(report) if has_compliance_data else {}

        context = {
            "report": report,
            "scan": scan_info or {},
            "generated_at": datetime.utcnow().isoformat(),
            "findings_by_severity": by_severity,
            "severity_order": ["critical", "high", "medium", "low", "info"],
            "total_findings": len(findings),
            "compliance_reports": compliance_reports,
            "has_compliance": bool(compliance_reports),
        }

        return template.render(**context)

    def generate_pdf(self, report: dict, scan_info: dict | None = None) -> bytes:
        """Generate a PDF report from scan data."""
        try:
            from weasyprint import HTML
        except ImportError:
            raise RuntimeError("weasyprint is required for PDF generation. Install with: pip install weasyprint")

        html_content = self.generate_html(report, scan_info)
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes

    def generate_json(self, report: dict, scan_info: dict | None = None) -> str:
        """Generate a formatted JSON report."""
        output = {
            "generated_at": datetime.utcnow().isoformat(),
            "scan_info": scan_info or {},
            **report,
        }
        return json.dumps(output, indent=2)
