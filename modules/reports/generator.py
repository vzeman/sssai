"""
Report generator — produces HTML and PDF reports from scan results.
Uses Jinja2 for templating and WeasyPrint for PDF.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

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
        self.env.filters["markdown_to_html"] = self._markdown_to_html

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
    def _markdown_to_html(text: str) -> Markup:
        """Convert basic markdown to HTML for report rendering."""
        if not text:
            return Markup("")
        # Escape HTML entities first
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        # Headers: ## Header → <h3>, ### Header → <h4>
        text = re.sub(r"^### (.+)$", r"<h4>\1</h4>", text, flags=re.MULTILINE)
        text = re.sub(r"^## (.+)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
        # Bold: **text** → <strong>text</strong>
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        # Italic: *text* → <em>text</em>
        text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
        # Inline code: `text` → <code>text</code>
        text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
        # Bullet lists: - item → <li>item</li>
        text = re.sub(r"^- (.+)$", r"<li>\1</li>", text, flags=re.MULTILINE)
        text = re.sub(r"(<li>.*</li>\n?)+", r"<ul>\g<0></ul>", text)
        # Numbered lists: 1. item → <li>item</li>
        text = re.sub(r"^\d+\.\s+(.+)$", r"<li>\1</li>", text, flags=re.MULTILINE)
        # Paragraphs: double newline → paragraph break
        text = re.sub(r"\n\n+", "</p><p>", text)
        # Single newlines → <br>
        text = text.replace("\n", "<br>")
        # Clean up empty tags
        text = re.sub(r"<p>\s*</p>", "", text)
        return Markup(f"<p>{text}</p>")

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

    def generate_html(self, report: dict, scan_info: dict | None = None) -> str:
        """Generate an HTML report from scan data."""
        template = self.env.get_template("report.html")

        # Prepare context
        findings = report.get("findings", [])
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        context = {
            "report": report,
            "scan": scan_info or {},
            "generated_at": datetime.utcnow().isoformat(),
            "findings_by_severity": by_severity,
            "severity_order": ["critical", "high", "medium", "low", "info"],
            "total_findings": len(findings),
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
