"""
Executive Brief Generator — produces AI-powered, non-technical security summaries
suitable for C-level stakeholders, board reports, and client deliverables.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# IBM Cost of a Data Breach 2025 baseline figures (USD)
_BREACH_COST_BASELINE = 4_880_000  # average total cost
_BREACH_COST_PER_RECORD = 165      # per compromised record

# Industry benchmark risk scores (lower is better security posture)
_INDUSTRY_BENCHMARKS = {
    "web": {"avg": 42, "top_quartile": 25},
    "api": {"avg": 38, "top_quartile": 20},
    "network": {"avg": 45, "top_quartile": 28},
    "default": {"avg": 42, "top_quartile": 25},
}

# Remediation cost multipliers by severity
_REMEDIATION_COST = {
    "critical": 15000,
    "high": 8000,
    "medium": 3000,
    "low": 500,
    "info": 0,
}

# Breach probability by risk score
def _breach_probability(risk_score: float) -> float:
    if risk_score >= 80:
        return 0.65
    if risk_score >= 60:
        return 0.40
    if risk_score >= 40:
        return 0.20
    if risk_score >= 20:
        return 0.08
    return 0.03


def _risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Minimal"


def _risk_color(score: float) -> str:
    if score >= 75:
        return "#dc3545"
    if score >= 55:
        return "#fd7e14"
    if score >= 35:
        return "#ffc107"
    if score >= 15:
        return "#17a2b8"
    return "#28a745"


def _remediation_timeline(risk_score: float, critical: int, high: int) -> dict:
    if risk_score >= 75 or critical > 0:
        return {
            "immediate": "0–30 days: Patch all critical vulnerabilities, isolate affected systems",
            "short_term": "30–90 days: Remediate high-severity findings, implement security monitoring",
            "long_term": "90–180 days: Address medium findings, security architecture review",
            "target_posture": "6 months to achieve Low risk posture",
        }
    if risk_score >= 55 or high > 0:
        return {
            "immediate": "0–30 days: Remediate high-severity findings",
            "short_term": "30–60 days: Address medium findings, patch management review",
            "long_term": "60–120 days: Implement security enhancements and controls",
            "target_posture": "4 months to achieve Low risk posture",
        }
    return {
        "immediate": "0–14 days: Address any remaining medium findings",
        "short_term": "14–45 days: Harden configurations, review access controls",
        "long_term": "45–90 days: Continuous monitoring and quarterly re-assessment",
        "target_posture": "3 months to achieve Minimal risk posture",
    }


def _generate_risk_matrix_svg(findings: list[dict]) -> str:
    """Generate an SVG 2×2 risk matrix (likelihood vs impact)."""

    # Map severity to (likelihood, impact) coordinates (0–10 scale)
    _sev_coords = {
        "critical": (8.5, 8.5),
        "high":     (7.0, 6.5),
        "medium":   (5.0, 4.5),
        "low":      (3.0, 2.5),
        "info":     (1.5, 1.0),
    }

    width, height = 360, 300
    pad = 50
    inner_w = width - pad * 2
    inner_h = height - pad * 2

    def cx(x: float) -> float:
        return pad + (x / 10) * inner_w

    def cy(y: float) -> float:
        return height - pad - (y / 10) * inner_h

    # Collect dots grouped by severity
    severity_groups: dict[str, list[tuple[float, float]]] = {}
    for f in findings:
        sev = f.get("severity", "info")
        coord = _sev_coords.get(sev, _sev_coords["info"])
        severity_groups.setdefault(sev, []).append(coord)

    dot_colors = {
        "critical": "#dc3545",
        "high":     "#fd7e14",
        "medium":   "#e6b800",
        "low":      "#17a2b8",
        "info":     "#6c757d",
    }

    # Build SVG
    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" style="font-family:sans-serif">',
        # Background quadrants
        f'<rect x="{pad}" y="{pad}" width="{inner_w//2}" height="{inner_h//2}" fill="#fff3cd" opacity="0.6"/>',
        f'<rect x="{pad + inner_w//2}" y="{pad}" width="{inner_w - inner_w//2}" height="{inner_h//2}" fill="#f8d7da" opacity="0.6"/>',
        f'<rect x="{pad}" y="{pad + inner_h//2}" width="{inner_w//2}" height="{inner_h - inner_h//2}" fill="#d4edda" opacity="0.6"/>',
        f'<rect x="{pad + inner_w//2}" y="{pad + inner_h//2}" width="{inner_w - inner_w//2}" height="{inner_h - inner_h//2}" fill="#fff3cd" opacity="0.6"/>',
        # Border
        f'<rect x="{pad}" y="{pad}" width="{inner_w}" height="{inner_h}" fill="none" stroke="#ccc" stroke-width="1"/>',
        # Dividers
        f'<line x1="{pad + inner_w//2}" y1="{pad}" x2="{pad + inner_w//2}" y2="{pad + inner_h}" stroke="#ccc" stroke-width="1" stroke-dasharray="4,4"/>',
        f'<line x1="{pad}" y1="{pad + inner_h//2}" x2="{pad + inner_w}" y2="{pad + inner_h//2}" stroke="#ccc" stroke-width="1" stroke-dasharray="4,4"/>',
        # Quadrant labels
        f'<text x="{pad + inner_w//4}" y="{pad + 16}" text-anchor="middle" font-size="10" fill="#856404">MEDIUM RISK</text>',
        f'<text x="{pad + 3*inner_w//4}" y="{pad + 16}" text-anchor="middle" font-size="10" fill="#721c24">HIGH RISK</text>',
        f'<text x="{pad + inner_w//4}" y="{pad + inner_h//2 + 16}" text-anchor="middle" font-size="10" fill="#155724">LOW RISK</text>',
        f'<text x="{pad + 3*inner_w//4}" y="{pad + inner_h//2 + 16}" text-anchor="middle" font-size="10" fill="#856404">MEDIUM RISK</text>',
        # Axis labels
        f'<text x="{pad + inner_w//2}" y="{height - 8}" text-anchor="middle" font-size="12" fill="#555">Likelihood →</text>',
        f'<text x="14" y="{pad + inner_h//2}" text-anchor="middle" font-size="12" fill="#555" transform="rotate(-90, 14, {pad + inner_h//2})">Impact →</text>',
        # Title
        f'<text x="{width//2}" y="18" text-anchor="middle" font-size="13" font-weight="bold" fill="#333">Risk Matrix</text>',
    ]

    # Plot dots (jitter overlapping points slightly)
    jitter_offsets = [(0, 0), (8, 0), (-8, 0), (0, 8), (0, -8), (8, 8), (-8, -8)]
    for sev, coords_list in severity_groups.items():
        color = dot_colors.get(sev, "#999")
        for idx, (lx, ly) in enumerate(coords_list):
            jx, jy = jitter_offsets[idx % len(jitter_offsets)]
            px = cx(lx) + jx
            py = cy(ly) + jy
            count = len([c for c in coords_list[:idx+1] if c == (lx, ly)])
            r = min(6 + (count - 1) * 2, 12)
            svg_lines.append(
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{r}" fill="{color}" '
                f'opacity="0.85" stroke="white" stroke-width="1"/>'
            )

    # Legend
    legend_x = pad
    legend_y = height - 8
    for i, (sev, color) in enumerate(dot_colors.items()):
        lx = legend_x + i * 64
        svg_lines.append(
            f'<circle cx="{lx + 6}" cy="{legend_y}" r="5" fill="{color}"/>'
            f'<text x="{lx + 14}" y="{legend_y + 4}" font-size="10" fill="#555">{sev.capitalize()}</text>'
        )

    svg_lines.append("</svg>")
    return "\n".join(svg_lines)


def _generate_ai_content(
    report: dict,
    scan_info: dict,
    top_risks: list[dict],
    risk_score: float,
    severity_counts: dict,
    financial_exposure: dict,
) -> dict:
    """Use Claude to generate plain-English executive content."""
    try:
        import anthropic
        from modules.config import AI_MODEL_LIGHT

        target = scan_info.get("target", "the target system")
        risk_lvl = _risk_level(risk_score)
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)

        top_risks_text = "\n".join(
            f"- {r['title']} ({r['severity'].upper()}): {r.get('description', '')[:200]}"
            for r in top_risks
        )

        prompt = f"""You are a cybersecurity executive advisor. Write concise, non-technical content for a board-level security brief.

Target: {target}
Risk Score: {risk_score:.0f}/100 ({risk_lvl})
Critical findings: {critical}, High: {high}, Medium: {medium}
Top risks:
{top_risks_text}
Estimated financial exposure: ${financial_exposure.get('low_estimate', 0):,.0f}–${financial_exposure.get('high_estimate', 0):,.0f}

Respond with valid JSON containing exactly these keys:
{{
  "risk_summary": "<1–2 sentence plain-English risk summary for C-level executives>",
  "business_impact": "<2–3 sentences on business impact without technical jargon>",
  "budget_recommendation": "<1–2 sentences on recommended remediation budget>",
  "benchmark_comparison": "<1 sentence comparing to industry average>"
}}

Be direct, professional, and avoid all technical jargon. Use dollar figures from the exposure estimate."""

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=AI_MODEL_LIGHT,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as exc:
        log.warning("AI content generation failed, using fallback: %s", exc)
        return _fallback_content(scan_info, risk_score, severity_counts, financial_exposure)


def _fallback_content(
    scan_info: dict,
    risk_score: float,
    severity_counts: dict,
    financial_exposure: dict,
) -> dict:
    target = scan_info.get("target", "your system")
    risk_lvl = _risk_level(risk_score)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    low_est = financial_exposure.get("low_estimate", 0)
    high_est = financial_exposure.get("high_estimate", 0)

    risk_summary = (
        f"{target} has a {risk_lvl} Risk security posture (score: {risk_score:.0f}/100). "
        f"The assessment identified {critical} critical and {high} high-severity issues "
        f"requiring immediate attention."
    )
    business_impact = (
        f"The identified vulnerabilities could expose the organization to unauthorized access to customer data "
        f"and business-critical systems. Based on current industry data, the estimated financial exposure "
        f"ranges from ${low_est:,.0f} to ${high_est:,.0f} in the event of a breach."
    )
    budget_recommendation = (
        f"We recommend allocating budget for immediate remediation of critical and high-severity findings, "
        f"with an estimated remediation investment significantly lower than potential breach costs."
    )
    benchmark_comparison = (
        f"Your current risk score of {risk_score:.0f} is compared against an industry average of 42 for similar organizations."
    )
    return {
        "risk_summary": risk_summary,
        "business_impact": business_impact,
        "budget_recommendation": budget_recommendation,
        "benchmark_comparison": benchmark_comparison,
    }


def _get_top_risks(findings: list[dict], n: int = 3) -> list[dict]:
    """Return top N findings sorted by severity."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 4))
    return sorted_findings[:n]


def _calculate_financial_exposure(risk_score: float, severity_counts: dict) -> dict:
    prob = _breach_probability(risk_score)
    # Estimate affected records based on severity
    record_multiplier = (
        severity_counts.get("critical", 0) * 5000
        + severity_counts.get("high", 0) * 1000
        + severity_counts.get("medium", 0) * 100
    )
    estimated_records = max(record_multiplier, 500)

    low_estimate = int(prob * _BREACH_COST_BASELINE * 0.5)
    high_estimate = int(prob * _BREACH_COST_BASELINE * 1.5)
    per_record_total = estimated_records * _BREACH_COST_PER_RECORD

    return {
        "breach_probability_pct": int(prob * 100),
        "low_estimate": low_estimate,
        "high_estimate": high_estimate,
        "per_record_exposure": per_record_total,
        "estimated_records_at_risk": estimated_records,
        "source": "IBM Cost of a Data Breach Report 2025",
    }


def _calculate_remediation_budget(severity_counts: dict) -> dict:
    total = sum(
        _REMEDIATION_COST.get(sev, 0) * count
        for sev, count in severity_counts.items()
    )
    return {
        "estimated_total": total,
        "breakdown": {
            sev: _REMEDIATION_COST.get(sev, 0) * count
            for sev, count in severity_counts.items()
            if count > 0 and _REMEDIATION_COST.get(sev, 0) > 0
        },
    }


def _compare_with_previous(
    current_score: float,
    current_counts: dict,
    previous_scans: list[dict],
) -> dict | None:
    if not previous_scans:
        return None
    prev = previous_scans[0]
    prev_score = prev.get("risk_score") or 0
    delta = current_score - prev_score
    direction = "improved" if delta < 0 else ("worsened" if delta > 0 else "unchanged")
    return {
        "previous_score": prev_score,
        "current_score": current_score,
        "delta": round(delta, 1),
        "direction": direction,
        "previous_scan_id": prev.get("scan_id"),
        "previous_date": prev.get("date"),
    }


class ExecutiveBriefGenerator:
    """Generates AI-powered executive security briefs from scan data."""

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )

    def generate_brief(
        self,
        report: dict,
        scan_info: dict,
        previous_scans: list[dict] | None = None,
    ) -> dict:
        """Generate executive brief data dict from scan report."""
        risk_score = float(report.get("risk_score") or 0)
        findings = report.get("findings", [])

        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        top_risks = _get_top_risks(findings)
        financial = _calculate_financial_exposure(risk_score, severity_counts)
        budget = _calculate_remediation_budget(severity_counts)
        timeline = _remediation_timeline(
            risk_score,
            severity_counts.get("critical", 0),
            severity_counts.get("high", 0),
        )

        ai_content = _generate_ai_content(
            report, scan_info, top_risks, risk_score, severity_counts, financial
        )

        scan_type = scan_info.get("scan_type", "default")
        benchmark = _INDUSTRY_BENCHMARKS.get(scan_type, _INDUSTRY_BENCHMARKS["default"])

        comparison = _compare_with_previous(risk_score, severity_counts, previous_scans or [])

        risk_matrix_svg = _generate_risk_matrix_svg(findings)

        return {
            "risk_score": risk_score,
            "risk_level": _risk_level(risk_score),
            "risk_color": _risk_color(risk_score),
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "top_risks": top_risks,
            "financial_exposure": financial,
            "remediation_budget": budget,
            "timeline": timeline,
            "risk_summary": ai_content.get("risk_summary", ""),
            "business_impact": ai_content.get("business_impact", ""),
            "budget_recommendation": ai_content.get("budget_recommendation", ""),
            "benchmark_comparison": ai_content.get("benchmark_comparison", ""),
            "industry_benchmark": benchmark,
            "risk_matrix_svg": risk_matrix_svg,
            "comparison": comparison,
            "generated_at": datetime.utcnow().isoformat(),
            "scan_info": scan_info,
        }

    def generate_html(self, brief: dict) -> str:
        """Render executive brief as HTML."""
        template = self.env.get_template("executive_brief.html")
        return template.render(**brief)

    def generate_pdf(self, brief: dict) -> bytes:
        """Render executive brief as PDF."""
        try:
            from weasyprint import HTML
        except ImportError:
            raise RuntimeError(
                "weasyprint is required for PDF generation. "
                "Install with: pip install weasyprint"
            )
        html_content = self.generate_html(brief)
        return HTML(string=html_content).write_pdf()
