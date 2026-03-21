"""
Multi-channel notification dispatcher.
Sends alerts via email, Slack, Discord, and webhooks.
"""

import json
import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)


@dataclass
class Notification:
    """A notification to send."""
    title: str
    message: str
    severity: str = "info"  # info, warning, critical
    scan_id: str | None = None
    target: str | None = None
    risk_score: float | None = None
    findings_count: int | None = None
    report_url: str | None = None
    metadata: dict | None = None


class NotificationDispatcher:
    """Dispatches notifications to configured channels."""

    def __init__(self, channels: list[dict]):
        """
        channels: list of dicts with keys:
            - type: "email" | "slack" | "discord" | "webhook" | "openclaw"
            - config: channel-specific configuration
            - min_severity: minimum severity to trigger (default: "info")
        """
        self.channels = channels
        self._severity_levels = {"info": 0, "warning": 1, "critical": 2}

    def should_notify(self, channel: dict, notification: Notification) -> bool:
        min_sev = channel.get("min_severity", "info")
        return self._severity_levels.get(notification.severity, 0) >= self._severity_levels.get(min_sev, 0)

    async def dispatch(self, notification: Notification):
        """Send notification to all configured channels."""
        for channel in self.channels:
            if not self.should_notify(channel, notification):
                continue
            try:
                handler = getattr(self, f"_send_{channel['type']}", None)
                if handler:
                    await handler(channel["config"], notification)
                else:
                    log.warning("Unknown channel type: %s", channel["type"])
            except Exception as e:
                log.error("Failed to send %s notification: %s", channel["type"], e)

    async def _send_slack(self, config: dict, notification: Notification):
        """Send Slack notification via incoming webhook."""
        webhook_url = config["webhook_url"]
        color = {"info": "#36a64f", "warning": "#ff9900", "critical": "#ff0000"}.get(notification.severity, "#36a64f")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": notification.title},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": notification.message},
            },
        ]

        fields = []
        if notification.target:
            fields.append({"type": "mrkdwn", "text": f"*Target:* {notification.target}"})
        if notification.risk_score is not None:
            fields.append({"type": "mrkdwn", "text": f"*Risk Score:* {notification.risk_score}/100"})
        if notification.findings_count is not None:
            fields.append({"type": "mrkdwn", "text": f"*Findings:* {notification.findings_count}"})
        if notification.severity:
            fields.append({"type": "mrkdwn", "text": f"*Severity:* {notification.severity.upper()}"})

        if fields:
            blocks.append({"type": "section", "fields": fields})

        if notification.report_url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report"},
                    "url": notification.report_url,
                }],
            })

        payload = {
            "attachments": [{"color": color, "blocks": blocks}],
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            log.info("Slack notification sent: %s", notification.title)

    async def _send_discord(self, config: dict, notification: Notification):
        """Send Discord notification via webhook."""
        webhook_url = config["webhook_url"]
        color = {"info": 0x36A64F, "warning": 0xFF9900, "critical": 0xFF0000}.get(notification.severity, 0x36A64F)

        embed = {
            "title": notification.title,
            "description": notification.message,
            "color": color,
            "fields": [],
        }

        if notification.target:
            embed["fields"].append({"name": "Target", "value": notification.target, "inline": True})
        if notification.risk_score is not None:
            embed["fields"].append({"name": "Risk Score", "value": f"{notification.risk_score}/100", "inline": True})
        if notification.findings_count is not None:
            embed["fields"].append({"name": "Findings", "value": str(notification.findings_count), "inline": True})
        if notification.report_url:
            embed["fields"].append({"name": "Report", "value": f"[View Report]({notification.report_url})"})

        payload = {"embeds": [embed]}

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            log.info("Discord notification sent: %s", notification.title)

    async def _send_webhook(self, config: dict, notification: Notification):
        """Send generic webhook notification (POST JSON)."""
        url = config["url"]
        headers = config.get("headers", {})

        payload = {
            "title": notification.title,
            "message": notification.message,
            "severity": notification.severity,
            "scan_id": notification.scan_id,
            "target": notification.target,
            "risk_score": notification.risk_score,
            "findings_count": notification.findings_count,
            "report_url": notification.report_url,
            "metadata": notification.metadata,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            log.info("Webhook notification sent: %s -> %s", notification.title, url)

    async def _send_email(self, config: dict, notification: Notification):
        """Send email notification via SMTP."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{notification.severity.upper()}] {notification.title}"
        msg["From"] = config.get("from_email", "scanner@localhost")
        msg["To"] = config["to_email"]

        text_body = f"{notification.title}\n\n{notification.message}"
        if notification.target:
            text_body += f"\n\nTarget: {notification.target}"
        if notification.risk_score is not None:
            text_body += f"\nRisk Score: {notification.risk_score}/100"
        if notification.findings_count is not None:
            text_body += f"\nFindings: {notification.findings_count}"
        if notification.report_url:
            text_body += f"\n\nView Report: {notification.report_url}"

        html_body = f"""
        <h2>{notification.title}</h2>
        <p>{notification.message}</p>
        <table>
            {"<tr><td><b>Target:</b></td><td>" + notification.target + "</td></tr>" if notification.target else ""}
            {"<tr><td><b>Risk Score:</b></td><td>" + str(notification.risk_score) + "/100</td></tr>" if notification.risk_score is not None else ""}
            {"<tr><td><b>Findings:</b></td><td>" + str(notification.findings_count) + "</td></tr>" if notification.findings_count is not None else ""}
        </table>
        {"<p><a href='" + notification.report_url + "'>View Full Report</a></p>" if notification.report_url else ""}
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        smtp = smtplib.SMTP(config.get("smtp_host", "localhost"), config.get("smtp_port", 587))
        smtp.starttls()
        if config.get("smtp_user"):
            smtp.login(config["smtp_user"], config["smtp_password"])
        smtp.send_message(msg)
        smtp.quit()
        log.info("Email notification sent: %s -> %s", notification.title, config["to_email"])

    async def _send_openclaw(self, config: dict, notification: Notification):
        """Send notification via OpenClaw gateway API for multi-channel distribution."""
        gateway_url = config.get("gateway_url", "http://localhost:3080")
        channel = config.get("channel", "default")

        payload = {
            "channel": channel,
            "message": {
                "text": f"**{notification.title}**\n\n{notification.message}",
                "metadata": {
                    "severity": notification.severity,
                    "scan_id": notification.scan_id,
                    "target": notification.target,
                    "risk_score": notification.risk_score,
                    "findings_count": notification.findings_count,
                    "report_url": notification.report_url,
                },
            },
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{gateway_url}/api/v1/messages", json=payload)
            resp.raise_for_status()
            log.info("OpenClaw notification sent: %s -> %s", notification.title, channel)


def build_scan_notification(scan_id: str, target: str, report: dict) -> Notification:
    """Build a notification from a completed scan report."""
    risk_score = report.get("risk_score", 0)
    findings = report.get("findings", [])
    findings_count = len(findings)

    # Determine severity from risk score
    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 50:
        severity = "warning"
    else:
        severity = "info"

    # Count by severity
    by_severity = {}
    for f in findings:
        s = f.get("severity", "info")
        by_severity[s] = by_severity.get(s, 0) + 1

    severity_summary = ", ".join(f"{count} {sev}" for sev, count in sorted(by_severity.items()))

    message = report.get("summary", "Scan completed.")
    if severity_summary:
        message += f"\n\nFindings breakdown: {severity_summary}"

    return Notification(
        title=f"Scan Complete: {target}",
        message=message,
        severity=severity,
        scan_id=scan_id,
        target=target,
        risk_score=risk_score,
        findings_count=findings_count,
    )
