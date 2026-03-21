"""
OpenClaw integration — multi-channel AI agent orchestration.

OpenClaw provides:
- Multi-channel inbox (Slack, Discord, Telegram, WhatsApp, etc.)
- Multi-agent routing — route channels/accounts to isolated agents
- Live Canvas for visual workspaces
- Cron scheduling for periodic tasks
- Session management for stateful conversations

We use OpenClaw as:
1. Notification/alerting gateway — distribute scan results across channels
2. User interaction layer — accept scan commands via chat
3. Agent orchestrator — coordinate multi-agent scanning workflows
"""

import json
import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)


@dataclass
class OpenClawChannel:
    """A configured OpenClaw messaging channel."""
    name: str
    type: str  # slack, discord, telegram, whatsapp, email, webhook
    config: dict = field(default_factory=dict)
    agent_id: str | None = None


@dataclass
class OpenClawGateway:
    """
    Client for the OpenClaw local gateway API.
    Manages channels, sessions, and message routing.
    """
    gateway_url: str = "http://localhost:3080"
    api_key: str | None = None

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def send_message(self, channel: str, text: str, metadata: dict | None = None):
        """Send a message to an OpenClaw channel."""
        payload = {
            "channel": channel,
            "message": {"text": text, "metadata": metadata or {}},
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.gateway_url}/api/v1/messages",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def create_session(self, channel: str, agent_type: str = "scanner") -> dict:
        """Create a new agent session for a channel."""
        payload = {
            "channel": channel,
            "agent_type": agent_type,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.gateway_url}/api/v1/sessions",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def register_tool(self, tool_name: str, tool_config: dict):
        """Register a scanning tool with OpenClaw for agent use."""
        payload = {
            "name": tool_name,
            "config": tool_config,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.gateway_url}/api/v1/tools",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def send_scan_result(self, channel: str, scan_id: str, target: str, report: dict):
        """Send a formatted scan result to an OpenClaw channel."""
        risk_score = report.get("risk_score", 0)
        findings_count = len(report.get("findings", []))

        # Build severity breakdown
        by_severity = {}
        for f in report.get("findings", []):
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        severity_text = " | ".join(f"{sev}: {count}" for sev, count in sorted(by_severity.items()))

        text = (
            f"**Scan Complete: {target}**\n"
            f"Risk Score: **{risk_score}/100** | Findings: **{findings_count}**\n"
        )
        if severity_text:
            text += f"Breakdown: {severity_text}\n"
        text += f"\n{report.get('summary', '')}"

        metadata = {
            "type": "scan_result",
            "scan_id": scan_id,
            "target": target,
            "risk_score": risk_score,
            "findings_count": findings_count,
        }

        return await self.send_message(channel, text, metadata)

    async def setup_scan_command_handler(self, channel: str):
        """
        Register a command handler so users can trigger scans via chat.
        Example: /scan https://example.com security
        """
        payload = {
            "channel": channel,
            "commands": [
                {
                    "name": "scan",
                    "description": "Trigger a security scan",
                    "usage": "/scan <target_url> [scan_type]",
                    "handler": "scanner_agent",
                },
                {
                    "name": "status",
                    "description": "Check scan status",
                    "usage": "/status [scan_id]",
                    "handler": "scanner_agent",
                },
                {
                    "name": "report",
                    "description": "Get latest scan report",
                    "usage": "/report [scan_id]",
                    "handler": "scanner_agent",
                },
            ],
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.gateway_url}/api/v1/commands",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def generate_config(self, channels: list[OpenClawChannel]) -> dict:
        """Generate OpenClaw configuration for the scanner agent."""
        return {
            "gateway": {
                "url": self.gateway_url,
                "api_key": self.api_key,
            },
            "agent": {
                "name": "Security Scanner",
                "description": "Autonomous security scanning and monitoring agent",
                "type": "scanner",
            },
            "channels": [
                {
                    "name": ch.name,
                    "type": ch.type,
                    "config": ch.config,
                    "agent_id": ch.agent_id,
                }
                for ch in channels
            ],
            "tools": [
                "run_scan",
                "get_report",
                "check_status",
                "list_scans",
                "set_schedule",
            ],
            "cron": [
                {
                    "name": "health_check",
                    "schedule": "*/5 * * * *",
                    "action": "check_monitored_targets",
                },
            ],
        }
