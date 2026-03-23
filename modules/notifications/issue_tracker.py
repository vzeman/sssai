"""
Issue tracker integration for automated ticket creation from scan findings.

Supports Jira, Linear, and GitHub Issues. Groups related findings into logical
tickets to avoid ticket spam, and manages ticket lifecycle (create, update,
close, reopen) across re-scans.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)

# ── Severity mappings ──────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_JIRA_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

_LINEAR_PRIORITY = {
    "critical": 1,  # Urgent
    "high": 2,      # High
    "medium": 3,    # Medium
    "low": 4,       # Low
    "info": 4,
}

_GITHUB_LABELS = {
    "critical": ["security", "critical", "priority: critical"],
    "high": ["security", "priority: high"],
    "medium": ["security", "priority: medium"],
    "low": ["security", "priority: low"],
    "info": ["security"],
}

# ── Finding grouping ───────────────────────────────────────────────────────────

_GROUP_KEYWORDS: list[tuple[str, str, list[str]]] = [
    ("security_headers", "Implement Security Headers", [
        "x-frame-options", "content-security-policy", "csp", "hsts",
        "strict-transport-security", "x-content-type", "referrer-policy",
        "permissions-policy", "feature-policy", "header",
    ]),
    ("tls_ssl", "TLS/SSL Configuration Hardening", [
        "ssl", "tls", "certificate", "cipher", "sslv", "tlsv",
        "weak cipher", "self-signed", "expired cert",
    ]),
    ("authentication", "Authentication & Session Security", [
        "authentication", "session", "cookie", "jwt", "token", "password",
        "login", "logout", "brute force", "credential", "oauth",
    ]),
    ("injection", "Injection Vulnerabilities", [
        "sql injection", "xss", "cross-site scripting", "command injection",
        "ssti", "template injection", "ldap injection", "xpath",
        "code injection", "injection",
    ]),
    ("access_control", "Access Control & CORS Issues", [
        "cors", "access control", "authorization", "privilege",
        "insecure direct object", "idor", "broken access",
    ]),
    ("information_disclosure", "Information Disclosure", [
        "disclosure", "exposure", "leak", "fingerprint", "version exposed",
        "stack trace", "error message", "sensitive data", "debug",
    ]),
    ("dependencies", "Vulnerable Dependencies & Libraries", [
        "cve-", "vulnerability", "outdated", "dependency", "library version",
        "component", "patch",
    ]),
    ("configuration", "Security Misconfiguration", [
        "misconfiguration", "default credential", "open redirect",
        "directory listing", "default page", "admin interface",
        "unnecessary service",
    ]),
]


def _finding_group_key(finding: dict) -> tuple[str, str]:
    """Return (group_key, group_title) for a finding based on its title/description."""
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("category", ""),
    ]).lower()

    for group_key, group_title, keywords in _GROUP_KEYWORDS:
        if any(kw in text for kw in keywords):
            return group_key, group_title

    return "other", "Other Security Findings"


@dataclass
class FindingGroup:
    """A logical grouping of related findings for a single ticket."""
    key: str
    title: str
    findings: list[dict] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(
            (f.get("severity", "info") for f in self.findings),
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
        )

    @property
    def fingerprint(self) -> str:
        """Stable hash of finding titles in this group for change detection."""
        titles = sorted(f.get("title", "") for f in self.findings)
        return hashlib.sha256(json.dumps(titles).encode()).hexdigest()[:16]

    @property
    def finding_titles(self) -> list[str]:
        return [f.get("title", "") for f in self.findings]


def group_findings(findings: list[dict], min_severity: str = "medium") -> list[FindingGroup]:
    """Group findings into logical ticket groups, filtered by min_severity."""
    min_level = _SEVERITY_ORDER.get(min_severity, 2)

    # Filter by min severity
    filtered = [
        f for f in findings
        if _SEVERITY_ORDER.get(f.get("severity", "info"), 0) >= min_level
    ]

    groups: dict[str, FindingGroup] = {}
    for finding in filtered:
        key, title = _finding_group_key(finding)
        if key not in groups:
            groups[key] = FindingGroup(key=key, title=title)
        groups[key].findings.append(finding)

    return list(groups.values())


# ── Ticket body formatting ─────────────────────────────────────────────────────

def _format_ticket_body(
    group: FindingGroup,
    target: str,
    scan_id: str,
    report_url: str | None,
    fmt: str = "markdown",
) -> str:
    """Build a structured ticket body from a finding group."""
    lines = []

    if fmt == "jira":
        lines += [
            f"h2. Security Findings: {group.title}",
            f"*Target:* {target}",
            f"*Severity:* {group.max_severity.upper()}",
            f"*Findings Count:* {len(group.findings)}",
            "",
        ]
        if report_url:
            lines.append(f"*Scan Report:* [{report_url}|{report_url}]")
        lines += ["", "h3. Findings", ""]
    else:
        lines += [
            f"## Security Findings: {group.title}",
            f"",
            f"**Target:** `{target}`  ",
            f"**Severity:** {group.max_severity.upper()}  ",
            f"**Findings Count:** {len(group.findings)}  ",
        ]
        if report_url:
            lines.append(f"**Scan Report:** {report_url}  ")
        lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(group.findings, 1):
        severity = f.get("severity", "info").upper()
        title = f.get("title", "Untitled")
        description = f.get("description", "")
        evidence = f.get("evidence", "")
        remediation = f.get("remediation", "")
        owasp = f.get("owasp", "") or f.get("cwe", "") or ""

        if fmt == "jira":
            lines += [
                f"h4. {i}. [{severity}] {title}",
                "",
                description,
                "",
            ]
            if evidence:
                lines += ["{code}", evidence[:500], "{code}", ""]
            if remediation:
                lines += [f"*Remediation:* {remediation}", ""]
            if owasp:
                lines += [f"*Reference:* {owasp}", ""]
        else:
            lines += [
                f"### {i}. [{severity}] {title}",
                "",
                description,
                "",
            ]
            if evidence:
                lines += [f"```\n{evidence[:500]}\n```", ""]
            if remediation:
                lines += [f"**Remediation:** {remediation}", ""]
            if owasp:
                lines += [f"**Reference:** {owasp}", ""]

    lines += [
        "",
        "---",
        f"*Auto-generated by SSSAI Security Scanner | Scan ID: `{scan_id}`*",
    ]
    return "\n".join(lines)


# ── Tracker state persistence ──────────────────────────────────────────────────

def _state_key(channel_id: str, target: str) -> str:
    slug = hashlib.md5(target.encode()).hexdigest()[:12]
    return f"tracker-state/{channel_id}/{slug}.json"


def _load_state(storage, channel_id: str, target: str) -> dict:
    key = _state_key(channel_id, target)
    try:
        return storage.get_json(key) or {}
    except Exception:
        return {}


def _save_state(storage, channel_id: str, target: str, state: dict):
    key = _state_key(channel_id, target)
    try:
        storage.put_json(key, state)
    except Exception as e:
        log.warning("Could not save tracker state: %s", e)


# ── Jira client ────────────────────────────────────────────────────────────────

class JiraClient:
    def __init__(self, config: dict):
        self.base_url = config["url"].rstrip("/")
        self.project = config["project"]
        self.api_token = config["api_token"]
        self.email = config.get("email", "")
        self.issue_type = config.get("issue_type", "Bug")
        self._auth = (self.email, self.api_token) if self.email else None
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def create_issue(self, summary: str, description: str, priority: str, labels: list[str]) -> str:
        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": priority},
                "labels": labels,
            }
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue",
                json=payload,
                auth=self._auth,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()["key"]

    async def update_issue(self, ticket_id: str, description: str, priority: str):
        payload = {
            "fields": {
                "description": description,
                "priority": {"name": priority},
            }
        }
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base_url}/rest/api/2/issue/{ticket_id}",
                json=payload,
                auth=self._auth,
                headers=self._headers,
            )
            resp.raise_for_status()

    async def transition_issue(self, ticket_id: str, status: str):
        """Transition issue to 'Done' (close) or 'To Do' (reopen) by finding valid transition."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/rest/api/2/issue/{ticket_id}/transitions",
                auth=self._auth,
                headers=self._headers,
            )
            resp.raise_for_status()
            transitions = resp.json().get("transitions", [])

        target_names = {
            "close": {"done", "closed", "resolved", "complete"},
            "reopen": {"to do", "open", "reopen", "backlog", "in progress"},
        }.get(status, set())

        transition_id = None
        for t in transitions:
            if t["name"].lower() in target_names:
                transition_id = t["id"]
                break

        if not transition_id:
            log.warning("No matching Jira transition for '%s' on %s", status, ticket_id)
            return

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue/{ticket_id}/transitions",
                json={"transition": {"id": transition_id}},
                auth=self._auth,
                headers=self._headers,
            )
            resp.raise_for_status()

    async def add_comment(self, ticket_id: str, comment: str):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue/{ticket_id}/comment",
                json={"body": comment},
                auth=self._auth,
                headers=self._headers,
            )
            resp.raise_for_status()


# ── Linear client ──────────────────────────────────────────────────────────────

class LinearClient:
    _API_URL = "https://api.linear.app/graphql"

    def __init__(self, config: dict):
        self.api_key = config["api_key"]
        self.team_id = config["team_id"]
        self._headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
        }

    async def _query(self, query: str, variables: dict) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._API_URL,
                json={"query": query, "variables": variables},
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data:
                raise ValueError(f"Linear API error: {data['errors']}")
            return data

    async def create_issue(self, title: str, description: str, priority: int, labels: list[str]) -> str:
        result = await self._query(
            """
            mutation CreateIssue($input: IssueCreateInput!) {
                issueCreate(input: $input) {
                    issue { id identifier }
                }
            }
            """,
            {"input": {
                "teamId": self.team_id,
                "title": title,
                "description": description,
                "priority": priority,
                "labelIds": [],  # label creation requires separate API calls
            }},
        )
        return result["data"]["issueCreate"]["issue"]["identifier"]

    async def update_issue(self, issue_id: str, description: str, priority: int):
        await self._query(
            """
            mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    issue { id }
                }
            }
            """,
            {"id": issue_id, "input": {"description": description, "priority": priority}},
        )

    async def close_issue(self, issue_id: str, reason: str = ""):
        # Get "Done" workflow state
        states = await self._query(
            """
            query States($teamId: String!) {
                team(id: $teamId) {
                    states { nodes { id name type } }
                }
            }
            """,
            {"teamId": self.team_id},
        )
        nodes = states["data"]["team"]["states"]["nodes"]
        done_state = next((n for n in nodes if n["type"] == "completed"), None)
        if not done_state:
            log.warning("No completed state found for Linear team %s", self.team_id)
            return

        await self._query(
            """
            mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    issue { id }
                }
            }
            """,
            {"id": issue_id, "input": {"stateId": done_state["id"]}},
        )
        if reason:
            await self.add_comment(issue_id, reason)

    async def reopen_issue(self, issue_id: str, reason: str = ""):
        # Get "Todo" workflow state
        states = await self._query(
            """
            query States($teamId: String!) {
                team(id: $teamId) {
                    states { nodes { id name type } }
                }
            }
            """,
            {"teamId": self.team_id},
        )
        nodes = states["data"]["team"]["states"]["nodes"]
        todo_state = next((n for n in nodes if n["type"] == "unstarted"), None)
        if not todo_state:
            return

        await self._query(
            """
            mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    issue { id }
                }
            }
            """,
            {"id": issue_id, "input": {"stateId": todo_state["id"]}},
        )
        if reason:
            await self.add_comment(issue_id, reason)

    async def add_comment(self, issue_id: str, body: str):
        await self._query(
            """
            mutation CreateComment($input: CommentCreateInput!) {
                commentCreate(input: $input) {
                    comment { id }
                }
            }
            """,
            {"input": {"issueId": issue_id, "body": body}},
        )


# ── GitHub Issues client ───────────────────────────────────────────────────────

class GitHubIssuesClient:
    _API_URL = "https://api.github.com"

    def __init__(self, config: dict):
        self.token = config["token"]
        self.owner = config["owner"]
        self.repo = config["repo"]
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def create_issue(self, title: str, body: str, labels: list[str]) -> int:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._API_URL}/repos/{self.owner}/{self.repo}/issues",
                json={"title": title, "body": body, "labels": labels},
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()["number"]

    async def update_issue(self, issue_number: int, body: str, labels: list[str]):
        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                f"{self._API_URL}/repos/{self.owner}/{self.repo}/issues/{issue_number}",
                json={"body": body, "labels": labels},
                headers=self._headers,
            )
            resp.raise_for_status()

    async def close_issue(self, issue_number: int, comment: str = ""):
        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                f"{self._API_URL}/repos/{self.owner}/{self.repo}/issues/{issue_number}",
                json={"state": "closed", "state_reason": "completed"},
                headers=self._headers,
            )
            resp.raise_for_status()
        if comment:
            await self.add_comment(issue_number, comment)

    async def reopen_issue(self, issue_number: int, comment: str = ""):
        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                f"{self._API_URL}/repos/{self.owner}/{self.repo}/issues/{issue_number}",
                json={"state": "open"},
                headers=self._headers,
            )
            resp.raise_for_status()
        if comment:
            await self.add_comment(issue_number, comment)

    async def add_comment(self, issue_number: int, body: str):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._API_URL}/repos/{self.owner}/{self.repo}/issues/{issue_number}/comments",
                json={"body": body},
                headers=self._headers,
            )
            resp.raise_for_status()


# ── Main dispatch logic ────────────────────────────────────────────────────────

async def dispatch_findings_to_jira(
    config: dict,
    channel_id: str,
    groups: list[FindingGroup],
    target: str,
    scan_id: str,
    report_url: str | None,
    storage,
    auto_close: bool = True,
):
    """Create/update/close Jira tickets from grouped findings."""
    client = JiraClient(config)
    state = _load_state(storage, channel_id, target)

    current_group_keys = {g.key for g in groups}

    # Auto-close resolved tickets
    if auto_close:
        for group_key, ticket_info in list(state.items()):
            if group_key not in current_group_keys and ticket_info.get("status") == "open":
                ticket_id = ticket_info["ticket_id"]
                try:
                    await client.transition_issue(ticket_id, "close")
                    await client.add_comment(
                        ticket_id,
                        f"Findings in this group were not detected in the latest scan of `{target}` "
                        f"(Scan ID: `{scan_id}`). Closing as resolved."
                    )
                    state[group_key]["status"] = "closed"
                    log.info("Closed Jira ticket %s (group: %s resolved)", ticket_id, group_key)
                except Exception as e:
                    log.warning("Failed to close Jira ticket %s: %s", ticket_id, e)

    for group in groups:
        body = _format_ticket_body(group, target, scan_id, report_url, fmt="jira")
        priority = _JIRA_PRIORITY.get(group.max_severity, "Medium")
        summary = f"[Security] {group.title} — {target}"
        labels = ["security", f"severity:{group.max_severity}"]

        existing = state.get(group.key)

        if existing and existing.get("status") == "closed":
            # Regression: reopen
            ticket_id = existing["ticket_id"]
            try:
                await client.transition_issue(ticket_id, "reopen")
                await client.add_comment(
                    ticket_id,
                    f"Regression detected in scan `{scan_id}` of `{target}`. Reopening."
                )
                await client.update_issue(ticket_id, body, priority)
                state[group.key] = {"ticket_id": ticket_id, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Reopened Jira ticket %s (regression: %s)", ticket_id, group.key)
            except Exception as e:
                log.warning("Failed to reopen Jira ticket %s: %s", ticket_id, e)

        elif existing and existing.get("fingerprint") != group.fingerprint:
            # Update changed ticket
            ticket_id = existing["ticket_id"]
            try:
                await client.update_issue(ticket_id, body, priority)
                await client.add_comment(
                    ticket_id,
                    f"Updated from re-scan `{scan_id}` of `{target}`. Findings have changed."
                )
                state[group.key]["fingerprint"] = group.fingerprint
                log.info("Updated Jira ticket %s (group: %s)", ticket_id, group.key)
            except Exception as e:
                log.warning("Failed to update Jira ticket %s: %s", ticket_id, e)

        elif not existing:
            # Create new ticket
            try:
                ticket_id = await client.create_issue(summary, body, priority, labels)
                state[group.key] = {"ticket_id": ticket_id, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Created Jira ticket %s (group: %s)", ticket_id, group.key)
            except Exception as e:
                log.warning("Failed to create Jira ticket for group %s: %s", group.key, e)

    _save_state(storage, channel_id, target, state)


async def dispatch_findings_to_linear(
    config: dict,
    channel_id: str,
    groups: list[FindingGroup],
    target: str,
    scan_id: str,
    report_url: str | None,
    storage,
    auto_close: bool = True,
):
    """Create/update/close Linear issues from grouped findings."""
    client = LinearClient(config)
    state = _load_state(storage, channel_id, target)

    current_group_keys = {g.key for g in groups}

    if auto_close:
        for group_key, ticket_info in list(state.items()):
            if group_key not in current_group_keys and ticket_info.get("status") == "open":
                issue_id = ticket_info["ticket_id"]
                try:
                    await client.close_issue(
                        issue_id,
                        f"Resolved: findings not detected in latest scan of `{target}` (Scan: `{scan_id}`)."
                    )
                    state[group_key]["status"] = "closed"
                    log.info("Closed Linear issue %s (group: %s resolved)", issue_id, group_key)
                except Exception as e:
                    log.warning("Failed to close Linear issue %s: %s", issue_id, e)

    for group in groups:
        body = _format_ticket_body(group, target, scan_id, report_url, fmt="markdown")
        priority = _LINEAR_PRIORITY.get(group.max_severity, 3)
        title = f"[Security] {group.title} — {target}"

        existing = state.get(group.key)

        if existing and existing.get("status") == "closed":
            issue_id = existing["ticket_id"]
            try:
                await client.reopen_issue(
                    issue_id,
                    f"Regression detected in scan `{scan_id}` of `{target}`. Reopening."
                )
                await client.update_issue(issue_id, body, priority)
                state[group.key] = {"ticket_id": issue_id, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Reopened Linear issue %s (regression: %s)", issue_id, group.key)
            except Exception as e:
                log.warning("Failed to reopen Linear issue %s: %s", issue_id, e)

        elif existing and existing.get("fingerprint") != group.fingerprint:
            issue_id = existing["ticket_id"]
            try:
                await client.update_issue(issue_id, body, priority)
                await client.add_comment(
                    issue_id,
                    f"Updated from re-scan `{scan_id}` of `{target}`. Findings have changed."
                )
                state[group.key]["fingerprint"] = group.fingerprint
                log.info("Updated Linear issue %s (group: %s)", issue_id, group.key)
            except Exception as e:
                log.warning("Failed to update Linear issue %s: %s", issue_id, e)

        elif not existing:
            try:
                issue_id = await client.create_issue(title, body, priority, [])
                state[group.key] = {"ticket_id": issue_id, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Created Linear issue %s (group: %s)", issue_id, group.key)
            except Exception as e:
                log.warning("Failed to create Linear issue for group %s: %s", group.key, e)

    _save_state(storage, channel_id, target, state)


async def dispatch_findings_to_github(
    config: dict,
    channel_id: str,
    groups: list[FindingGroup],
    target: str,
    scan_id: str,
    report_url: str | None,
    storage,
    auto_close: bool = True,
):
    """Create/update/close GitHub Issues from grouped findings."""
    client = GitHubIssuesClient(config)
    state = _load_state(storage, channel_id, target)

    current_group_keys = {g.key for g in groups}

    if auto_close:
        for group_key, ticket_info in list(state.items()):
            if group_key not in current_group_keys and ticket_info.get("status") == "open":
                issue_number = ticket_info["ticket_id"]
                try:
                    await client.close_issue(
                        issue_number,
                        f"Resolved: findings not detected in latest scan of `{target}` (Scan: `{scan_id}`)."
                    )
                    state[group_key]["status"] = "closed"
                    log.info("Closed GitHub issue #%s (group: %s resolved)", issue_number, group_key)
                except Exception as e:
                    log.warning("Failed to close GitHub issue #%s: %s", issue_number, e)

    for group in groups:
        body = _format_ticket_body(group, target, scan_id, report_url, fmt="markdown")
        labels = _GITHUB_LABELS.get(group.max_severity, ["security"])
        title = f"[Security] {group.title} — {target}"

        existing = state.get(group.key)

        if existing and existing.get("status") == "closed":
            issue_number = existing["ticket_id"]
            try:
                await client.reopen_issue(
                    issue_number,
                    f"Regression detected in scan `{scan_id}` of `{target}`. Reopening."
                )
                await client.update_issue(issue_number, body, labels)
                state[group.key] = {"ticket_id": issue_number, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Reopened GitHub issue #%s (regression: %s)", issue_number, group.key)
            except Exception as e:
                log.warning("Failed to reopen GitHub issue #%s: %s", issue_number, e)

        elif existing and existing.get("fingerprint") != group.fingerprint:
            issue_number = existing["ticket_id"]
            try:
                await client.update_issue(issue_number, body, labels)
                await client.add_comment(
                    issue_number,
                    f"Updated from re-scan `{scan_id}` of `{target}`. Findings have changed."
                )
                state[group.key]["fingerprint"] = group.fingerprint
                log.info("Updated GitHub issue #%s (group: %s)", issue_number, group.key)
            except Exception as e:
                log.warning("Failed to update GitHub issue #%s: %s", issue_number, e)

        elif not existing:
            try:
                issue_number = await client.create_issue(title, body, labels)
                state[group.key] = {"ticket_id": issue_number, "fingerprint": group.fingerprint, "status": "open"}
                log.info("Created GitHub issue #%s (group: %s)", issue_number, group.key)
            except Exception as e:
                log.warning("Failed to create GitHub issue for group %s: %s", group.key, e)

    _save_state(storage, channel_id, target, state)


async def dispatch_issue_trackers(
    channels: list[dict],
    findings: list[dict],
    target: str,
    scan_id: str,
    report_url: str | None,
    storage,
):
    """
    Dispatch findings to all configured issue tracker channels.

    Each channel dict should have:
      - type: "jira" | "linear" | "github_issues"
      - id: channel identifier (for state tracking)
      - config: tracker-specific config
      - min_severity: minimum finding severity to include (default: "medium")
      - auto_group_findings: whether to group findings (default: True)
      - auto_close_resolved: whether to auto-close tickets for resolved findings (default: True)
    """
    tracker_types = {"jira", "linear", "github_issues"}
    tracker_channels = [c for c in channels if c.get("type") in tracker_types]

    if not tracker_channels:
        return

    for channel in tracker_channels:
        channel_type = channel["type"]
        channel_id = channel.get("id", channel_type)
        config = channel.get("config", {})
        min_severity = config.get("min_severity", channel.get("min_severity", "medium"))
        auto_close = config.get("auto_close_resolved", True)
        auto_group = config.get("auto_group_findings", True)

        if auto_group:
            groups = group_findings(findings, min_severity=min_severity)
        else:
            # Each finding becomes its own group
            min_level = _SEVERITY_ORDER.get(min_severity, 2)
            groups = []
            for f in findings:
                if _SEVERITY_ORDER.get(f.get("severity", "info"), 0) >= min_level:
                    g = FindingGroup(
                        key=hashlib.md5(f.get("title", "").encode()).hexdigest()[:8],
                        title=f.get("title", "Security Finding"),
                        findings=[f],
                    )
                    groups.append(g)

        if not groups:
            log.info("No findings meet min_severity '%s' for %s channel", min_severity, channel_type)
            continue

        try:
            if channel_type == "jira":
                await dispatch_findings_to_jira(
                    config, channel_id, groups, target, scan_id, report_url, storage, auto_close
                )
            elif channel_type == "linear":
                await dispatch_findings_to_linear(
                    config, channel_id, groups, target, scan_id, report_url, storage, auto_close
                )
            elif channel_type == "github_issues":
                await dispatch_findings_to_github(
                    config, channel_id, groups, target, scan_id, report_url, storage, auto_close
                )
        except Exception as e:
            log.error("Issue tracker dispatch failed for channel %s (%s): %s", channel_id, channel_type, e)
