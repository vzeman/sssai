# Getting Started

This guide walks you through your first experience with SSSAI — from creating your account to running your first security scan and understanding the results.

## 1. Register Your Account

### Via the Dashboard

Open `http://localhost:8000` in your browser. You'll see a login/register interface. Click **Register** and enter your email and password.

**Password requirements:**
- Minimum 8 characters
- At least one lowercase letter
- At least one uppercase letter
- At least one digit

### Via the API

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "YourPassword1"}'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "you@example.com",
  "plan": "free"
}
```

**Important:** The first registered user automatically becomes the **admin** with full access to the admin panel at `/admin`. Subsequent users are regular users.

## 2. Log In

### Via the Dashboard

Enter your credentials on the login screen. You'll be taken to the main dashboard.

### Via the API

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "YourPassword1"}' | jq -r .access_token)

echo $TOKEN
```

The token is valid for **24 hours**. Use it in all subsequent API requests:

```
Authorization: Bearer <your-token>
```

### Security Features

- **Rate limiting:** 5 failed login attempts trigger a 15-minute account lockout
- **2FA support:** Enable TOTP-based two-factor authentication via the dashboard or API for additional security
- **Refresh tokens:** Valid for 7 days, use them to get new access tokens without re-entering credentials

## 3. Run Your First Scan

### Via the Dashboard

1. In the dashboard, you'll see a scan input area
2. Enter a **target** (domain name or IP address), e.g., `example.com`
3. Select a **scan type** (start with `security` for a general vulnerability scan)
4. Click **Start Scan**

The scan will be queued and picked up by the worker within seconds.

### Via the API

```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "example.com", "scan_type": "security"}'
```

Response:
```json
{
  "id": "scan-uuid-here",
  "target": "example.com",
  "scan_type": "security",
  "status": "queued",
  "created_at": "2025-01-15T10:30:00Z"
}
```

### Choosing a Scan Type

For your first scan, we recommend starting with one of these:

| Scan Type | Best For | Duration |
|-----------|----------|----------|
| `security` | General vulnerability assessment | 3-10 min |
| `recon` | Quick reconnaissance (no active testing) | 2-5 min |
| `seo` | Website technical SEO audit | 2-5 min |

See [Security Checks](security-checks.md) for all 11 scan types.

## 4. Monitor Scan Progress

### Via the Dashboard

The dashboard shows real-time scan progress:
- **Status indicator:** queued → running → completed (or failed)
- **Live activity log:** Watch the AI agent's tool calls and decisions in real-time
- **Heartbeat panel:** Green/red indicator at the top shows platform health

### Via the API

```bash
# Check scan status
curl -s http://localhost:8000/api/scans/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN" | jq .status

# Watch live activity
curl -s http://localhost:8000/api/scans/$SCAN_ID/activity \
  -H "Authorization: Bearer $TOKEN"
```

Scan statuses flow as: `queued` → `running` → `completed` | `failed`

## 5. View Your Report

Once the scan completes, you'll get a structured report with findings.

### Via the Dashboard

Click on a completed scan to see the full report with:
- **Executive summary** — High-level overview of what was found
- **Risk score** — 0-100 score (higher = more risk)
- **Findings list** — Each vulnerability with severity, description, and remediation
- **Technologies detected** — What tech stack was identified
- **Improvement roadmap** — Prioritized action items

### Via the API

```bash
# JSON report
curl -s http://localhost:8000/api/reports/$SCAN_ID/json \
  -H "Authorization: Bearer $TOKEN" | jq .

# HTML report (viewable in browser)
curl -s http://localhost:8000/api/reports/$SCAN_ID/html \
  -H "Authorization: Bearer $TOKEN" > report.html

# PDF report
curl -s http://localhost:8000/api/reports/$SCAN_ID/pdf \
  -H "Authorization: Bearer $TOKEN" > report.pdf
```

### Understanding the Report

Each finding includes:

| Field | Description |
|-------|-------------|
| **severity** | `critical`, `high`, `medium`, `low`, `info` |
| **category** | e.g., `headers`, `ssl`, `network`, `injection` |
| **description** | What the issue is and why it matters |
| **evidence** | Proof — the actual command output or response |
| **remediation** | How to fix it, including specific commands |
| **cve_ids** | Related CVE identifiers (if applicable) |
| **cwes** | CWE weakness categories |
| **owasp_category** | OWASP Top 10 mapping |
| **compliance_frameworks** | Which frameworks this affects (OWASP, PCI-DSS, GDPR) |
| **remediation_priority** | `immediate`, `short-term`, `long-term` |

## 6. Next Steps

Now that you've completed your first scan, here's what to explore next:

### Set Up Scheduled Scans

Automate recurring scans to continuously monitor your targets:

```bash
curl -X POST http://localhost:8000/api/schedules/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "example.com",
    "scan_type": "security",
    "cron_expression": "daily",
    "max_runs": 30
  }'
```

Available schedules: `hourly`, `daily`, `weekly`, `monthly`, `12h`, `30m`, `2d`

### Set Up Uptime Monitoring

Monitor your targets for availability 24/7:

```bash
curl -X POST http://localhost:8000/api/monitors/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "example.com",
    "check_type": "http",
    "interval_seconds": 300
  }'
```

Check types: `http`, `tcp`, `dns`, `tls`

### Configure Notifications

Get alerts when scans complete or monitors detect issues:

```bash
curl -X POST http://localhost:8000/api/notifications/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Slack alerts",
    "channel_type": "slack",
    "config": {"webhook_url": "https://hooks.slack.com/services/..."},
    "min_severity": "warning"
  }'
```

Supported channels: `slack`, `discord`, `email`, `webhook`, `openclaw`

### Enable Two-Factor Authentication

For additional account security, enable 2FA through the dashboard settings or API.

### Explore the Admin Panel

If you're the admin user, visit `http://localhost:8000/admin` to:
- Manage user accounts
- View system-wide scan statistics
- Monitor platform health

## Further Reading

- [Security Checks](security-checks.md) — Deep dive into all 11 scan types and how they work
- [Configuration](configuration.md) — AI models, notifications, environment variables
- [Architecture](architecture.md) — How the AI agent plans, executes, and reports
- [API Reference](api-reference.md) — Complete API documentation
- [Scanning Tools](scanning-tools.md) — All 69+ tools available in the platform
