# API Reference

All API endpoints are served at `http://localhost:8000/api/`. Except for registration and login, all endpoints require a JWT bearer token.

## Authentication

### Register

```
POST /api/auth/register
```

Create a new user account. The first registered user becomes the admin.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "YourPassword1"
}
```

**Password requirements:** 8+ characters, at least one lowercase, one uppercase, one digit.

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "plan": "free"
}
```

### Login

```
POST /api/auth/login
```

**Request:**
```json
{
  "email": "user@example.com",
  "password": "YourPassword1"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

- Access token expires in **24 hours**
- Refresh token expires in **7 days**
- After 5 failed attempts, account is locked for **15 minutes**

### Using Tokens

Include the access token in all subsequent requests:

```
Authorization: Bearer eyJ...
```

---

## Scans

### Create Scan

```
POST /api/scans/
```

**Request:**
```json
{
  "target": "example.com",
  "scan_type": "security",
  "config": {}
}
```

**Scan types:** `security`, `pentest`, `seo`, `performance`, `api_security`, `compliance`, `privacy`, `cloud`, `recon`, `uptime`, `full`

**Response (201):**
```json
{
  "id": "scan-uuid",
  "target": "example.com",
  "scan_type": "security",
  "status": "queued",
  "created_at": "2025-01-15T10:30:00Z"
}
```

### List Scans

```
GET /api/scans/
```

Returns all scans for the authenticated user.

### Get Scan Details

```
GET /api/scans/{id}
```

### Get Scan Activity

```
GET /api/scans/{id}/activity
```

Returns the live activity log for a running or completed scan.

### Scan Statuses

`queued` → `running` → `completed` | `failed`

---

## Reports

### JSON Report

```
GET /api/reports/{id}/json
```

Returns the full structured report as JSON. See [Report Structure](#report-structure) below.

### HTML Report

```
GET /api/reports/{id}/html
```

Returns a rendered HTML report. Supports `?token=<jwt>` query parameter for direct browser access without headers.

### PDF Report

```
GET /api/reports/{id}/pdf
```

Returns a downloadable PDF report generated from the HTML template.

### Report Structure

```json
{
  "summary": "Executive summary of findings",
  "risk_score": 72,
  "findings": [
    {
      "title": "Missing Content-Security-Policy Header",
      "severity": "medium",
      "category": "headers",
      "description": "The CSP header is not set...",
      "evidence": "curl -I https://example.com shows no CSP header",
      "cve_ids": [],
      "cwes": ["CWE-693"],
      "owasp_category": "A05:2021 Security Misconfiguration",
      "compliance_frameworks": ["OWASP", "PCI-DSS"],
      "remediation": "Add Content-Security-Policy header...",
      "remediation_commands": ["Header set Content-Security-Policy \"default-src 'self'\""],
      "remediation_priority": "short-term",
      "affected_urls": ["https://example.com/"],
      "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
    }
  ],
  "technologies_detected": ["nginx/1.24", "PHP/8.1", "WordPress 6.4"],
  "compliance_summary": {
    "owasp_top10": "partial",
    "pci_dss": "fail",
    "gdpr": "pass",
    "tls_best_practices": "pass"
  },
  "attack_surface": {
    "open_ports": [80, 443, 22],
    "subdomains_found": 3,
    "exposed_services": ["nginx", "OpenSSH"],
    "entry_points": ["/wp-admin", "/xmlrpc.php"]
  },
  "improvement_roadmap": [
    {
      "priority": 1,
      "title": "Add Content-Security-Policy",
      "description": "Prevents XSS and data injection",
      "effort": "low",
      "impact": "high"
    }
  ],
  "scan_metadata": {
    "tools_used": ["nmap", "nuclei", "testssl"],
    "duration_seconds": 245,
    "commands_executed": 28,
    "total_tool_calls": 35,
    "scan_id": "uuid",
    "target": "example.com",
    "scan_type": "security",
    "plan": "1. Reconnaissance..."
  }
}
```

---

## Scheduled Scans

### Create Schedule

```
POST /api/schedules/
```

**Request:**
```json
{
  "target": "example.com",
  "scan_type": "security",
  "cron_expression": "daily",
  "max_runs": 30
}
```

**Cron expressions:** `hourly`, `daily`, `weekly`, `monthly`, `12h`, `30m`, `2d`

### List Schedules

```
GET /api/schedules/
```

### Get Schedule

```
GET /api/schedules/{id}
```

### Update Schedule

```
PATCH /api/schedules/{id}
```

**Request:**
```json
{
  "cron_expression": "weekly",
  "is_active": false
}
```

### Delete Schedule

```
DELETE /api/schedules/{id}
```

---

## Uptime Monitors

### Create Monitor

```
POST /api/monitors/
```

**Request:**
```json
{
  "target": "example.com",
  "check_type": "http",
  "interval_seconds": 300
}
```

**Check types:** `http`, `tcp`, `dns`, `tls`

### List Monitors

```
GET /api/monitors/
```

### Delete Monitor

```
DELETE /api/monitors/{id}
```

### Monitor Status Values

- `up` — Target is responding normally
- `down` — Target is not responding or returning errors
- `degraded` — Target is responding but with issues (slow response, partial errors)

---

## Notification Channels

### Create Channel

```
POST /api/notifications/
```

**Slack:**
```json
{
  "name": "Slack alerts",
  "channel_type": "slack",
  "config": {"webhook_url": "https://hooks.slack.com/services/..."},
  "min_severity": "warning"
}
```

**Discord:**
```json
{
  "name": "Discord alerts",
  "channel_type": "discord",
  "config": {"webhook_url": "https://discord.com/api/webhooks/..."},
  "min_severity": "critical"
}
```

**Email:**
```json
{
  "name": "Email alerts",
  "channel_type": "email",
  "config": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "...",
    "password": "...",
    "to_email": "alerts@example.com"
  },
  "min_severity": "info"
}
```

**Webhook:**
```json
{
  "name": "Custom webhook",
  "channel_type": "webhook",
  "config": {"url": "https://your-service.com/hooks/scan"},
  "min_severity": "info"
}
```

**Channel types:** `email`, `slack`, `discord`, `webhook`, `openclaw`

### Severity Routing

Notifications fire based on risk score:
- `critical` — risk_score >= 80
- `warning` — risk_score >= 50
- `info` — all scans

### List Channels

```
GET /api/notifications/
```

### Update Channel

```
PATCH /api/notifications/{id}
```

### Delete Channel

```
DELETE /api/notifications/{id}
```

---

## Tools

### List All Tools

```
GET /api/tools/
```

Returns all 69+ scanning tools organized by category.

### List Categories

```
GET /api/tools/categories
```

### Tools for Scan Type

```
GET /api/tools/scan-type/{type}
```

Returns tools used by a specific scan type (e.g., `security`, `pentest`).

### Tool Details

```
GET /api/tools/{name}
```

Returns metadata for a specific tool including description, category, examples, and output format.

---

## System

### Health Check

```
GET /health
```

No authentication required. Returns `{"status": "ok"}` if the API is running.

### Heartbeat Status

```
GET /api/heartbeat
```

Returns recent heartbeat messages with per-module health status.

### Worker Logs

```
GET /api/logs/worker
```

Returns recent worker log lines.

### Dashboard

```
GET /
```

Serves the web dashboard UI.
