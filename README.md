# SSSAI — Simple Security Scan AI Assistant

AI-powered autonomous security scanning platform. A Claude AI agent drives the scans — it plans the strategy, decides which tools to run, interprets results in real-time, delegates to specialized sub-agents, and produces actionable reports.

Inspired by [PentAGI](https://github.com/vxcontrol/pentagi) architecture patterns: multi-agent delegation, execution monitoring, chain summarization, and cross-scan memory.

## Architecture

```
                                    ┌─────────────────────────────────────────┐
                                    │            Worker Container             │
                                    │                                         │
User → Dashboard (HTML) ──┐         │  ┌─────────┐    ┌──────────────────┐   │
                          │         │  │ Primary  │───→│ 69+ Scan Tools   │   │
Browser → API (FastAPI) ──┼── Redis │  │ Agent    │    │ nmap, nuclei,    │   │
                          │  Queue  │  │ (Claude) │    │ nikto, testssl...│   │
CLI → API ────────────────┘         │  └────┬─────┘    └──────────────────┘   │
                                    │       │                                  │
                                    │  ┌────┴──────────────────────────┐      │
                                    │  │ Sub-Agents                    │      │
                                    │  │ ┌───────────┐ ┌──────────┐   │      │
                                    │  │ │ Pentester │ │ Searcher │   │      │
                                    │  │ └───────────┘ └──────────┘   │      │
                                    │  │ ┌───────────┐                │      │
                                    │  │ │ Coder     │                │      │
                                    │  │ └───────────┘                │      │
                                    │  └───────────────────────────────┘      │
                                    └─────────────────────────────────────────┘
                                              │
                              ┌────────────────┼────────────────┐
                              ▼                ▼                ▼
                         PostgreSQL         Redis          Storage
                         (scans, users,    (queue, logs,   (reports,
                          schedules,        activity,       agent logs)
                          memory)           pub/sub)
```

### Services

| Service | Purpose | Port |
|---------|---------|------|
| **api** | FastAPI REST API + dashboard | 8000 |
| **worker** | Queue consumer → AI agent + scanning tools | — |
| **scheduler** | Triggers scans on cron schedules | — |
| **monitor** | Uptime/availability checks | — |
| **redis** | Queue, pub/sub, live logs | 6379 |
| **postgres** | Users, scans, schedules, memory | 5432 |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/vzeman/sssai.git
cd sssai

# 2. Configure
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY

# 3. Start
docker compose up --build -d

# 4. Open dashboard
open http://localhost:8000
```

Register a user, log in, and start scanning from the dashboard.

### CLI Usage

```bash
# Register
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "password123"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "password123"}' | jq -r .access_token)

# Start a scan
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "example.com", "scan_type": "security"}'
```

---

## Scan Types

| Type | Description | Key Tools |
|------|-------------|-----------|
| `security` | Vulnerability scanning, CVE detection, misconfigurations | nmap, nuclei, nikto, testssl, sslyze |
| `pentest` | Penetration testing (PTES methodology), attack chains | nmap, sqlmap, hydra, wapiti, gobuster |
| `seo` | Technical SEO audit, Core Web Vitals, accessibility | lighthouse, pa11y, blc, yellowlabtools |
| `performance` | Load testing, response times, throughput | hey, wrk, artillery, k6 |
| `api_security` | API-specific testing, auth, injection, rate limits | nuclei, wapiti, curl, stepci |
| `compliance` | OWASP Top 10, PCI-DSS, GDPR, CIS benchmarks | nuclei, testssl, drheader, checkov |
| `privacy` | Privacy compliance, cookie consent, data exposure | curl, drheader, checkdmarc |
| `cloud` | Cloud infrastructure security, IaC scanning | trivy, checkov, grype |
| `recon` | Reconnaissance only — subdomains, ports, technologies | subfinder, whatweb, amass, dnsrecon |
| `uptime` | Availability, TLS cert expiry, DNS, port monitoring | curl, openssl, dig |
| `full` | All of the above in one comprehensive scan | Everything |

---

## AI Agent Architecture

The scanning engine uses Claude as an autonomous agent that plans, executes, and reports. Inspired by PentAGI's multi-agent patterns:

### Agent Loop

```
1. PLAN      → Agent generates 3-7 step scan plan
2. EXECUTE   → Agent calls tools, interprets results
3. MONITOR   → Execution monitor reviews progress every 10 tool calls
4. SUMMARIZE → Chain summarization compresses old messages when > 80K chars
5. REFLECT   → Reflector redirects agent back to tools if it produces only text
6. REPORT    → Agent submits structured report with findings
```

### Sub-Agent Delegation

The primary agent can delegate specialized tasks to focused sub-agents:

| Sub-Agent | Role | Available Tools |
|-----------|------|-----------------|
| **Pentester** | Deep vulnerability analysis, exploit verification, attack chains | run_command, http_request, dns_lookup, screenshot, read/write_file |
| **Searcher** | CVE research, exploit lookup, vulnerability details | web_search, exploit_search, http_request, read_file |
| **Coder** | Custom scripts, data processing, tool configurations | run_command, read/write_file |

Each sub-agent gets its own Claude call with a focused system prompt and limited tool set (max 20 iterations).

### Loop Detection

Tracks every tool call and detects:
- **Repeated calls**: Same tool + same arguments called 3+ times
- **Oscillation**: A→B→A→B pattern detection
- **Warnings**: Injected into tool results to redirect the agent

### Execution Monitor

Every 10 tool calls, a separate LLM call reviews the agent's progress:
- Detects stuck/looping behavior
- Identifies missed scan areas
- Recommends strategy pivots
- Feedback injected into conversation

### Chain Summarization

When conversation exceeds 80K characters:
- Older messages are summarized via a separate LLM call
- Recent 6 messages kept intact
- Summary preserves: key findings, tools run, vulnerabilities discovered
- "Summarization Awareness Protocol" in every prompt teaches agents to interpret summaries

### Reflector Pattern

When the agent produces text instead of tool calls (up to 3 attempts):
1. A "reflector" agent analyzes the text output
2. Determines what tool call should come next
3. Redirects the agent back to structured tool use
4. If the agent is done, directs it to call the `report` tool

### Cross-Scan Memory

PostgreSQL-backed memory store that persists across scans:

| Memory Type | Purpose |
|-------------|---------|
| `guide` | Scanning methodologies that worked well |
| `finding` | Important findings about a target |
| `answer` | Research answers reusable in future scans |

Agent tools: `search_memory` (query before running redundant tools) and `store_memory` (save reusable knowledge).

### Search Integration

| Tool | Source | Data |
|------|--------|------|
| `web_search` | DuckDuckGo | General vulnerability research, documentation |
| `exploit_search` | NVD + Exploit-DB | CVE IDs, CVSS scores, exploit references |

---

## Agent Tools

### Direct Tools (no shell needed)

| Tool | Description |
|------|-------------|
| `run_command` | Execute shell commands (300s timeout) |
| `read_file` | Read files from /output/ |
| `write_file` | Write files to /output/ |
| `http_request` | HTTP requests with full header/body inspection |
| `dns_lookup` | DNS record queries (A, MX, TXT, NS, etc.) |
| `parse_json` | Extract data from JSON files using jq expressions |
| `compare_results` | Compare current vs. previous scan results |
| `screenshot` | Capture web page screenshots (desktop + mobile) |
| `web_search` | Search the web via DuckDuckGo |
| `exploit_search` | Search NVD + Exploit-DB for CVEs and exploits |
| `delegate_to_pentester` | Delegate task to pentester sub-agent |
| `delegate_to_searcher` | Delegate research to searcher sub-agent |
| `delegate_to_coder` | Delegate coding task to coder sub-agent |
| `search_memory` | Search cross-scan memory |
| `store_memory` | Store knowledge for future scans |
| `report` | Submit final structured report |

### Scanning Tools (69+ in worker container)

**Network**: nmap, masscan, ping, traceroute
**Vulnerability**: nuclei (8000+ templates), nikto, wapiti, sqlmap
**SSL/TLS**: testssl, sslyze, sslscan, openssl
**Headers**: drheader, shcheck, curl
**Recon**: whatweb, subfinder, httpx, gobuster, dirb, ffuf, wafw00f
**OSINT**: amass, theHarvester, spiderfoot
**DNS**: dig, whois, dnsrecon
**CORS**: corsy, corscanner
**Subdomain Takeover**: subjack, dnsreaper
**Secrets**: trufflehog, gitleaks
**Container**: trivy, grype, syft
**IaC**: checkov
**SAST**: semgrep
**CMS**: wpscan, droopescan
**Email**: checkdmarc, dnstwist
**SEO/Performance**: lighthouse, pa11y, axe, blc, yellowlabtools, sitespeed.io
**Load Testing**: hey, wrk, artillery, vegeta, locust
**Protocol**: h2spec, wscat
**Auth**: hydra
**Visual**: backstopjs

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, get JWT token (24h expiry) |

**Register:**
```json
POST /api/auth/register
{"email": "user@example.com", "password": "password123"}
→ {"id": "uuid", "email": "user@example.com", "plan": "free"}
```

**Login:**
```json
POST /api/auth/login
{"email": "user@example.com", "password": "password123"}
→ {"access_token": "eyJ...", "token_type": "bearer"}
```

All subsequent requests require: `Authorization: Bearer <token>`

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans/` | Create and queue a new scan |
| GET | `/api/scans/` | List user's scans |
| GET | `/api/scans/{id}` | Get scan details |
| GET | `/api/scans/{id}/report` | Get scan report (JSON) |
| GET | `/api/scans/{id}/activity` | Get live scan activity log |

**Create scan:**
```json
POST /api/scans/
{
  "target": "example.com",
  "scan_type": "security",
  "config": {}
}
→ {"id": "uuid", "target": "example.com", "scan_type": "security", "status": "queued", ...}
```

**Scan statuses:** `queued` → `running` → `completed` | `failed`

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/{id}/json` | Report as JSON |
| GET | `/api/reports/{id}/html` | Report as HTML (supports `?token=` for direct browser access) |
| GET | `/api/reports/{id}/pdf` | Report as downloadable PDF |

### Scheduled Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/schedules/` | Create scheduled scan |
| GET | `/api/schedules/` | List schedules |
| GET | `/api/schedules/{id}` | Get schedule details |
| PATCH | `/api/schedules/{id}` | Update schedule |
| DELETE | `/api/schedules/{id}` | Delete schedule |

**Cron expressions:** `hourly`, `daily`, `weekly`, `monthly`, `12h`, `30m`, `2d`

```json
POST /api/schedules/
{
  "target": "example.com",
  "scan_type": "security",
  "cron_expression": "daily",
  "max_runs": 30
}
```

### Uptime Monitors

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/monitors/` | Create monitor |
| GET | `/api/monitors/` | List monitors |
| DELETE | `/api/monitors/{id}` | Delete monitor |

**Check types:** `http`, `tcp`, `dns`, `tls`

```json
POST /api/monitors/
{
  "target": "example.com",
  "check_type": "http",
  "interval_seconds": 300
}
```

### Notification Channels

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/notifications/` | Create channel |
| GET | `/api/notifications/` | List channels |
| PATCH | `/api/notifications/{id}` | Update channel |
| DELETE | `/api/notifications/{id}` | Delete channel |

**Channel types:** `email`, `slack`, `discord`, `webhook`, `openclaw`

```json
POST /api/notifications/
{
  "name": "Slack alerts",
  "channel_type": "slack",
  "config": {"webhook_url": "https://hooks.slack.com/services/..."},
  "min_severity": "warning"
}
```

### Tools

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tools/` | List all tools by category |
| GET | `/api/tools/categories` | List tool categories |
| GET | `/api/tools/scan-type/{type}` | Tools for a scan type |
| GET | `/api/tools/{name}` | Tool details |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/logs/worker` | Worker log lines |
| GET | `/` | Dashboard UI |

---

## Report Structure

Each scan produces a structured JSON report:

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

## Database Schema

### Users
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | User ID |
| email | VARCHAR (unique) | Email address |
| hashed_password | VARCHAR | bcrypt hash |
| plan | VARCHAR | free, pro, enterprise |
| created_at | TIMESTAMP | Registration time |

### Scans
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Scan ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR (indexed) | Scan target |
| scan_type | VARCHAR | security, pentest, seo, etc. |
| status | VARCHAR | queued, running, completed, failed |
| risk_score | FLOAT | 0-100 risk score |
| findings_count | INTEGER | Number of findings |
| config | JSON | Scan configuration |
| created_at | TIMESTAMP | Creation time |
| completed_at | TIMESTAMP | Completion time |
| schedule_id | UUID (FK, nullable) | If triggered by schedule |

### Scheduled Scans
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Schedule ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR | Scan target |
| scan_type | VARCHAR | Scan type |
| cron_expression | VARCHAR | hourly, daily, 12h, etc. |
| config | JSON | Scan config |
| is_active | BOOLEAN | Active flag |
| next_run_at | TIMESTAMP | Next execution |
| last_run_at | TIMESTAMP | Last execution |
| run_count | INTEGER | Times executed |
| max_runs | INTEGER (nullable) | Max executions |

### Monitors
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Monitor ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR | Target to monitor |
| check_type | VARCHAR | http, tcp, dns, tls |
| interval_seconds | INTEGER | Check interval (default 300) |
| is_active | BOOLEAN | Active flag |
| last_status | VARCHAR | up, down, degraded |
| last_response_ms | INTEGER | Response time |
| last_checked_at | TIMESTAMP | Last check time |

### Notification Channels
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Channel ID |
| user_id | UUID (FK) | Owner |
| name | VARCHAR | Channel name |
| channel_type | VARCHAR | email, slack, discord, webhook |
| config | JSON | Channel-specific config |
| min_severity | VARCHAR | info, warning, critical |
| is_active | BOOLEAN | Active flag |

### Scan Memory (cross-scan)
| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL (PK) | Memory ID |
| content | TEXT | Stored knowledge |
| memory_type | VARCHAR | guide, finding, answer |
| tags | TEXT[] | Searchability tags |
| metadata | JSONB | Additional data |
| scan_id | VARCHAR | Source scan |
| target | VARCHAR | Related target |
| created_at | TIMESTAMP | Storage time |

---

## Project Structure

```
sssai/
├── docker/
│   ├── Dockerfile.worker         # Worker: Ubuntu 22.04 + 69 scanning tools + Python
│   ├── Dockerfile.api            # API: Python FastAPI
│   ├── Dockerfile.scheduler      # Scheduler: Python cron service
│   └── Dockerfile.monitor        # Monitor: Python uptime checker
├── docker-compose.yml            # Local dev: 6 services
├── modules/
│   ├── agent/
│   │   ├── scan_agent.py         # AI agent loop — planning, execution, monitoring
│   │   ├── tools.py              # Tool definitions for Claude (16 tools + sub-agents)
│   │   └── prompts/              # System prompts per scan type (11 templates)
│   │       ├── security.txt
│   │       ├── pentest.txt
│   │       ├── seo.txt
│   │       ├── performance.txt
│   │       ├── api_security.txt
│   │       ├── compliance.txt
│   │       ├── privacy.txt
│   │       ├── cloud.txt
│   │       ├── recon.txt
│   │       ├── uptime.txt
│   │       └── full.txt
│   ├── api/
│   │   ├── main.py               # FastAPI app + dashboard serving
│   │   ├── models.py             # SQLAlchemy ORM models (5 tables)
│   │   ├── schemas.py            # Pydantic request/response schemas
│   │   ├── auth.py               # JWT authentication (bcrypt + HMAC)
│   │   ├── database.py           # PostgreSQL connection
│   │   ├── static/
│   │   │   └── dashboard.html    # Single-page dashboard UI
│   │   └── routes/
│   │       ├── auth.py           # Register, login
│   │       ├── scans.py          # CRUD + queue submission
│   │       ├── reports.py        # JSON, HTML, PDF report endpoints
│   │       ├── schedules.py      # Scheduled scan management
│   │       ├── monitors.py       # Uptime monitor management
│   │       ├── notifications.py  # Notification channel management
│   │       └── tools.py          # Tool registry queries
│   ├── worker/
│   │   ├── __init__.py           # Queue consumer + Redis log handler
│   │   └── consumer.py           # Entry point
│   ├── scheduler/
│   │   ├── cron.py               # Scheduler service (polls every 30s)
│   │   └── consumer.py           # Entry point
│   ├── monitor/
│   │   └── uptime.py             # HTTP, TCP, DNS, TLS checks
│   ├── notifications/
│   │   └── dispatcher.py         # Email, Slack, Discord, Webhook, OpenClaw
│   ├── reports/
│   │   ├── generator.py          # Jinja2 HTML + WeasyPrint PDF generation
│   │   └── templates/
│   │       └── report.html       # Report Jinja2 template
│   ├── infra/
│   │   ├── __init__.py           # Factory: get_queue(), get_storage(), get_secrets()
│   │   ├── local_queue.py        # Redis queue implementation
│   │   ├── local_storage.py      # Filesystem storage
│   │   ├── local_secrets.py      # Environment variable secrets
│   │   ├── aws_queue.py          # SQS queue
│   │   ├── aws_storage.py        # S3 storage
│   │   └── aws_secrets.py        # AWS Secrets Manager
│   ├── tools/
│   │   └── registry.py           # 80+ tool registry with categories
│   └── sandbox/                  # Execution environment abstractions
│       ├── openshell.py
│       ├── openclaw.py
│       └── nemoclaw.py
├── config/
│   └── settings.json
├── .env.example                  # Template — copy to .env
└── output/                       # Local scan results (gitignored)
```

---

## Infrastructure: Local vs AWS

Same codebase, different backends via `RUNTIME` environment variable:

| Component | `RUNTIME=local` | `RUNTIME=aws` |
|-----------|-----------------|---------------|
| Queue | Redis (BRPOP/LPUSH) | SQS |
| Storage | Filesystem (`/output/`) | S3 |
| Secrets | `.env` file | AWS Secrets Manager |
| Compute | docker compose | ECS Fargate |
| Database | Local PostgreSQL | RDS PostgreSQL |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Claude API key |
| `RUNTIME` | No | `local` | `local` or `aws` |
| `DATABASE_URL` | No | `postgresql://scanner:scanner@postgres:5432/scanner` | PostgreSQL URL |
| `REDIS_URL` | No | `redis://redis:6379` | Redis URL |
| `JWT_SECRET` | No | `dev-secret-change-in-production` | JWT signing secret |
| `NOTIFICATION_CHANNELS` | No | `[]` | JSON array of notification configs |
| `S3_BUCKET` | AWS only | — | S3 bucket for reports |
| `SQS_SCAN_QUEUE_URL` | AWS only | — | SQS queue URL |

---

## Notification Configuration

Configure via `NOTIFICATION_CHANNELS` env var or API:

**Slack:**
```json
{"type": "slack", "config": {"webhook_url": "https://hooks.slack.com/services/..."}, "min_severity": "warning"}
```

**Discord:**
```json
{"type": "discord", "config": {"webhook_url": "https://discord.com/api/webhooks/..."}, "min_severity": "critical"}
```

**Email:**
```json
{"type": "email", "config": {"smtp_host": "smtp.gmail.com", "smtp_port": 587, "username": "...", "password": "...", "to_email": "alerts@example.com"}, "min_severity": "info"}
```

**Webhook:**
```json
{"type": "webhook", "config": {"url": "https://your-service.com/hooks/scan"}, "min_severity": "info"}
```

Severity routing: Notifications only fire when `risk_score >= 80` (critical), `>= 50` (warning), or always (info).

---

## Requirements

- Docker & Docker Compose
- Anthropic API key (Claude Sonnet 4)
- ~8GB disk space (worker image with all tools)

---

## License

See [COMMERCIAL.md](COMMERCIAL.md) for licensing details.
