# Security Scanner & Analysis Platform

AI-first security scanning SaaS. Claude AI agent drives the scans — it decides which tools to run, interprets results in real-time, and produces actionable reports.

## Architecture

```
User → API (FastAPI) → Queue (Redis/SQS) → Worker (Claude AI Agent + scanning tools)
                                                    ↓
                                              Storage (local/S3) → Report
```

The AI agent has access to 20+ security, performance, and SEO tools inside a Docker container. It autonomously decides the scanning strategy based on what it discovers.

## Scan Types

| Type | What it does |
|------|-------------|
| `security` | Vulnerability scanning, CVE detection, misconfiguration checks |
| `pentest` | Automated penetration testing (PTES methodology) |
| `performance` | Load testing, Core Web Vitals, response times |
| `seo` | Technical SEO audit, broken links, structured data |
| `uptime` | Availability checks, TLS cert, DNS, port monitoring |
| `compliance` | OWASP, PCI DSS, GDPR, CIS benchmark checks |
| `full` | All of the above in one comprehensive scan |

## Quick Start (Local)

```bash
# 1. Configure
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Start everything
docker-compose up --build

# 3. Register a user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# 4. Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}' | jq -r .access_token)

# 5. Run a scan
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "example.com", "scan_type": "security"}'

# 6. Check results
curl http://localhost:8000/api/scans/ \
  -H "Authorization: Bearer $TOKEN"
```

## Project Structure

```
security-scanner/
├── docker/
│   ├── Dockerfile.worker      # Scan worker (all tools + AI agent)
│   ├── Dockerfile.api         # FastAPI backend
│   └── Dockerfile.monitor     # Uptime monitor
├── docker-compose.yml         # Local dev environment
├── modules/
│   ├── agent/
│   │   ├── scan_agent.py      # AI agent loop (Claude SDK)
│   │   ├── tools.py           # Tool definitions for Claude
│   │   └── prompts/           # System prompts per scan type
│   ├── api/
│   │   ├── main.py            # FastAPI app
│   │   ├── models.py          # SQLAlchemy models
│   │   ├── schemas.py         # Pydantic schemas
│   │   ├── auth.py            # JWT authentication
│   │   └── routes/            # API endpoints
│   ├── infra/
│   │   ├── __init__.py        # Local/AWS backend switcher
│   │   ├── local_queue.py     # Redis queue (local)
│   │   ├── aws_queue.py       # SQS queue (AWS)
│   │   ├── local_storage.py   # Filesystem (local)
│   │   ├── aws_storage.py     # S3 (AWS)
│   │   ├── local_secrets.py   # .env (local)
│   │   └── aws_secrets.py     # Secrets Manager (AWS)
│   ├── monitor/
│   │   └── uptime.py          # Periodic uptime checker
│   └── worker/
│       └── consumer.py        # Queue consumer → launches agent
├── config/
│   └── settings.json
├── output/                    # Local scan results
└── .env.example
```

## Local ↔ AWS

Same code runs everywhere. Set `RUNTIME=local` or `RUNTIME=aws`:

| Component | Local | AWS |
|-----------|-------|-----|
| Queue | Redis | SQS |
| Storage | Filesystem | S3 |
| Secrets | .env | Secrets Manager |
| Compute | docker-compose | ECS Fargate |
| Database | Local PostgreSQL | RDS |

## Tools Available in Scanner

**Security**: nmap, nuclei, nikto, testssl, zap, sslscan, masscan
**Web**: whatweb, gobuster, dirb, ffuf, wpscan, subfinder, httpx
**Performance**: k6, lighthouse, curl
**SEO**: lighthouse, broken-link-checker, pa11y
**Recon**: dig, whois, curl, ping, traceroute

## Requirements

- Docker & Docker Compose
- Anthropic API key
