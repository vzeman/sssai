# SSSAI — Simple Security Scan AI Assistant

AI-powered autonomous security scanning platform. Point it at a target, and a Claude AI agent plans the strategy, runs 69+ scanning tools, interprets results in real-time, and delivers actionable reports — all without manual configuration.

## What It Does

- **11 scan types** — Security, penetration testing, SEO, performance, API security, compliance, privacy, cloud, reconnaissance, uptime, and full comprehensive scans
- **AI-driven execution** — Claude plans 3-7 step strategies, adapts to discoveries, delegates to specialized sub-agents
- **69+ scanning tools** — nmap, nuclei (8,000+ templates), nikto, testssl, sqlmap, lighthouse, trivy, and many more
- **Structured reports** — Risk scores, categorized findings, remediation steps, compliance mapping (OWASP, PCI-DSS, GDPR)
- **Continuous monitoring** — Scheduled scans, uptime monitoring, and alerts via Slack, Discord, email, or webhooks
- **Cross-scan memory** — The AI remembers findings across scans and gets smarter over time

## Quick Start

```bash
git clone https://github.com/vzeman/sssai.git
cd sssai/security-scanner
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY
docker compose up --build -d
open http://localhost:8000
```

Register your first account through the dashboard. The first user becomes the admin.

That's it. Start scanning.

## Architecture

```
User → Dashboard/API → Redis Queue → Worker (Claude AI + 69+ Tools)
                                              │
                                    ┌─────────┼─────────┐
                                    ▼         ▼         ▼
                               PostgreSQL   Redis    Storage
```

The worker container runs an autonomous Claude agent that plans, executes, and reports. It delegates to specialized sub-agents (Pentester, Searcher, Coder) and uses loop detection, execution monitoring, and chain summarization to stay on track.

## Scan Types

| Type | What It Does |
|------|-------------|
| `security` | Vulnerability scanning, CVE detection, misconfigurations |
| `pentest` | Penetration testing with PTES methodology |
| `seo` | Technical SEO, Core Web Vitals, accessibility |
| `performance` | Load testing, throughput, latency benchmarks |
| `api_security` | API-specific testing — auth, injection, rate limits |
| `compliance` | OWASP Top 10, PCI-DSS, GDPR, CIS benchmarks |
| `privacy` | Cookie consent, data exposure, email security |
| `cloud` | Container & IaC security scanning |
| `recon` | Subdomain enumeration, technology fingerprinting |
| `uptime` | Availability, TLS cert expiry, DNS checks |
| `full` | All of the above combined |

## Requirements

- Docker & Docker Compose
- Anthropic API key
- ~8 GB disk space

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Prerequisites, setup, troubleshooting |
| [Getting Started](docs/getting-started.md) | First account, first scan, understanding reports |
| [Security Checks](docs/security-checks.md) | Deep dive into all 11 scan types and methodologies |
| [Architecture](docs/architecture.md) | AI agent loop, sub-agents, infrastructure design |
| [API Reference](docs/api-reference.md) | Complete REST API documentation |
| [Configuration](docs/configuration.md) | Environment variables, AI models, notifications, database schema |
| [Scanning Tools](docs/scanning-tools.md) | All 69+ tools with descriptions |
| [Deployment](docs/deployment.md) | Local and AWS production deployment |

## License

See [COMMERCIAL.md](COMMERCIAL.md) for licensing details.
