# SSSAI — Autonomous AI Security Scanner

AI-powered autonomous security auditing platform inspired by [Karpathy's autoresearch principles](https://x.com/karpathy). Point it at a target — a Claude AI agent autonomously plans the attack strategy, runs 80+ security tools with systematic payload variation, proves vulnerabilities with read-only PoCs, challenges its own findings with an adversarial critic, and delivers actionable reports. No manual configuration. No human in the loop.

## How It Works

```
              ┌──────────────────────────────────────────────┐
              │           Autonomous Scan Lifecycle           │
              │                                              │
Target ──►  Discovery ──► Attack Surface ──► Adaptive Plan   │
              │    whatweb, nmap,    update_attack_    adapt_ │
              │    dns, ffuf, http   surface()        plan() │
              │                                              │
            ──┼──► Parallel Hypothesis Branches ─────────────┤
              │    fork_hypothesis_branches()                 │
              │    ┌─ SQLi in forms                          │
              │    ├─ IDOR in APIs                           │
              │    ├─ Auth bypass                            │
              │    ├─ SSRF via fetch endpoints               │
              │    └─ Path traversal                         │
              │                                              │
            ──┼──► Payload Sweep (10 vuln classes) ──────────┤
              │    sweep_payloads() with oracle scoring       │
              │                                              │
            ──┼──► Red-Team Critic ──────────────────────────┤
              │    challenge_finding() — adversarial review   │
              │    verdict: accept / reject / needs_evidence  │
              │                                              │
            ──┼──► Exploitation Gate ────────────────────────┤
              │    Prove-or-demote: PoC on high/critical      │
              │    Unproven findings auto-demoted             │
              │                                              │
            ──┼──► Report + Recommendations ─────────────────┤
              │    Structured findings, attack chains,        │
              │    OWASP/CWE mapping, remediation roadmap    │
              │                                              │
              │  ┌─ Recommended Next Scans ──────────────┐   │
              │  │ • phpmyadmin.internal.example.com      │   │
              │  │ • grafana.monitoring.example.com       │   │
              │  │ • db-server from X-Backend header      │   │
              │  │          [Start Scan] one click        │   │
              │  └───────────────────────────────────────┘   │
              │                                              │
              │  Cross-scan memory stores results for         │
              │  retrieval-augmented planning on next scan    │
              └──────────────────────────────────────────────┘
```

## Key Capabilities

### Autonomous Security Auditing
- **Zero-config scanning** — the AI agent discovers what to test, plans how to test it, and adapts as it finds new attack surface
- **80+ security tools** — nmap, nuclei (8,000+ templates), nikto, sqlmap, testssl, zap-cli, wapiti, trivy, semgrep, and many more
- **11 scan types** — security, pentest, SEO, performance, API, compliance, privacy, cloud, recon, uptime, full

### Auto-Discovery & Expanding Scan Network
Each scan doesn't just report — it maps new infrastructure and recommends follow-up scans:

- **Infrastructure discovery** — the agent watches for new targets in response headers, DNS records, TLS certificate SANs, JavaScript source, API responses, and redirect chains
- **Auto-queue discovery scans** — the agent can queue new scans mid-test when it finds critical infrastructure (DB servers, admin panels, monitoring dashboards)
- **Recommended next scans** — every report includes actionable follow-up recommendations extracted from discovered subdomains, internal hostnames, and exposed services
- **One-click start** — operators can launch any recommended scan directly from the UI with a single click
- **Expanding scan network** — scan A discovers hosts B and C → scans B and C discover hosts D and E → repeat until the full infrastructure is mapped

Real example: scanning `crm.qualityunit.com` auto-generated **17 recommended follow-up scans** including phpMyAdmin instances, Kibana clusters, Grafana dashboards, Salt master, Prometheus, and database servers — all discovered from DNS enumeration and TLS certificate analysis.

### Autoresearch-Inspired Design
Applies Karpathy's autoresearch principles to security auditing:

- **Tight eval signal** — success = working PoC, not just scanner output. The exploitation gate proves every high/critical finding or demotes it.
- **Proposer-critic loop** — the red-team critic adversarially challenges findings. "Is this really a vuln, or a WAF false positive?"
- **Parallel hypothesis trees** — after discovery, the agent forks into concurrent attack branches (SQLi, IDOR, auth bypass, SSRF, etc.), each with narrow context
- **Systematic action-space exploration** — `sweep_payloads` tries 10 vulnerability classes with oracle-scored variants against every discovered endpoint
- **Strategy reflection** — every 8 tool calls the agent is forced to reflect: "What did I learn? Am I being too shallow? What alternatives should I try?"
- **Visible reasoning** — the agent's thinking is logged to the activity timeline so operators can see WHY it chose each action
- **Learning from prior runs** — cross-scan memory auto-recalls relevant experience on similar target classes for retrieval-augmented planning
- **Budget-aware execution** — token/cost/time budgets replace hard iteration caps; the agent gets a warning at 80% and gracefully wraps up

### Prove, Don't Just Report
Every scan goes through three validation layers before a finding reaches your report:

1. **Finding verification** — automated re-probing to confirm each finding (demotes false positives to info)
2. **Red-team critic** — adversarial AI challenges high/critical findings with counter-hypotheses and specific falsification tests
3. **Exploitation gate** — attempts read-only PoC exploitation on eligible findings; unproven claims are demoted

### Non-Destructive by Design
The agent operates under a strict **read-only** testing policy:
- SQL injection: boolean/time-based detection only — never DROP, DELETE, UPDATE
- Command injection: `id`, `whoami`, `sleep` — never rm, shutdown, kill
- XSS: `alert(1)` reflection check — never cookie exfiltration
- All payloads pass through a safety guard deny-list before execution
- See [Non-Destructive Testing Policy](docs/AUTONOMOUS_TESTING.md#17-non-destructive-testing-policy) for full details

## Quick Start

```bash
git clone https://github.com/vzeman/sssai.git
cd sssai/security-scanner
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY
docker compose up --build -d
open http://localhost:8000
```

Register your first account through the dashboard. The first user becomes the admin. Start scanning.

## Architecture

```
User → Dashboard (React SPA) → FastAPI → Redis Queue → Worker Container
                                                            │
                                              Claude AI Agent (Sonnet 4.6)
                                              ┌─────────────┼─────────────────┐
                                              │             │                 │
                                         Tool Dispatch   Sub-Agents    Autonomous
                                         (80+ tools)    (Pentester,   Primitives
                                                         Searcher,    (sweep, critic,
                                                         Coder)       fork, gate)
                                              │             │                 │
                                              └─────────────┼─────────────────┘
                                                            │
                                              ┌─────────────┼─────────────┐
                                              ▼             ▼             ▼
                                         PostgreSQL   Elasticsearch    Storage
                                         (scans,      (findings,       (reports,
                                          users,       activity,        artifacts)
                                          memory)      metrics)
```

### Model Tiers
| Tier | Model | Used For |
|------|-------|----------|
| Discovery | Haiku 4.5 | Routine tool dispatch, HTTP parsing, heartbeat |
| Reasoning | Sonnet 4.6 | Main scan loop, adaptive planning, exploitation decisions |
| Critical | Opus 4.6 | Opt-in for highest-stakes scans |

### The 8 Autonomous Testing Primitives

| Primitive | Module | Purpose |
|-----------|--------|---------|
| Budget-based stopping | `agent/budget.py` | Token/cost/duration limits per scan type (quick/security/pentest/full) |
| Model tiers | `config.py` | Haiku for dispatch, Sonnet for reasoning, Opus for critical |
| Auto-recall memory | `agent/memory.py` | Prior experience on similar targets auto-injected into planning |
| Exploitation gate | `agent/exploitation_gate.py` | Prove high/critical findings with PoC or demote |
| Payload sweeper | `agent/payload_sweeper.py` | 10 vuln classes, oracle-scored systematic parameter variation |
| Red-team critic | `agent/critic_agent.py` | Adversarial sub-agent challenges every non-trivial finding |
| Parallel hypotheses | `agent/hypothesis_executor.py` | Fork N concurrent attack branches after discovery |
| Network retry | `agent/scan_agent.py` | Exponential-backoff retry on transient API errors |

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
| [**Autonomous Testing Deep Dive**](docs/AUTONOMOUS_TESTING.md) | **The agent loop, budgets, exploitation gate, red-team critic, parallel hypotheses, payload sweeper, memory, safety policy** — 2,600+ lines of technical detail |
| [Security Checks](docs/security-checks.md) | Deep dive into all 11 scan types and methodologies |
| [Architecture](docs/architecture.md) | AI agent loop, sub-agents, infrastructure design |
| [API Reference](docs/api-reference.md) | Complete REST API documentation |
| [Configuration](docs/configuration.md) | Environment variables, AI models, notifications |
| [Scanning Tools](docs/scanning-tools.md) | All 80+ tools with descriptions |
| [Deployment](docs/deployment.md) | Local and AWS production deployment |

## License

See [COMMERCIAL.md](COMMERCIAL.md) for licensing details.
