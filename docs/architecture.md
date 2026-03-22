# Architecture

SSSAI uses Claude AI as an autonomous agent that plans, executes, and reports on security scans. This document explains the system architecture, the AI agent loop, and how the platform's services work together.

## System Overview

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
                              ▲                ▲
                              │                │
                         ┌────┴────────────────┴────┐
                         │   Heartbeat Service       │
                         │   (health checks every    │
                         │   120s + AI summary)      │
                         └───────────────────────────┘
```

## Services

### API Service

The FastAPI-based REST API serves both the web dashboard and programmatic access.

**Responsibilities:**
- User authentication (JWT + optional 2FA)
- Scan creation and status tracking
- Report generation (JSON, HTML, PDF)
- Scheduled scan management
- Uptime monitor management
- Notification channel configuration
- Live scan activity streaming
- Tool registry queries

**Tech:** FastAPI, SQLAlchemy, Pydantic, Jinja2, WeasyPrint

### Worker Service

The core of the platform. An Ubuntu 22.04 container with 69+ security scanning tools and the AI agent runtime.

**Responsibilities:**
- Consuming scan jobs from the Redis queue
- Running the AI agent loop (Claude API calls)
- Executing scanning tools via shell commands
- Storing reports and findings
- Dispatching notifications on completion

**How it processes a scan:**
1. Picks up a scan job from the Redis queue
2. Loads the appropriate scan type prompt
3. Starts the AI agent loop with Claude
4. Agent calls tools (nmap, nuclei, etc.) via `run_command`
5. Agent interprets results and decides next steps
6. Agent calls the `report` tool with structured findings
7. Report is saved and notifications dispatched

### Scheduler Service

Polls the database every 30 seconds for scheduled scans that are due.

**Supported schedules:** `hourly`, `daily`, `weekly`, `monthly`, `12h`, `30m`, `2d`

When a scheduled scan is due, it creates a new scan job and pushes it to the Redis queue, just like a manually triggered scan.

### Monitor Service

Runs uptime checks at configured intervals for each active monitor.

**Check types:**
- **HTTP** — Makes an HTTP request and checks status code, response time
- **TCP** — Tests TCP port connectivity
- **DNS** — Verifies DNS resolution
- **TLS** — Validates SSL certificate, checks expiry

Results update the monitor's status (`up`, `down`, `degraded`) and trigger notifications when status changes.

### Heartbeat Service

Periodically checks the health of all platform modules and generates AI-powered status summaries.

**Checked modules:** API, Worker, Scheduler, Monitor, Redis, PostgreSQL, Elasticsearch

**How it works:**
1. Every 120 seconds (configurable), probes each module
2. Checks Redis connectivity, memory usage, connected clients
3. Checks PostgreSQL connectivity, scan/user counts, running scans
4. Checks Elasticsearch cluster health and node count
5. Checks API health endpoint response time
6. Checks Worker activity and queue depth
7. Checks Monitor status and active monitors
8. Claude Haiku generates a concise natural-language summary
9. Results stored in Redis and Elasticsearch

The heartbeat panel appears at the top of the dashboard with a green/red status indicator.

---

## AI Agent Loop

The scanning engine uses Claude as an autonomous agent. Inspired by [PentAGI](https://github.com/vxcontrol/pentagi) architecture patterns.

### Execution Flow

```
1. PLAN      → Agent generates 3-7 step scan plan
2. EXECUTE   → Agent calls tools, interprets results
3. MONITOR   → Execution monitor reviews progress every 10 tool calls
4. SUMMARIZE → Chain summarization compresses old messages when > 80K chars
5. REFLECT   → Reflector redirects agent back to tools if it produces only text
6. REPORT    → Agent submits structured report with findings
```

### Agent Tools

The agent has 16 tools available:

| Tool | Description |
|------|-------------|
| `run_command` | Execute shell commands with 300s timeout |
| `read_file` | Read files from the output directory |
| `write_file` | Write files to the output directory |
| `http_request` | HTTP requests with full header/body inspection |
| `dns_lookup` | DNS record queries (A, MX, TXT, NS, etc.) |
| `parse_json` | Extract data from JSON using jq expressions |
| `compare_results` | Compare current vs. previous scan results |
| `screenshot` | Capture web page screenshots (desktop + mobile) |
| `web_search` | Search the web via DuckDuckGo |
| `exploit_search` | Search NVD + Exploit-DB for CVEs and exploits |
| `delegate_to_pentester` | Delegate to pentester sub-agent |
| `delegate_to_searcher` | Delegate to searcher sub-agent |
| `delegate_to_coder` | Delegate to coder sub-agent |
| `search_memory` | Query cross-scan memory |
| `store_memory` | Save knowledge for future scans |
| `report` | Submit the final structured report |

### Sub-Agent Delegation

The primary agent can delegate specialized tasks to focused sub-agents, each with their own Claude call, system prompt, and limited tool set:

| Sub-Agent | Role | Available Tools | Max Iterations |
|-----------|------|-----------------|----------------|
| **Pentester** | Deep vulnerability analysis, exploit verification, attack chains | run_command, http_request, dns_lookup, screenshot, read/write_file | 20 |
| **Searcher** | CVE research, exploit lookup, vulnerability details | web_search, exploit_search, http_request, read_file | 20 |
| **Coder** | Custom scripts, data processing, tool configurations | run_command, read/write_file | 20 |

### Loop Detection

The agent loop tracks every tool call and detects problematic patterns:

- **Repeated calls:** Same tool + same arguments called 3+ times → warning injected
- **Oscillation:** A→B→A→B pattern detection → agent redirected
- **Stuck detection:** Agent producing text but no tool calls → reflector engaged

### Execution Monitor

Every 10 tool calls, a separate LLM call reviews the agent's progress:
- Detects stuck or looping behavior
- Identifies missed scan areas
- Recommends strategy pivots
- Feedback is injected into the conversation

### Chain Summarization

When the conversation exceeds 80K characters:
- Older messages are summarized via a separate LLM call
- The most recent 6 messages are kept intact
- Summary preserves: key findings, tools run, vulnerabilities discovered
- A "Summarization Awareness Protocol" in every prompt teaches agents to interpret summaries

### Reflector Pattern

When the agent produces text instead of tool calls (up to 3 attempts):
1. A "reflector" agent analyzes the text output
2. Determines what tool call should come next
3. Redirects the agent back to structured tool use
4. If the agent is genuinely done, directs it to call the `report` tool

### Cross-Scan Memory

PostgreSQL-backed memory store that persists across scans:

| Memory Type | Purpose |
|-------------|---------|
| `guide` | Scanning methodologies that worked well |
| `finding` | Important findings about a target |
| `answer` | Research answers reusable in future scans |

The agent uses `search_memory` before running redundant research and `store_memory` to save reusable knowledge.

### Search Integration

| Tool | Source | Data |
|------|--------|------|
| `web_search` | DuckDuckGo HTML | General vulnerability research, documentation |
| `exploit_search` | NVD + Exploit-DB | CVE IDs, CVSS scores, exploit references |

No API keys needed — both use HTML scraping.

---

## Infrastructure Abstraction

The codebase supports both local and AWS deployment via the `RUNTIME` environment variable:

| Component | `RUNTIME=local` | `RUNTIME=aws` |
|-----------|-----------------|---------------|
| Queue | Redis (BRPOP/LPUSH) | SQS |
| Storage | Filesystem (`/output/`) | S3 |
| Secrets | `.env` file | AWS Secrets Manager |
| Compute | Docker Compose | ECS Fargate |
| Database | Local PostgreSQL | RDS PostgreSQL |

This abstraction is handled by factory functions in `modules/infra/`:
- `get_queue()` — Returns Redis or SQS queue
- `get_storage()` — Returns filesystem or S3 storage
- `get_secrets()` — Returns env var or Secrets Manager reader

---

## Data Flow

### Scan Lifecycle

```
User creates scan (Dashboard/API)
        │
        ▼
API validates request, saves to PostgreSQL (status: queued)
        │
        ▼
Scan job pushed to Redis queue
        │
        ▼
Worker picks up job from queue
        │
        ▼
AI agent loop starts (Claude API)
        │
        ├── Agent calls tools (nmap, nuclei, etc.)
        ├── Results interpreted by Claude
        ├── Sub-agents delegated as needed
        ├── Execution monitor checks every 10 calls
        └── Chain summarization if conversation grows
        │
        ▼
Agent calls report tool with findings
        │
        ▼
Report saved to storage (filesystem/S3)
Scan status updated to completed
Notifications dispatched
```

### Live Activity

During a scan, the worker streams activity to Redis pub/sub. The dashboard subscribes to these events and displays real-time progress including:
- Tool calls and their results
- Agent decisions and reasoning
- Sub-agent delegations
- Scan milestones and findings

## Further Reading

- [Security Checks](security-checks.md) — What each scan type does
- [Scanning Tools](scanning-tools.md) — All 69+ tools in the worker container
- [Configuration](configuration.md) — AI model and infrastructure settings
- [Deployment](deployment.md) — Production deployment guide
