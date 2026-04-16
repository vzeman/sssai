# Autonomous Security Testing

> **The deep-dive guide to SSSAI's AI-driven scan engine.**
> Covers the autonomous agent loop, the eight new testing primitives shipped
> in PRs #167-#174, the non-destructive testing contract, and how all of
> it fits together end-to-end.

This document is the authoritative reference for how a scan actually runs
inside SSSAI. It complements — it does not replace — the other docs:

| Read first                                           | Then this doc for                          |
|------------------------------------------------------|--------------------------------------------|
| [`architecture.md`](architecture.md)                 | Service topology (API / worker / Redis)   |
| [`AUTONOMOUS_AGENT_ARCHITECTURE.md`](AUTONOMOUS_AGENT_ARCHITECTURE.md) | The (inactive) state-machine alternative  |
| [`security-checks.md`](security-checks.md)           | High-level overview of the 11 scan types  |
| [`scanning-tools.md`](scanning-tools.md)             | Inventory of the 80+ underlying CLI tools |
| [`api-reference.md`](api-reference.md)               | REST endpoints to trigger scans           |
| [`getting-started.md`](getting-started.md)           | First-scan walkthrough                    |
| [`installation.md`](installation.md)                 | Docker Compose setup                      |
| [`conventions.md`](conventions.md)                   | Code style & patterns                     |
| [`layers.md`](layers.md)                             | Dependency layering between modules       |

---

## Table of contents

1. [Overview & philosophy](#1-overview--philosophy)
2. [High-level architecture](#2-high-level-architecture)
3. [The scan lifecycle](#3-the-scan-lifecycle)
4. [The AI agent internals](#4-the-ai-agent-internals)
5. [Tools the agent has access to](#5-tools-the-agent-has-access-to)
6. [The 10 vulnerability classes tested](#6-the-10-vulnerability-classes-tested)
7. [Non-destructive testing policy](#7-non-destructive-testing-policy)
8. [Model tiers & extended thinking](#8-model-tiers--extended-thinking)
9. [Budget system](#9-budget-system)
10. [Exploitation gate](#10-exploitation-gate)
11. [Red-team critic](#11-red-team-critic)
12. [Parallel hypothesis execution](#12-parallel-hypothesis-execution)
13. [Memory system](#13-memory-system)
14. [Finding lifecycle](#14-finding-lifecycle)
15. [UI / frontend integration](#15-ui--frontend-integration)
16. [Operations](#16-operations)
17. [Extending the system](#17-extending-the-system)
18. [Future improvements](#18-future-improvements)

---

## 1. Overview & philosophy

### What SSSAI does

SSSAI is an AI-powered autonomous security scanner. An operator points it at
a target URL (or host, or API base path), selects a scan type, and a Claude
agent takes it from there:

- It **discovers** what the target actually is — technologies, APIs, forms,
  chatbots, GraphQL endpoints, authentication mechanisms, infrastructure.
- It **plans** a targeted testing strategy based on those discoveries.
- It **executes** tests using 80+ shell tools, direct HTTP requests, browser
  automation, parallel hypothesis branches, and read-only payload sweeps.
- It **proves** findings with read-only PoCs; unproven claims get demoted.
- It **critiques** its own work with an adversarial red-team sub-agent.
- It **reports** a structured, triaged, deduplicated finding list with
  CVSS scores, attack chains, and a risk roadmap.

Everything runs in Docker. No pipelines. No manual tool selection. The
agent adapts continuously as it learns about the target.

### The autonomous-testing vision

Traditional scanners run a fixed pipeline: `nmap → nuclei → sqlmap → report`.
They are fast, predictable, and produce enormous amounts of noise — most of
it irrelevant to the specific target. An e-commerce shop and a GraphQL
backend get roughly the same test coverage.

SSSAI inverts that. The scanner is an agent with a toolbox. It decides
what to run based on what it sees. A Shopify site triggers e-commerce
protocol probing. A chatbot widget triggers prompt-injection testing. A
GraphQL endpoint triggers introspection + field-level auth testing. No
target is tested the same way twice.

### Karpathy-inspired principles

The recent round of upgrades (PRs #167-#174) applied four principles
drawn from Andrej Karpathy's writing on agent architectures. They are the
"why" behind the new primitives.

| Principle                        | How SSSAI applies it                                              | Module                               |
|----------------------------------|-------------------------------------------------------------------|--------------------------------------|
| **Tight eval signal**            | Exploitation gate proves or demotes every high/critical finding   | `modules/agent/exploitation_gate.py` |
| **Narrow context**               | Hypothesis branches get a focused slice of the attack surface     | `modules/agent/hypothesis_executor.py` |
| **Parallel hypotheses**          | N investigation branches fan out after attack-surface map         | `modules/agent/hypothesis_executor.py` |
| **Learning loop**                | Memory auto-store + auto-recall cross-scan                        | `modules/agent/memory.py`            |
| **Cost/latency budget**          | Per-scan-type token/USD/duration/iteration budget                 | `modules/agent/budget.py`            |
| **Adversarial self-critique**   | Red-team critic sub-agent challenges findings pre-report          | `modules/agent/critic_agent.py`      |
| **Systematic probing**           | Payload sweeper fires a curated catalog of read-only oracle tests | `modules/agent/payload_sweeper.py`   |

The philosophy is: **agents work best when they have a fast feedback
loop, clear verdict points, and small enough context windows that the
model's attention doesn't blur**. Every new primitive in this round
exists to tighten one of those knobs.

---

## 2. High-level architecture

SSSAI is a service-oriented system. Five containers (plus three data stores)
coordinate through Redis. The AI agent lives inside the `worker`.

```
                            ┌──────────────────┐
                            │  Browser / curl  │
                            └────────┬─────────┘
                                     │  HTTPS
                                     ▼
                       ┌─────────────────────────┐
                       │      FastAPI (api)      │  :8000
                       │  auth, CRUD, dashboard  │
                       └────┬────────────┬───────┘
                            │            │
                   SQLAlchemy│            │LPUSH scan-jobs
                            ▼            ▼
                 ┌──────────────┐   ┌──────────┐
                 │  PostgreSQL  │   │  Redis   │
                 │ users, scans │   │  queue   │
                 │ memory, etc. │   │  pubsub  │
                 └──────▲───────┘   └────┬─────┘
                        │                │ BRPOP
                        │                ▼
                        │     ┌──────────────────────┐
                        │     │   Worker container   │
                        │     │                      │
                        │     │ scan_agent.run_scan  │
                        │     │        │             │
                        │     │        ▼             │
                        │     │  ┌──────────────┐    │
                        │     │  │  Main loop   │◀──┐│
                        │     │  │ (#iteration) │   ││ loop until report
                        │     │  └─┬────────────┘   ││
                        │     │    │ tool_use       ││
                        │     │    ▼                ││
                        │     │  ┌──────────────┐   ││
                        │     │  │  Tool        │───┤│
                        │     │  │  handlers    │   ││
                        │     │  └─┬────────────┘   ││
                        │     │    │                ││
                        │     │    ├─ run_command ─►│ 80+ CLI tools
                        │     │    ├─ sweep_payloads ►│ payload catalog
                        │     │    ├─ fork_hypotheses ► ThreadPool ►
                        │     │    │                          │      │
                        │     │    │                          ▼      ▼
                        │     │    │                   pentester  searcher  coder
                        │     │    ├─ challenge_finding ► critic LLM
                        │     │    ├─ delegate_to_*    ► sub-agent LLM
                        │     │    └─ report ─┐               │
                        │     │               │               │
                        │     │  Post-processing: verification│
                        │     │                  CVSS scoring │
                        │     │                  triage       │
                        │     │                  critic sweep │
                        │     │               exploitation gate│
                        │     │                  dedup        │
                        │     │                  memory store │
                        │     │               ↓               │
                        │     └──────────────────────────────┘│
                        │                                     │
                        │              persist report.json    │
                        └────── Postgres (scan row) ──────────┘
                                     │
                                     ▼
                       ┌─────────────────────────┐
                       │    Elasticsearch        │  ← findings, tokens
                       │ (findings index + ILM)  │     activities, chat
                       └─────────────────────────┘
                                     │
                            ┌────────┴─────────┐
                            ▼                  ▼
                      Scheduler service   Heartbeat service
                      (cron → enqueue)    (health + stuck scan recovery)

                            Notifications dispatcher (Slack, Discord,
                            email, webhooks, Jira, Linear, GitHub Issues)
                                     ▲
                                     └── triggered from run_scan()
```

Key points:

- **The worker is the only container that calls the Anthropic API.**
  API key never leaves that process.
- **Redis is the message bus.** Scan jobs, activity streams, chat
  messages, and stop signals all flow through Redis lists and pub/sub.
- **PostgreSQL is the source of truth** for scans, users, and memory.
  Elasticsearch is a write-through index for search and analytics.
- **Storage is abstracted.** `RUNTIME=local` uses filesystem + Redis;
  `RUNTIME=aws` uses S3 + SQS. The agent doesn't care.

See [`architecture.md`](architecture.md) for the full service breakdown
and ADRs.

---

## 3. The scan lifecycle

A single scan moves through a chain of phases. Each phase either is
driven by the agent itself (it picks which tools to call) or is a
deterministic post-processing step (verification, gate, dedup, store).

### 3.1 Queue pickup

```
POST /api/scans             (API route)
 └── create Scan row, status=queued
 └── LPUSH scan-jobs { scan_id, target, scan_type, config }

worker.__init__.py
 └── BRPOP scan-jobs
 └── scan_agent.run_scan(scan_id, target, scan_type, config)
```

Entry point: `modules/agent/scan_agent.py:2950` — `def run_scan(...)`.

### 3.2 Phase 0: Deep reconnaissance (MANDATORY)

The master system prompt declares Phase 0 mandatory. The agent may not
skip discovery; tools like `adapt_plan` only produce meaningful output
once the attack surface is partially mapped.

The prompt (at `modules/agent/prompts/master.txt:5-83`) enumerates
seven recon sub-phases:

1. Technology fingerprinting — `whatweb`, `http_request` headers, `wafw00f`
2. Chatbot detection — regex + endpoint probing for Intercom, Drift, etc.
3. API discovery — `/api/`, `/swagger`, `/openapi.json`, `/graphql`
4. GraphQL detection — introspection query, `graphw00f`
5. gRPC detection — HTTP/2 probe, `grpcurl -plaintext`
6. Commerce protocol detection — `/.well-known/ucp`, Stripe keys, ACP
7. Form enumeration + authentication detection + infrastructure mapping

Breach + dark-web exposure checks are added for `security` and
`pentest` scan types.

### 3.3 Phase 1: Attack-surface mapping

The agent calls `update_attack_surface` with structured data — technologies,
APIs, forms, auth mechanisms, graphql endpoints. The handler is at
`modules/agent/scan_agent.py:859` and merges the input into
`scan_context["_attack_surface"]`. This is the foundation everything else
reads.

### 3.4 Phase 2: Adaptive test planning

The agent calls `adapt_plan` with planned test steps and a
`knowledge_needed` list. The handler (`scan_agent.py:~630`):

1. Records the plan revision in `_plan_history`.
2. Checks which knowledge modules are available (`prompts/knowledge/*.txt`).
3. **On the first revision only**, auto-recalls prior experience from
   the memory system (`modules/agent/memory.py:103`,
   `recall_for_planning`). This injects up to 5 structured summaries of
   past scans on similar tech stacks, per-tenant isolated.

The agent then calls `load_knowledge` on relevant modules —
`auth_testing`, `chatbot_testing`, `graphql_testing`, etc. These are
verbatim prompt text injected as tool output.

### 3.5 Phase 3: Execution with continuous adaptation

This is the main `while True` loop at `scan_agent.py:3143`. Each
iteration:

1. **Budget check** (see §9) — warn at 80%, force-report at 100%.
2. **Heartbeat ping** to Redis so the heartbeat service knows the scan
   is alive.
3. **Periodic checkpoint** (every 5 iterations) — saves enough state to
   resume after a worker crash.
4. **Chain summarization** — if conversation exceeds 80K chars, old
   messages are summarized into a single `[CONVERSATION SUMMARY]` block.
5. **Execution monitor** — every 10 tool calls, a separate LLM call
   reviews progress and can inject pivot suggestions.
6. **Human chat check** — polls `scan:chat:inbox:{scan_id}` for
   operator messages, injects them as `[HUMAN MESSAGE]:` prefix.
7. **Stop signal check** — if `scan:stop:{scan_id}` is set, break.
8. **Main LLM call** to Claude with all tools registered.
9. **Tool dispatch** — iterate every `tool_use` block in the response,
   execute the handler, stream activity events.

Within this loop the agent may call `fork_hypothesis_branches` (see
§12) which in turn spawns a ThreadPoolExecutor of sub-agent calls.

### 3.6 Phase 3.5: Attack chain analysis

The agent is expected to include `attack_chains` in its `report` call.
The master prompt (`master.txt:129-155`) lists concrete chain patterns:

- Open redirect + XSS → session hijack
- IDOR + broken access control → admin takeover
- Subdomain takeover + cookie scope → session theft
- SQLi + misconfigured DB → exfiltration + RCE

If the agent forgets, `scan_agent.py:3528` runs
`_run_attack_chain_analysis()` as a fallback — a dedicated LLM call that
builds chains from the final finding list.

### 3.7 Phase 3.6: Post-processing

After `report` is called, the worker runs a deterministic pipeline.
Every step mutates the report dict in place:

| Step                      | File                                           | What it does                                             |
|---------------------------|------------------------------------------------|----------------------------------------------------------|
| **Finding verification**  | `modules/agent/finding_verification.py`        | Re-tests each finding with read-only HTTP probes. Demotes unconfirmed to `info`. |
| **CVSS scoring pass**     | `scan_agent.py:_run_cvss_scoring_pass`         | LLM assigns CVSS vectors where missing.                 |
| **Auto-triage**           | `modules/agent/triage.py`                      | Exploitability + business impact + exposure → priority. |
| **Confidence scoring**    | `scan_agent.py:_apply_confidence_scores`       | 0-100 confidence based on evidence quality.             |
| **Scan interval recommendation** | `modules/agent/scheduling.py`           | Suggests how often to re-scan this target.              |
| **Critic sweep**          | `modules/agent/critic_agent.py`                | Runs adversarial critic on every high/critical finding. |
| **Exploitation gate**     | `modules/agent/exploitation_gate.py`           | Demands a read-only PoC; demotes unprovable findings.   |

The critic sweep and the exploitation gate intentionally run **after**
verification and triage — they operate on finalized severities. A
finding the agent submitted as `medium` that triage promoted to `high`
still gets gated.

### 3.8 Phase 4: Storage, indexing, notifications

1. `storage.put_json("scans/{id}/report.json", report)`
2. Finding deduplication via `modules/agent/finding_dedup.py` — matches
   against previous findings for the same target by `dedup_key` and
   assigns `finding_status` (`new` / `open` / `resolved`).
3. Bulk index to Elasticsearch `scanner-scan-findings`.
4. Conversation log persisted to `scans/{id}/agent_log.json`.
5. HTML report rendered via `modules/reports/generator.py`.
6. Notifications dispatched to Slack / Discord / email / webhooks.
7. Issue-tracker dispatch (Jira / Linear / GitHub Issues).
8. Final progress event published on `scan-progress:{scan_id}` pub/sub.
9. Token usage indexed to `scanner-token-usage`.

### 3.9 Phase 5: Memory auto-store

At scan completion the worker calls `auto_store_scan_summary()`
(`modules/agent/memory.py:222`) to persist a structured summary of the
scan keyed by `user_id` + `target_class`. That summary is what future
scans recall in Phase 2 planning. Idempotent — re-running the same scan
replaces the prior summary.

---

## 4. The AI agent internals

This section is the reverse engineering of `modules/agent/scan_agent.py`
— the file is ~4,000 lines, so here are the load-bearing pieces.

### 4.1 Entry point and context

- `run_scan(scan_id, target, scan_type, config)` at `scan_agent.py:2950`
- `scan_context` dict threaded through every tool handler at
  `scan_agent.py:2963`. Key fields:
  - `scan_id`, `target`, `scan_type`
  - `user_id` (for memory isolation)
  - `_token_tracker` (cumulative token usage)
  - `_budget` (ScanBudget instance)
  - `_attack_surface` (populated by `update_attack_surface`)
  - `_session_manager` (if auth was configured)
  - `_plan_history` (list of plan revisions)

### 4.2 The main loop

```python
# scan_agent.py:3143
while True:
    budget_status = budget.status()
    if budget_status == "exhausted":
        messages.append({"role": "user", "content": "[SYSTEM] Scan budget exhausted..."})
    elif budget.should_warn_once():
        messages.append({"role": "user", "content": "[SYSTEM] Scan budget 80% consumed..."})

    iteration += 1
    budget.record_iteration()
    if iteration > MAX_ITERATIONS:
        break

    _ping_heartbeat(scan_id)
    if iteration % CHECKPOINT_INTERVAL == 0:
        _save_scan_checkpoint(...)

    chain_size = _estimate_chain_size(messages)
    if chain_size > SUMMARIZE_THRESHOLD:
        messages = _summarize_chain(client, messages, scan_context=scan_context)

    if loop_detector.total_calls > 0 and loop_detector.total_calls % MONITOR_INTERVAL == 0:
        monitor_msg = _run_execution_monitor(...)
        if monitor_msg:
            messages.append({"role": "user", "content": monitor_msg})

    # Main LLM call
    response = client.messages.create(
        model=AI_MODEL_REASONING,          # Sonnet 4.6 by default
        max_tokens=16000,
        system=system_prompt,
        tools=all_tools,                   # TOOLS + SUBAGENT_TOOLS
        messages=messages,
        **({"thinking": thinking_param(_main_model)} if ... else {}),
    )
    token_tracker.record(response, caller="main")
    budget.record(usage.input_tokens, usage.output_tokens, AI_MODEL)

    if response.stop_reason == "tool_use":
        # dispatch each tool_use block, build tool_results
        ...
    elif response.stop_reason == "end_turn":
        # reflector pattern — agent forgot to use a tool
        ...
```

Constants governing the loop (top of `scan_agent.py`):

| Constant                | Value       | Purpose                                       |
|-------------------------|-------------|-----------------------------------------------|
| `MAX_OUTPUT_LEN`        | 50_000      | Truncate per-tool output                      |
| `MAX_ITERATIONS`        | 100         | Hard iteration safety ceiling                 |
| `MONITOR_INTERVAL`      | 10          | Every N tool calls run execution monitor      |
| `SAME_TOOL_LIMIT`       | 3           | Loop detector threshold                       |
| `SUMMARIZE_THRESHOLD`   | 80_000      | Chars before summarizing chain                |
| `KEEP_RECENT`           | 6           | Messages kept un-summarized at tail           |
| `CHECKPOINT_INTERVAL`   | 5           | Iterations between checkpoint saves           |

The budget system (#9) is the *primary* stopping mechanism.
`MAX_ITERATIONS` is just a safety net.

### 4.3 LoopDetector

`scan_agent.py:2238`. A `Counter` indexed by `(tool_name, hash(input))`.
Fires a warning when:

- Same call with same args is made ≥ `SAME_TOOL_LIMIT` times (default 3).
- Last 6 calls form an `A→B→A→B→A→B` oscillation pattern.

Warnings are appended to the tool's result so the agent sees them in
its next turn.

### 4.4 Chain summarization

`_summarize_chain()` at `scan_agent.py:2402`. When the conversation
exceeds 80K chars, it:

1. Keeps the first user message (target instruction) intact.
2. Keeps the last `KEEP_RECENT=6` messages intact.
3. Compresses everything in between into a single synthetic assistant
   message prefixed `[CONVERSATION SUMMARY]` via a dedicated LLM call.

The system prompt explicitly instructs the agent: "If you see a
`[CONVERSATION SUMMARY]`, trust it — do NOT re-run tools already
mentioned in it."

### 4.5 Reflector pattern

`_run_reflector()` at `scan_agent.py:2490`. When the agent returns a
text block instead of a tool call (`stop_reason == "end_turn"` with no
`report` yet), the reflector fires a small LLM call to translate that
text into a tool-call redirect. Bounded by `max_reflector_attempts=3`
per continuous text run.

### 4.6 Execution monitor

`_run_execution_monitor()` at `scan_agent.py:2283`. Every 10 tool calls,
a separate (lighter) LLM reviews the recent action log. It can:

- Tell the agent to stop looping on a dead tool.
- Suggest a completely different investigative pivot.
- Confirm the agent is on track (no injection).

Its output is injected as a system-ish user message.

### 4.7 Checkpoint persistence

`modules/agent/checkpoint.py` — simple JSON blob saved to Redis under
`scan:checkpoint:{scan_id}` every 5 iterations. Resume context at
`scan_agent.py:3094` replays the attack surface, plan history, and
findings-so-far into a synthetic `[CONVERSATION SUMMARY]` so the agent
continues without repeating tools. Used for crash recovery by the
heartbeat service (see §16).

### 4.8 Token tracking

`TokenTracker` class at `scan_agent.py:57`. Every LLM call (main, sub-agent,
critic, monitor, reflector, summarizer, CVSS scorer) registers its
input/output tokens with a caller name:

```python
{
  "total_input_tokens": 420_187,
  "total_output_tokens": 34_512,
  "total_tokens": 454_699,
  "estimated_cost_usd": 1.7823,
  "api_calls": 89,
  "by_caller": {
    "main": {"input": 380_000, "output": 28_000, "calls": 45},
    "subagent_pentester": {"input": 30_000, "output": 5_000, "calls": 20},
    "subagent_coder": {"input": 8_000, "output": 1_200, "calls": 12},
    "critic": {"input": 2_000, "output": 300, "calls": 10},
    ...
  }
}
```

The budget (see §9) records against the same token stream for
stopping decisions.

---

## 5. Tools the agent has access to

The agent's toolbox is registered in `modules/agent/tools.py`. There are
42 top-level tools plus delegation to 3 sub-agent types. This section
groups them by purpose.

### 5.1 Shell executor

| Tool          | Purpose                                                                 |
|---------------|-------------------------------------------------------------------------|
| `run_command` | Arbitrary shell command with 300 s default timeout. Gateway to 80+ CLI tools. |
| `read_file`   | Read from `/output/` (where scanner tools dump results).                |
| `write_file`  | Write to `/output/` (e.g., save a custom payload file).                 |

The `run_command` tool description enumerates available tools by
category. See [`scanning-tools.md`](scanning-tools.md) for the full
list. Summary:

| Category          | Tools                                                          |
|-------------------|----------------------------------------------------------------|
| Network           | nmap, masscan, ping, traceroute                                |
| Vulnerability     | nuclei, nikto, zap-cli, wapiti, sqlmap                         |
| API security      | cats, stepci, apifuzzer                                        |
| SSL/TLS           | testssl, sslscan, sslyze, openssl                              |
| Recon             | whatweb, subfinder, httpx, gobuster, dirb, ffuf, wafw00f       |
| OSINT             | amass, theHarvester, spiderfoot                                |
| Headers           | drheader, shcheck.py, curl                                     |
| CORS              | corsy, corscanner                                              |
| Takeover          | subjack, dnsreaper                                             |
| Secrets           | trufflehog, gitleaks                                           |
| Container         | trivy, grype                                                   |
| IaC               | checkov, kics                                                  |
| Supply chain      | syft, retire                                                   |
| SAST              | semgrep                                                        |
| Email             | checkdmarc                                                     |
| Phishing          | dnstwist                                                       |
| SEO               | lighthouse, blc, yellowlabtools, sitespeed.io                  |
| Accessibility     | pa11y, axe                                                     |
| CMS               | wpscan, droopescan                                             |
| Performance       | k6, vegeta, locust, artillery, hey, wrk                        |
| Protocol          | h2spec, wscat                                                  |
| DNS               | dig, whois, dnsrecon                                           |
| CT                | certspotter                                                    |
| Visual            | backstopjs                                                     |
| Auth              | hydra                                                          |
| Cloud             | prowler                                                        |
| Breach            | holehe, breach-parse                                           |
| Utility           | curl, wget, jq, python3, node                                  |

### 5.2 Direct tools (no shell)

| Tool              | Purpose                                                          |
|-------------------|------------------------------------------------------------------|
| `http_request`    | Native httpx request with header inspection. Auto-injects auth headers when a session is active. |
| `dns_lookup`      | A/AAAA/MX/TXT/NS/CNAME/SOA lookups.                              |
| `parse_json`      | Parse JSON file via jq expression.                              |
| `compare_results` | Diff two result files (current vs previous scan).                |
| `screenshot`      | Headless Chrome screenshot; returns filesystem path.             |
| `browser_test`    | Execute Playwright script for DOM XSS, prototype pollution, client-side open redirects. |
| `browser_crawl`   | Auto-crawl forms, links, console logs via Playwright.            |

### 5.3 AI tools

| Tool                    | Purpose                                                    |
|-------------------------|------------------------------------------------------------|
| `adapt_plan`            | Revise scan plan; triggers memory auto-recall on rev #1.  |
| `load_knowledge`        | Inject a specialized methodology prompt on demand.        |
| `update_attack_surface` | Structured attack-surface merge.                          |
| `breach_check`          | HIBP + breach database lookup for a domain.                |
| `credential_leak_check` | Look for exposed emails tied to the domain.                |
| `web_search`            | DuckDuckGo scraping (no API key).                          |
| `exploit_search`        | NVD + ExploitDB scraping.                                  |
| `search_memory`         | Query `scan_memory` for a topic.                           |
| `store_memory`          | Write a memory entry (manual, in addition to auto-store). |
| `ask_human`             | Pause for operator input via chat inbox.                   |
| `report_assets`         | Record discovered assets for the asset inventory.          |

### 5.4 Authenticated-session tools

Only present when `config.auth` is set on the scan. Backed by
`SessionManager` (`modules/agent/session_manager.py`).

| Tool                  | Purpose                                                       |
|-----------------------|---------------------------------------------------------------|
| `get_session_headers` | Return curl flags (`-H "Cookie: ..."`) for CLI tool injection. |
| `test_auth_endpoint`  | Compare authenticated vs unauthenticated responses.          |
| `check_session`       | Verify session is still valid; re-auth if requested.         |

### 5.5 Sub-agent delegation

| Tool                    | Delegates to           | Tool access                                          |
|-------------------------|------------------------|------------------------------------------------------|
| `delegate_to_pentester` | Pentester sub-agent    | `run_command`, `http_request`, `web_search`, etc.    |
| `delegate_to_searcher`  | Searcher sub-agent     | `web_search`, `exploit_search`, memory.              |
| `delegate_to_coder`     | Coder sub-agent        | `run_command`, `read_file`, `write_file` — produces custom Python/bash. |

Each sub-agent runs its own `client.messages.create` loop bounded at
20 iterations (`scan_agent.py:1435`, `_handle_subagent`). The parent
agent receives the sub-agent's final text as a tool result.

### 5.6 Autonomous testing primitives (new — PRs #167-#174)

| Tool                       | Purpose                                                                 |
|----------------------------|-------------------------------------------------------------------------|
| `sweep_payloads`           | Run a curated payload catalog (10 vuln classes) against an endpoint with oracle-based scoring. See §6. |
| `challenge_finding`        | Send one finding to an adversarial red-team critic. See §11.           |
| `fork_hypothesis_branches` | Fan out 3-6 parallel sub-agent investigations. See §12.               |

These are the new primitives the rest of this document focuses on.

### 5.7 Scan-management tools (brain / chat agent only)

A secondary set of tools that let a central "chat brain" agent manage
scans at the fleet level: `list_user_scans`, `get_scan_status`,
`start_scan`, `stop_scan`, `cancel_scan`, `retry_scan`,
`get_scan_report`, `get_stuck_scans`, `force_retry_stuck_scan`,
`force_fail_scan`, `verify_scan`, `run_exploitation`. These are
documented in [`api-reference.md`](api-reference.md).

### 5.8 The report tool

The terminal tool. `report` returns the sentinel string `__REPORT__`,
which the loop catches at `scan_agent.py:3379` and breaks out of the
tool-call iteration. Everything in `block.input` becomes the draft
report passed to post-processing.

---

## 6. The 10 vulnerability classes tested

The `sweep_payloads` tool (`modules/agent/payload_sweeper.py`) exposes
a catalog of 10 read-only oracle-probe vulnerability classes. This is
the curated core of what the agent aggressively tests. The catalog is
`PAYLOAD_CATALOG` at `payload_sweeper.py:40`.

Every payload is a **read-only oracle probe** — it is designed to
reveal presence of the vulnerability without modifying data, spawning
shells, or exfiltrating sensitive content. Every payload also passes
through `safety_guard.py` deny-list validation before it leaves the
process.

### 6.1 sqli_boolean — Boolean-based SQL injection

**Why it matters.** Even when error messages are suppressed, a
Boolean-differential response proves injection — the attacker can
infer schema and exfiltrate data one bit at a time.

**Detection.** Send paired true/false payloads and compare response
signatures (length + status). If `' OR '1'='1` returns a different
content-length than `' OR '1'='2`, we have a boolean oracle.

**Example payloads.**
```
' OR '1'='1          (true)
' OR '1'='2          (false)
" OR "1"="1          (true)
" OR "1"="2          (false)
1 OR 1=1             (true)
1 OR 1=2             (false)
') OR ('1'='1        (true)
') OR ('1'='2        (false)
```

**Oracle.** Median response length delta between `true` and `false`
variants > 50 bytes ⇒ score 0.7+ with reason `boolean_delta=<N>`.
Implementation at `payload_sweeper.py:398-408`.

### 6.2 sqli_time — Time-based SQL injection

**Why it matters.** The catch-all for blind SQLi. Works even when
responses are identical for true/false conditions.

**Detection.** Inject a time-delay payload and measure wall-clock.

**Example payloads.**
```
' AND SLEEP(4)--                       (MySQL)
' AND pg_sleep(4)--                    (PostgreSQL)
'; WAITFOR DELAY '0:0:4'--             (MSSQL)
' AND BENCHMARK(5000000,MD5(1))--      (MySQL fallback)
```

**Oracle.** Elapsed time >= `baseline_elapsed + 2.5s` ⇒ score 0.9
(`time_delta=<x>s>`). Implementation at `payload_sweeper.py:194-201`.

### 6.3 sqli_error — Error-based SQL injection

**Why it matters.** Error messages leak schema, version, and queryable
data directly.

**Example payloads.**
```
'
"
\
' AND extractvalue(1,concat(0x7e,version()))--
```

**Oracle.** Response body contains any of:
```
you have an error in your sql syntax, warning: mysql, unclosed quotation mark,
quoted string not properly terminated, ora-00933, ora-00921, pg::syntaxerror,
pg_query():, sqlite3::, sqlitedatabaseerror, microsoft ole db provider for
sql server, odbc microsoft access driver, syntax error at or near, mysql_fetch,
psycopg2
```
⇒ score 0.85 (`sql_error_signature:<sig>`). `500` response alone ⇒ 0.4.
Full list at `payload_sweeper.py:115-131`.

### 6.4 xss_reflected — Reflected XSS

**Why it matters.** Reflected XSS is the foothold for session hijack,
phishing lures, and CSRF bypass chains.

**Example payloads.**
```
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)
<body onload=alert(1)>
```

**Oracle.** Payload string appears **unescaped** in the response body
⇒ score 0.75 (`payload_reflected_unescaped`). Implementation at
`payload_sweeper.py:213-217`.

Note: HTML-escaped reflection (`&lt;script&gt;`) is not a hit — that's
what the critic will reject with "reflected content that's HTML-escaped
on render".

### 6.5 path_traversal — Path traversal / LFI

**Why it matters.** Leaks config files, source code, sometimes SSH keys
or credentials.

**Example payloads.**
```
../../../../etc/hostname
..\..\..\..\windows\win.ini
....//....//....//etc/hostname           (bypass dot stripping)
%2e%2e%2f%2e%2e%2fetc%2fhostname         (URL-encoded)
/etc/hostname%00                         (null byte termination)
```

We deliberately avoid `/etc/passwd` as the primary probe to prevent
accidental exfiltration of real user data — `/etc/hostname` is a
non-sensitive canary.

**Oracle.** Response contains `root:x:0:0:` (passwd marker) or
`[fonts]` (win.ini marker) ⇒ score 0.95 (`file_signature:<sig>`).
Short plaintext 200 with no HTML ⇒ weaker 0.35. At
`payload_sweeper.py:220-228`.

### 6.6 open_redirect — Open redirect

**Why it matters.** The classic phishing enabler; combined with an XSS
or an OAuth flow it becomes account takeover.

**Example payloads.**
```
//evil.example.com
https://evil.example.com
//google.com
/\evil.example.com
```

**Oracle.** `301/302/303/307/308` response ⇒ score 0.7
(`http_<status>`). The agent is instructed to verify the `Location`
header actually points off-domain.

### 6.7 ssrf_internal — Server-side request forgery

**Why it matters.** Cloud metadata endpoints leak IAM credentials; the
internal network is almost always unprotected from the application
server.

**Example payloads.**
```
http://169.254.169.254/latest/meta-data/     (AWS EC2 metadata)
http://127.0.0.1:22                          (local SSH)
http://localhost:6379                        (local Redis)
http://[::1]:80                              (IPv6 localhost)
file:///etc/hostname                         (file:// scheme)
```

**Oracle.** Body contains file signature (via `content` kind) or a 2xx
response to an internal address (`connect` kind). Cloud metadata
responses are highly distinctive.

### 6.8 cmd_injection_safe — Command injection (read-only)

**Why it matters.** OS command execution is often game-over, but
proving it must not cause damage.

**Example payloads (only read-only probes).**
```
; id
| id
`id`
$(id)
; whoami
| sleep 4                   (time oracle)
; sleep 4                   (time oracle)
```

Notably **absent**: `cat /etc/passwd`, `wget http://evil`, `;rm`. The
safety guard blocks destructive patterns even if a human were to type
them into a custom payload.

**Oracle.** Output reflection (UID line) ⇒ 0.75. Time delta for sleep
payloads ⇒ 0.9.

### 6.9 graphql_introspection — GraphQL introspection

**Why it matters.** When introspection is enabled on production, the
entire schema is public — attackers pick off sensitive fields directly.

**Example payloads.**
```
{__schema{queryType{name}}}
{__schema{types{name}}}
{__type(name:"User"){fields{name}}}
```

**Oracle.** Body contains `__schema` or `queryType` ⇒ score 0.8
(`graphql_introspection_allowed`).

### 6.10 jwt_tamper — JWT algorithm confusion

**Why it matters.** Endpoints that accept `alg=none` or naively verify
against the `alg` header are catastrophically broken — the attacker
mints their own token.

**Example payloads.**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.     (alg=none token)
```

**Oracle.** 200/201 response to the probe ⇒ score 0.6
(`auth_accepted_<status>`).

### Summary table

| Class                   | Oracle kind  | Hit threshold              | Read-only? |
|-------------------------|--------------|----------------------------|-----------|
| `sqli_boolean`          | pair-compare | median length delta > 50   | yes       |
| `sqli_time`             | time         | elapsed >= baseline + 2.5s | yes       |
| `sqli_error`            | error        | error signature match      | yes       |
| `xss_reflected`         | reflection   | payload appears unescaped  | yes       |
| `path_traversal`        | content      | file signature match       | yes (`/etc/hostname`) |
| `open_redirect`         | redirect     | 3xx response               | yes       |
| `ssrf_internal`         | content/connect | signature or 2xx        | yes (probes only) |
| `cmd_injection_safe`    | reflection/time | id output or sleep delay | yes (id/whoami/sleep only) |
| `graphql_introspection` | graphql      | `__schema` in body         | yes       |
| `jwt_tamper`            | auth         | 2xx on alg=none token      | yes       |

Every class entry in `PAYLOAD_CATALOG` is capped at `_MAX_VARIANTS=50`
per sweep. Default is 20. Delay between probes defaults to 100 ms to
avoid DoSing the target.

---

## 7. Non-destructive testing policy

SSSAI is a **read-only scanner**. It is designed to be safe enough to
run against production systems with zero advance coordination. This
section quotes verbatim from the master prompt to make the contract
unambiguous.

### 7.1 Master prompt — Forbidden Actions

From `modules/agent/prompts/master.txt:244-287`:

> ## CRITICAL: Non-Destructive Testing Policy
>
> You are a **read-only** security scanner. Your job is to **prove**
> vulnerabilities exist, NOT to exploit them destructively. Every test
> you run must be safe to execute against a production system.
>
> ### Forbidden Actions (NEVER do these):
> - **SQL Injection**: NEVER use `DROP`, `DELETE`, `UPDATE`, `INSERT`,
>   `ALTER`, `TRUNCATE`, `CREATE`, or any data-modifying SQL statements.
>   Only use `SELECT`, `UNION SELECT`, `ORDER BY`, or time-based/
>   boolean-based techniques that READ data to prove the injection
>   exists.
>   - WRONG: `sqlmap --risk=3 --level=5` (may attempt destructive payloads)
>   - WRONG: `' OR 1=1; DROP TABLE users--`
>   - RIGHT: `' OR 1=1--` (boolean-based detection)
>   - RIGHT: `' UNION SELECT NULL,version(),NULL--` (read-only proof)
>   - RIGHT: `sqlmap -u URL --batch --technique=BEU --no-cast` (safe read-only techniques)
>   - RIGHT: `' AND SLEEP(5)--` (time-based detection, no data modification)
> - **Command Injection**: NEVER execute destructive commands (`rm`,
>   `shutdown`, `kill`, `mkfs`, `dd`, `wget malware`). Only use
>   harmless read commands to prove injection exists.
>   - WRONG: `; rm -rf /`
>   - WRONG: `; cat /etc/shadow` (sensitive data exfiltration)
>   - RIGHT: `; id` or `; whoami` (proves command execution)
>   - RIGHT: `; uname -a` (proves injection, reads system info)
>   - RIGHT: `| sleep 5` (time-based detection)
> - **File Operations**: NEVER write, delete, or modify files on the
>   target. Only read publicly accessible files to prove path traversal
>   or LFI.
>   - WRONG: Writing web shells, uploading malicious files
>   - RIGHT: `../../etc/hostname` (read-only proof of path traversal)
> - **Database Operations**: NEVER modify, drop, or create database
>   objects. Only read schema metadata or version info.
> - **Account Manipulation**: NEVER create, delete, or modify user
>   accounts, roles, or permissions.
> - **Denial of Service**: NEVER intentionally overwhelm the target
>   with traffic or trigger resource exhaustion. Use moderate rate
>   limits for all scanning.
> - **Data Exfiltration**: NEVER extract real user data, PII,
>   credentials, or sensitive business data. If you prove access is
>   possible, report the finding with metadata (row count, column
>   names) — not the actual data.

### 7.2 sqlmap safe flags

> When using sqlmap, ALWAYS include these safety flags:
> ```
> sqlmap -u URL --batch --technique=BEU --no-cast --risk=1 --level=3 --tamper=between --threads=1
> ```
> - `--technique=BEU`: Boolean, Error, Union only (no stacked queries
>   that could modify data)
> - `--risk=1`: Lowest risk level (avoids heavy/destructive tests)
> - NEVER use `--os-shell`, `--os-cmd`, `--file-write`, `--file-dest`,
>   `--sql-shell` with write queries
> - NEVER use `--technique=S` (stacked queries) as it allows arbitrary
>   SQL execution

### 7.3 How to prove vulnerabilities without damage

> 1. **SQL Injection**: Prove with boolean/time-based detection or by
>    reading database version/metadata
> 2. **XSS**: Prove with `alert(1)` or similar harmless JavaScript —
>    never exfiltrate cookies to external servers
> 3. **Command Injection**: Prove with `id`, `whoami`, `uname`, or
>    `sleep` — never run destructive commands
> 4. **SSRF**: Prove by reading internal metadata endpoints or DNS
>    resolution — never access internal services destructively
> 5. **Path Traversal/LFI**: Prove by reading `/etc/hostname` or
>    similar non-sensitive files
> 6. **Authentication Bypass**: Prove access is possible — never modify
>    accounts or data
> 7. **File Upload**: Test with harmless text files — never upload web
>    shells or executables

### 7.4 Enforcement via safety_guard.py

The master prompt is *advisory* — the **enforcement** layer is
`modules/agent/safety_guard.py`. It applies regex-based deny-lists to
every payload before it reaches the sandbox executor or the payload
sweeper:

**Destructive SQL patterns (blocked):**
```
\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b
\bDELETE\s+FROM\b
\bTRUNCATE\s+
\bALTER\s+TABLE\b
\bUPDATE\s+\S+\s+SET\b
\bINSERT\s+INTO\b
\bCREATE\s+USER\b
\bGRANT\s+
\bSHUTDOWN\b
```

**Destructive OS patterns (blocked):**
```
\brm\s+-rf\b
\brm\s+-fr\b
\brm\s+--no-preserve-root\b
\bmkfs\b
\bdd\s+if=
\bformat\s+[a-zA-Z]:
\bshutdown\b
\breboot\b
\bhalt\b
\binit\s+0\b
\bkill\s+-9\s+-1\b
\bkillall\b
```

**DoS patterns (blocked):**
```
:\(\)\{.*:\|:.*\}               (bash fork bomb)
\bfork\s*\(\s*\)\s*while\b
\bwhile\s+true.*do.*fork\b
import\s+os.*os\.fork
\bstress\b
\b/dev/zero\b
\b/dev/urandom\b.*>\s*/dev/
```

**Network destructive patterns (blocked):**
```
\biptables\s+-F\b
\biptables\s+--flush\b
\bnc\s+-l\b.*\bsh\b               (reverse shell listener)
\bbash\s+-i\s+>&\s*/dev/tcp       (reverse shell)
```

Patterns are checked case-insensitively on **both** the raw payload
and its URL-decoded form (double-decoded too) to prevent
percent-encoded bypass. Implementation at `safety_guard.py:78-100`.

The payload sweeper wires the safety guard at `payload_sweeper.py:154`
via `_safety_check()`. Any blocked payload is excluded from the sweep
and the reason is returned in the `blocked_variants` list.

### 7.5 Scope limits

> ## Rules
> - Only scan the authorized target: `{target}`
> - Save all intermediate results to `/output/`
> - Be thorough but efficient — skip irrelevant tools
> - Think like an attacker — what attack chains are possible?
> - Map findings to CWE and OWASP categories where applicable
> - When done, call the `report` tool with your structured findings
> - ALWAYS start with Phase 0 discovery before any testing
> - Adapt your approach based on what you discover — every target is different

---

## 8. Model tiers & extended thinking

### 8.1 The tier system (#171)

SSSAI uses **four model tiers** configured in `modules/config.py`:

| Tier                    | Default model                | Used for                                                  |
|-------------------------|------------------------------|-----------------------------------------------------------|
| `AI_MODEL_DISCOVERY`    | `claude-haiku-4-5-20251001`  | Routine tool dispatch, HTTP parsing, fast recon           |
| `AI_MODEL_REASONING`    | `claude-sonnet-4-6`          | Main agent loop, adapt_plan, CVSS scoring, chain analysis |
| `AI_MODEL_CRITICAL`     | `claude-opus-4-6`            | Opt-in — highest-stakes deep scans                        |
| `AI_MODEL_LIGHT`        | `claude-haiku-4-5-20251001`  | Heartbeat, monitors, short summaries, **critic by default** |

Back-compat: `AI_MODEL` is an alias for `AI_MODEL_DISCOVERY` (old
single-model config still works).

**Where each tier runs:**

| Caller                       | Tier                    | File:line                                |
|------------------------------|-------------------------|------------------------------------------|
| Main scan loop               | `AI_MODEL_REASONING`    | `scan_agent.py:3269`                     |
| Sub-agent dispatcher         | `AI_MODEL` (discovery)  | `scan_agent.py:1460`                     |
| Execution monitor            | `AI_MODEL` (discovery)  | `scan_agent.py:_run_execution_monitor`   |
| Chain summarizer             | `AI_MODEL` (discovery)  | `scan_agent.py:_summarize_chain`         |
| Reflector                    | `AI_MODEL` (discovery)  | `scan_agent.py:_run_reflector`           |
| CVSS scoring pass            | `AI_MODEL_REASONING`    | `scan_agent.py:_run_cvss_scoring_pass`   |
| Attack chain analysis        | `AI_MODEL_REASONING`    | `scan_agent.py:_run_attack_chain_analysis` |
| Red-team critic              | `AI_MODEL_LIGHT`        | `critic_agent.py:45-55` (override: `CRITIC_MODEL`) |

### 8.2 Pricing (per 1M tokens)

From `modules/config.py:63-69`:

| Model                          | Input | Output |
|--------------------------------|-------|--------|
| claude-opus-4-6                | $15   | $75    |
| claude-opus-4-20250514         | $15   | $75    |
| claude-sonnet-4-6              | $3    | $15    |
| claude-sonnet-4-20250514       | $3    | $15    |
| claude-haiku-4-5-20251001      | $0.80 | $4     |

A typical `security` scan uses ~400-600k input tokens and 30-80k output
tokens — mostly on the Sonnet main loop. Cost lands around $1.50-$2.50
for a well-scoped scan. Budget caps (see §9) enforce the ceiling.

### 8.3 Extended thinking (opt-in)

Sonnet-4 and Opus-4 support **extended thinking blocks**. Enable via:

```bash
EXTENDED_THINKING_BUDGET=2000   # tokens
```

Implementation at `config.py:92-101`:

```python
def thinking_param(model: str | None = None, budget: int | None = None) -> dict | None:
    m = model or AI_MODEL_DISCOVERY
    b = budget if budget is not None else EXTENDED_THINKING_BUDGET
    if b <= 0 or not supports_thinking(m):
        return None
    return {"type": "enabled", "budget_tokens": b}
```

Haiku models do **not** support thinking and skip the block. The main
loop checks `supports_thinking()` before injecting the `thinking` kwarg.

**Tuning guidance.**

| Budget | Use when                                                        |
|--------|------------------------------------------------------------------|
| 0      | Default — fast turns, cheap                                      |
| 2000-4000 | Complex targets (GraphQL, gRPC, multi-tenant SaaS)             |
| 8000+  | One-off heavy reasoning runs (bounty hunting, red-team rehearsal) |

Enabling thinking on every turn with `EXTENDED_THINKING_BUDGET=8000`
pushes Sonnet latency to multi-minute turns. That kills the feedback
loop — avoid unless the target justifies it.

### 8.4 Environment overrides

```bash
AI_MODEL_DISCOVERY=claude-haiku-4-5-20251001
AI_MODEL_REASONING=claude-sonnet-4-6
AI_MODEL_CRITICAL=claude-opus-4-6
AI_MODEL_LIGHT=claude-haiku-4-5-20251001
EXTENDED_THINKING_BUDGET=0
CRITIC_MODEL=claude-haiku-4-5-20251001    # overrides critic selection
```

---

## 9. Budget system

Introduced in #172, the budget system replaces pure iteration-based
stopping with a **multi-axis budget**. Module:
`modules/agent/budget.py`.

### 9.1 Why budgets

A single cap on iterations poorly models the failure modes of an agent:
- A single `nmap` tool call can cost $0.02 in tokens — or $0.80 if the
  output is huge and the agent tries to paginate.
- A runaway loop of sub-agents can chew through 200k tokens in 5 iterations.
- An authenticated scan of a SaaS app can legitimately need 50+
  iterations and still be cheap.

The budget tracks **five axes simultaneously**:

| Axis                 | Unit             | Typical quick | Typical pentest |
|----------------------|------------------|---------------|-----------------|
| `max_input_tokens`   | tokens           | 150k          | 1,000k          |
| `max_output_tokens`  | tokens           | 40k           | 250k            |
| `max_usd_cost`       | USD              | $0.50         | $5.00           |
| `max_duration_seconds` | wall clock     | 900 (15 min)  | 7200 (2 h)      |
| `max_iterations`     | loop turns       | 60            | 500             |

### 9.2 Per-scan-type defaults

From `budget.py:56-85`:

```python
DEFAULT_BUDGETS = {
    "quick": {
        "max_input_tokens":  150_000,
        "max_output_tokens": 40_000,
        "max_usd_cost":      0.50,
        "max_duration_seconds": 900,       # 15 min
        "max_iterations":    60,
    },
    "security": {
        "max_input_tokens":  500_000,
        "max_output_tokens": 120_000,
        "max_usd_cost":      2.00,
        "max_duration_seconds": 3600,      # 1 h
        "max_iterations":    300,
    },
    "pentest": {
        "max_input_tokens":  1_000_000,
        "max_output_tokens": 250_000,
        "max_usd_cost":      5.00,
        "max_duration_seconds": 7200,      # 2 h
        "max_iterations":    500,
    },
    "full": {
        "max_input_tokens":  2_000_000,
        "max_output_tokens": 500_000,
        "max_usd_cost":      10.00,
        "max_duration_seconds": 14400,     # 4 h
        "max_iterations":    500,
    },
}
```

There is also a safety ceiling:
```python
HARD_ITERATION_CEILING = 500    # BUDGET_HARD_ITERATION_CEILING
```

Regardless of scan-type settings, the loop exits at 500 iterations.

### 9.3 Environment overrides

Every default is overridable via env vars. Naming convention:
`BUDGET_<SCAN_TYPE>_<FIELD>`.

```bash
BUDGET_QUICK_TOKENS=200000
BUDGET_QUICK_OUTPUT_TOKENS=50000
BUDGET_QUICK_USD=1.00
BUDGET_QUICK_DURATION=1200
BUDGET_QUICK_ITERATIONS=80

BUDGET_SECURITY_TOKENS=750000
BUDGET_SECURITY_USD=3.00

BUDGET_PENTEST_USD=8.00
BUDGET_PENTEST_DURATION=10800          # 3h

BUDGET_FULL_USD=15.00
BUDGET_HARD_ITERATION_CEILING=750
```

### 9.4 Per-scan overrides via config

When creating a scan via API, pass `config.budget`:

```json
POST /api/scans
{
  "target": "https://example.com",
  "scan_type": "security",
  "config": {
    "budget": {
      "max_usd_cost": 0.75,
      "max_duration_seconds": 1800
    }
  }
}
```

Values not specified fall back to the scan-type default
(`budget.py:112-119`).

### 9.5 States: ok / warn_80 / exhausted

`ScanBudget.status()` returns one of:

| Status      | Condition                                  |
|-------------|--------------------------------------------|
| `ok`        | All fractions < 0.80                       |
| `warn_80`   | Any fraction >= 0.80                       |
| `exhausted` | Any fraction >= 1.0, OR iterations >= 500  |

### 9.6 Loop integration

From `scan_agent.py:3143-3180`:

```python
while True:
    budget_status = budget.status()
    if budget_status == "exhausted":
        messages.append({"role": "user", "content":
            f"[SYSTEM] Scan budget exhausted ({budget.most_consumed()} at 100%). "
            "Stop all testing and call the `report` tool NOW with whatever findings you have."
        })
    elif budget.should_warn_once():   # fires exactly once at first crossing
        messages.append({"role": "user", "content":
            "[SYSTEM] Scan budget 80% consumed. Finalize findings and call the "
            "`report` tool soon — avoid starting new lines of investigation."
        })
    iteration += 1
    budget.record_iteration()
    ...
```

At 80%: the agent gets a polite nudge once. At 100%: every subsequent
iteration gets the exhausted message; if the agent still hasn't called
`report`, the fallback at `scan_agent.py:3475` emits a partial-results
report with `warning: budget exhausted`.

### 9.7 Budget summary in the report

Every scan report contains:
```json
"scan_metadata": {
  "budget": {
    "input_tokens":     {"used": 420187, "limit": 500000, "fraction": 0.840},
    "output_tokens":    {"used": 34512,  "limit": 120000, "fraction": 0.288},
    "usd_cost":         {"used": 1.7823, "limit": 2.00,   "fraction": 0.891},
    "duration_seconds": {"used": 2704.2, "limit": 3600,   "fraction": 0.751},
    "iterations":       {"used": 89,     "limit": 300,    "fraction": 0.297},
    "status":           "warn_80"
  }
}
```

The frontend reads this at `ScanDetailsPage.jsx:228-239` and renders a
colored tile (green `ok`, yellow `warn_80`, red `exhausted`).

---

## 10. Exploitation gate

Introduced in #167. The gate is the core "tight eval signal" mechanism
— it forces every high/critical finding to either carry a working PoC
or be demoted. Module: `modules/agent/exploitation_gate.py`.

### 10.1 Why a gate

Security scanners are notorious for false-positive fatigue. A scanner
that reports "possible SQL injection" without actually injecting is
noise. The gate enforces the discipline: **if you can't prove it, it
doesn't ship as high/critical**.

### 10.2 Policies

Controlled via `EXPLOITATION_GATE_POLICY`:

| Policy    | Applies to            | On failure                                 |
|-----------|-----------------------|--------------------------------------------|
| `strict`  | high + critical       | Demote one severity step + mark unverified |
| `lenient` | critical only         | Demote critical; leave high as-is          |
| `off`     | nothing               | Skip the gate entirely                     |

Default is `strict`.

### 10.3 Eligible finding classes

The gate only attempts PoCs for classes where a read-only proof
technique exists. From `exploitation_gate.py:48-59`:

```python
_GATE_ELIGIBLE_CLASSES = {
    "sqli", "sql_injection", "sql injection",
    "xss", "cross-site scripting", "stored xss", "reflected xss",
    "idor", "insecure direct object reference",
    "ssrf", "server-side request forgery",
    "path_traversal", "path traversal", "lfi", "local file inclusion",
    "open_redirect", "open redirect",
    "cors", "cors misconfiguration",
    "auth_bypass", "authentication bypass",
    "command_injection", "command injection", "os command injection",
    "xxe", "xml external entity",
}
```

Classification happens by text match against the finding's `category`,
`type`, `cwe`, `title`, `name`. Findings that don't classify get
`exploitation_status=skipped_ineligible` and no PoC is attempted.

### 10.4 How a PoC attempt works

```
enforce_exploitation_gate(report, target, scan_id)
  └── for each high/critical finding with eligible class:
        _attempt_poc(target, finding)
          └── ExploitationFramework(target).exploit_finding(finding)
          │     └── runs curated payloads from modules/agent/exploitation_engine.py
          │         (already constrained to read-only: SELECT, id, whoami,
          │          alert(1), ../../etc/hostname, etc.)
          └── returns {exploitation_status, poc_payload,
                       poc_response_evidence, poc_reproduction_steps,
                       poc_error, poc_duration_seconds}
```

The heavy `ExploitationFramework` is **lazy-imported** so when the gate
is off, it doesn't load.

### 10.5 Timeouts

| Env var                          | Default | Meaning                                   |
|----------------------------------|---------|-------------------------------------------|
| `EXPLOITATION_GATE_POLICY`       | strict  | strict / lenient / off                    |
| `EXPLOITATION_GATE_PER_FINDING_SEC` | 30   | Max seconds per PoC attempt               |
| `EXPLOITATION_GATE_TOTAL_SEC`    | 300     | Overall wall-clock budget for the gate    |

If the total budget is exhausted mid-loop, remaining findings get
`exploitation_status=skipped_gate_timeout` and the gate exits cleanly.

### 10.6 Severity demotion

On failed PoC, the finding is demoted one step on the ladder:

```
info ← low ← medium ← high ← critical
```

The **original** severity is preserved in `severity_original` so the UI
can show the strikethrough. The finding also gets:

```json
{
  "severity": "medium",                     (new)
  "severity_original": "high",              (new)
  "verification_status": "unverified_unexploitable",
  "exploitation_status": "attempted_failed",
  "poc_error": "No payload succeeded",
  "poc_duration_seconds": 12.7
}
```

### 10.7 Gate metadata in the report

```json
"exploitation_gate": {
  "policy": "strict",
  "attempted": 4,
  "proven": 2,
  "demoted": 2,
  "skipped_ineligible": 1,
  "skipped_already_marked": 0,
  "skipped_insufficient_severity": 12,
  "duration_seconds": 84.3
}
```

The frontend renders a summary tile at `ScanDetailsPage.jsx:240-249`:

```
EXPLOIT GATE  2 proven / 2 demoted / 4 attempted
```

### 10.8 Interaction with the critic

Both critic and gate run post-processing. The critic runs **first** so
the exploitation gate operates on adversarial-critiqued findings. A
critic `reject` verdict doesn't automatically remove a finding (the
agent might have pushed back intentionally), but it becomes visible
alongside the gate's proof status. In practice:

- `critic=accept` + `exploitation_status=proven` → high confidence, ship.
- `critic=accept` + `exploitation_status=attempted_failed` → demoted.
- `critic=needs_more_evidence` + `proven` → still ships; critic was too
  cautious.
- `critic=reject` + `proven` → critic was wrong; ships with a note.

---

## 11. Red-team critic

Introduced in #170. A dedicated adversarial sub-agent that challenges
individual findings. Module: `modules/agent/critic_agent.py`. Prompt:
`modules/agent/prompts/critic.txt`.

### 11.1 Why an adversarial critic

The main agent is optimistic — it wants to find things. False positives
erode customer trust faster than missed findings. The critic's job is
to be aggressively skeptical. It assumes the finding is wrong and
demands the main agent disprove that.

### 11.2 The prompt (verbatim)

From `prompts/critic.txt`:

> You are an adversarial red-team critic reviewing a claimed security
> finding.
>
> Your job is to AGGRESSIVELY challenge the finding. Assume it is wrong
> until proven right. False positives waste real time and damage
> customer trust — your job is to catch them.
>
> You will be given a single finding in JSON. Analyze it and respond
> with STRICT JSON in this exact shape:
>
> ```json
> {
>   "verdict": "accept" | "reject" | "needs_more_evidence",
>   "confidence": 0.0–1.0,
>   "counter_hypotheses": [
>     "Plausible reason the finding could be wrong",
>     "..."
>   ],
>   "falsification_tests": [
>     "Specific test the main agent should run to falsify the finding",
>     "..."
>   ],
>   "missing_evidence": [
>     "Specific piece of evidence whose absence weakens the finding",
>     "..."
>   ],
>   "summary": "One-sentence assessment"
> }
> ```
>
> Guidelines:
> - Focus on COMMON false-positive patterns: WAF error pages, cached
>   responses, generic 500s, parameters the server ignores, reflected
>   content that's HTML-escaped on render, CORS headers only on
>   OPTIONS, etc.
> - For claimed SQL injection without a working PoC: reject or
>   needs_more_evidence unless there's boolean-delta, time-based, or
>   error-signature evidence.
> - For claimed XSS without demonstrated payload reflection: reject
>   unless execution context is shown.
> - For claimed SSRF without successful internal fetch:
>   needs_more_evidence.
> - For "missing header" findings: accept only if the header is
>   actually absent (not just differently named).
> - For scanner-only findings (no manual verification in evidence):
>   lean toward needs_more_evidence.
>
> Be skeptical. Be specific. Do not hedge — pick one of the three
> verdicts.
>
> Output ONLY the JSON object, no other text.

### 11.3 Verdict schema

```json
{
  "verdict": "accept" | "reject" | "needs_more_evidence",
  "confidence": 0.82,
  "counter_hypotheses": [
    "The 500 response may be a generic error page, not SQL injection",
    "The time delay could be rate limiting, not pg_sleep"
  ],
  "falsification_tests": [
    "Send the same payload without the SLEEP clause and compare response time",
    "Send 10 identical requests and measure variance"
  ],
  "missing_evidence": [
    "No boolean-differential payload pair was tested",
    "Error message is not in evidence"
  ],
  "summary": "Scanner-only finding with weak timing evidence — needs paired boolean test.",
  "model": "claude-haiku-4-5-20251001"
}
```

The parser (`critic_agent.py:58-100`) is tolerant of code fences and
normalizes missing keys. Unparseable output collapses to a
`needs_more_evidence` stub so the caller always gets a usable verdict.

### 11.4 Two integration points

**1. Automatic sweep (post-processing).** `scan_agent.py:3594-3620`:

```python
if os.environ.get("CRITIC_AUTO_ENABLED", "true").lower() in ("1", "true", "yes"):
    for f in report.get("findings", []):
        if (f.get("severity") or "").lower() not in ("high", "critical"):
            continue
        if f.get("critic_verdict"):          # skip if already critiqued
            continue
        f["critic_verdict"] = challenge_finding(f)
        _critiqued += 1
        if _critiqued >= 15:
            break
```

Runs on every high/critical finding that doesn't already carry a
verdict. Capped at 15 findings per scan to keep cost predictable.

**2. Mid-scan tool call.** The agent can call `challenge_finding(finding=...)`
at any time — e.g., before putting a non-trivial claim into its report.
This is the "iterate earlier" path. Handler at `scan_agent.py:760`.

### 11.5 Env controls

| Env var               | Default | Meaning                                    |
|-----------------------|---------|--------------------------------------------|
| `CRITIC_AUTO_ENABLED` | true    | Toggle automatic post-processing sweep     |
| `CRITIC_MODEL`        | unset   | Override critic model (defaults to LIGHT tier) |

### 11.6 Cost guard

The critic uses the **light model** (Haiku) by default. A typical
verdict is ~1.5k input / 500 output tokens, costing ~$0.003. The 15
per-scan cap means a critic sweep is at most ~$0.05.

---

## 12. Parallel hypothesis execution

Introduced in #168. After the agent maps the attack surface, it can
fork into N parallel investigation branches — each with a narrow
context and a specific hypothesis to test. Module:
`modules/agent/hypothesis_executor.py`.

### 12.1 Why parallel hypotheses

A single agent pursuing multiple attack paths linearly runs into two
problems:

1. **Context pollution.** Looking for SQLi while also testing GraphQL
   introspection means both contexts interfere in the main loop — the
   agent starts mixing payloads.
2. **Wall clock.** Each attack path is independent, so running them
   serially wastes time.

Karpathy's principle: **narrow context + parallel hypotheses** solves
both. Each branch is a focused pentester sub-agent with exactly the
pieces of the attack surface relevant to its hypothesis.

### 12.2 Hypothesis derivation (not fabrication)

`fork_hypotheses(attack_surface, scan_type)` at
`hypothesis_executor.py:51` only returns branches whose prerequisites
are satisfied by the actual surface. The rules:

| Hypothesis                              | Required surface element                 | Scan types     |
|-----------------------------------------|------------------------------------------|----------------|
| `h_sqli_forms` (SQLi in forms)         | `forms` or `login_forms`                 | all            |
| `h_xss_forms` (XSS in forms)           | `forms` or `login_forms`                 | all            |
| `h_idor_api` (IDOR in APIs)            | `api_endpoints` or `apis`                | all            |
| `h_api_auth` (missing auth on APIs)    | `api_endpoints` or `apis`                | all            |
| `h_graphql_introspection`              | `graphql_endpoints`                      | all            |
| `h_session_mgmt`                       | `auth_mechanisms` or `login_forms`       | all            |
| `h_ssrf`                               | universal — checks URL params            | all            |
| `h_path_traversal`                     | universal — checks file-like params      | all            |
| `h_file_upload`                        | surface contains "upload"/"attachment"   | pentest + full |
| `h_open_redirect`                      | universal                                | pentest + full |

If the attack surface has no forms, no SQLi-in-forms branch is
generated — the hypothesis executor refuses to fabricate work.

### 12.3 Branch definition

Each branch is a dict:

```python
{
    "id": "h_sqli_forms",
    "title": "SQL injection in discovered forms",
    "vulnerability_class": "sqli",
    "focus": "forms",
    "task_instructions": (
        "Test every discovered form for SQL injection using boolean, "
        "time-based, and error-based oracle techniques. For each form "
        "field, use sweep_payloads with vulnerability_class='sqli_boolean' "
        "and 'sqli_time'. Record hits with payload, response, and reproduction steps."
    ),
}
```

The instructions point branches at the payload sweeper (§6) — the two
primitives compose.

### 12.4 Narrow context construction

`_run_branch()` at `hypothesis_executor.py:201` builds a narrow
context for each branch by projecting the full attack surface to the
fields relevant to the branch's `focus`:

```python
focus_key_map = {
    "forms":            ["forms", "login_forms"],
    "api_endpoints":    ["api_endpoints", "apis"],
    "graphql_endpoints": ["graphql_endpoints"],
    "auth":             ["auth_mechanisms", "login_forms"],
    "url_params":       ["api_endpoints", "apis"],
    "file_params":      ["api_endpoints", "apis"],
    "file_ops":         ["api_endpoints", "file_uploads"],
    "redirect_params":  ["api_endpoints", "apis"],
}
```

So the SQLi-in-forms branch sees `forms` + `login_forms` + `target` +
`hypothesis` — not the full 50k-char surface map. This keeps the
sub-agent's attention on exactly one attack path.

### 12.5 Parallel execution

```python
# hypothesis_executor.py:274
def run_parallel(hypotheses, scan_context, subagent_dispatcher, concurrency=None, max_branches=None):
    max_cap = int(os.environ.get("HYPOTHESIS_MAX_BRANCHES", max_branches or 6))
    hypotheses = hypotheses[:max_cap]

    conc = int(concurrency or os.environ.get("HYPOTHESIS_BRANCH_CONCURRENCY", "3"))
    conc = max(1, min(conc, 6))

    with ThreadPoolExecutor(max_workers=conc) as pool:
        futures = {
            pool.submit(_run_branch, h, scan_context, subagent_dispatcher): h
            for h in hypotheses
        }
        for fut in as_completed(futures):
            results.append(fut.result())
```

Each worker calls `_handle_subagent("pentester", ...)` — the existing
sub-agent dispatcher. That gives each branch access to the full tool
registry (run_command, http_request, sweep_payloads, etc.) via the
pentester role.

`ThreadPoolExecutor` is used instead of asyncio because the Anthropic
SDK call + tool dispatch is synchronous. The GIL is fine here —
waiting on network IO releases it, so 3-6 parallel threads achieve
near-linear speedup.

### 12.6 Env controls

| Env var                          | Default | Meaning                                   |
|----------------------------------|---------|-------------------------------------------|
| `HYPOTHESIS_MAX_BRANCHES`        | 6       | Hard cap on branches per fork            |
| `HYPOTHESIS_BRANCH_CONCURRENCY`  | 3       | Parallelism (clamped 1-6)                |

### 12.7 Returned shape

```json
{
  "branches": [
    {
      "branch_id": "h_sqli_forms",
      "title": "SQL injection in discovered forms",
      "status": "completed",
      "duration_s": 42.8,
      "raw_output": "[PENTESTER SUB-AGENT RESULT]\n{ ... branch findings ... }"
    },
    {
      "branch_id": "h_idor_api",
      "status": "failed",
      "error": "TimeoutError: ..."
    }
  ],
  "count": 4,
  "concurrency": 3,
  "summary": "Ran 4 hypothesis branches with concurrency=3. completed=3, failed=1"
}
```

The main agent merges findings from each branch's raw_output into its
running finding list. The merge is done by the agent itself, not
mechanically — the main agent can sanity-check each branch's claims
before accepting them.

---

## 13. Memory system

Introduced in #174. Cross-scan memory with strict per-tenant isolation
and retrieval-augmented planning. Module: `modules/agent/memory.py`.

### 13.1 Schema

Stored in PostgreSQL. The module auto-creates the table idempotently
on first use (`memory.py:44-66`):

```sql
CREATE TABLE IF NOT EXISTS scan_memory (
    id           SERIAL PRIMARY KEY,
    content      TEXT NOT NULL,
    memory_type  VARCHAR(50) NOT NULL DEFAULT 'guide',    -- 'scan_summary' | 'guide' | ...
    tags         TEXT[] DEFAULT '{}',
    metadata     JSONB DEFAULT '{}',
    scan_id      VARCHAR(100),
    target       VARCHAR(500),
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Added in #174:
    user_id      VARCHAR(100),                            -- tenant isolation key
    target_class VARCHAR(200),                            -- derived from tech stack
    scan_type    VARCHAR(50),
    technologies TEXT[]
);
CREATE INDEX idx_scan_memory_user_id     ON scan_memory(user_id);
CREATE INDEX idx_scan_memory_target_class ON scan_memory(target_class);
```

### 13.2 Per-tenant isolation

`recall_for_planning()` **fails closed** when `user_id` is missing —
never returns memories cross-tenant:

```python
# memory.py:109-114
user_id = scan_context.get("user_id") or scan_context.get("_user_id")
if not user_id:
    return ""  # Fail closed — never leak across tenants
```

Every query filters by `user_id`:
```sql
SELECT ... FROM scan_memory
 WHERE user_id = :user_id AND memory_type = 'scan_summary'
```

### 13.3 target_class derivation

A deterministic identifier for a target's technology stack.
`derive_target_class()` at `memory.py:75`:

```python
def derive_target_class(technologies):
    seen = []
    for t in technologies or []:
        n = _normalize_tech(str(t))     # lowercase, underscored, 40 char cap
        if n and n not in seen:
            seen.append(n)
    seen.sort()                         # deterministic
    return "+".join(seen[:8])           # cap at 8 techs
```

Examples:
```
["Shopify", "Cloudflare", "jQuery"]     → "cloudflare+jquery+shopify"
["nginx", "React", "PostgreSQL"]        → "nginx+postgresql+react"
["WordPress 6.2", "PHP 8.1"]            → "php_8.1+wordpress_6.2"
```

Similar stacks hash to the same key, enabling memory transfer between
targets with the same tech.

### 13.4 recall_for_planning scoring

Called on the first `adapt_plan` revision. Fetches the last 100
memories for the user, scores each, returns top-K:

```python
# memory.py:144-158
score = tech_overlap * 0.7 +
        (0.2 if row.scan_type == scan_type else 0) +
        (0.1 if row.target_class == target_class else 0)
```

Where `tech_overlap = |req_tech ∩ row_tech| / |req_tech|`. Minimum
threshold `_MIN_TECH_OVERLAP = 0.25`.

### 13.5 Output format

The recalled block is injected verbatim into the `adapt_plan` tool
result:

```markdown
## Prior experience on similar targets
(auto-recalled 3 relevant memories for target_class=cloudflare+shopify)

### 1. score=0.95 scan_type=security
Technologies: shopify, cloudflare, jquery
{ target: "https://old-shop.example.com",
  target_class: "cloudflare+jquery+shopify",
  technologies: ["Shopify", "Cloudflare", "jQuery"],
  scan_type: "security",
  findings_summary: [
    {"title": "Missing Strict-Transport-Security header", "severity": "medium", ...},
    {"title": "GraphQL introspection enabled", "severity": "high", "confirmed": true, ...}
  ],
  working_payloads: ["'{__schema{types{name}}}'"],
  risk_score: 72,
  finding_count: 12,
  timestamp: "2026-04-14T11:02:14" }

### 2. score=0.80 scan_type=security
...
```

The agent sees this as a plain tool result, can cross-reference working
payloads, and often pivots directly to verified attack paths from prior
scans on similar stacks.

### 13.6 Auto-store

Called from `run_scan` after all post-processing:

```python
# auto_store_scan_summary in memory.py:222
payload = {
    "target":           target,
    "target_class":     target_class,
    "technologies":     technologies[:20],
    "scan_type":        scan_type,
    "findings_summary": _summarize_findings(findings),   # no PII — just
                                                          # title/severity/
                                                          # category/confirmed/owasp
    "working_payloads": _extract_working_payloads(findings),  # cap 20, <500 chars
    "risk_score":       report.get("risk_score", 0),
    "finding_count":    len(findings),
    "timestamp":        "2026-04-16T12:34:56",
}
```

**Idempotent.** Any previous summary for the same `scan_id` is deleted
first — rerunning a scan replaces the old memory.

**Skipped when.**
- `user_id` is missing (strict)
- No findings (nothing to remember)

### 13.7 No PII in memory

`_summarize_findings` and `_extract_working_payloads` deliberately strip
raw response bodies, usernames, tokens, and other sensitive data. Only
structural hints persist: finding titles, severities, OWASP mappings,
and short (<500 char) payload strings.

### 13.8 Complementary manual memory tools

The agent can also use `search_memory` and `store_memory` mid-scan for
ad-hoc notes (a running guide, a reusable payload). These are
implemented in `scan_agent.py:1527+` and predate #174 — they store to
the same `scan_memory` table but with `memory_type='guide'` by default.
Manual notes do NOT participate in the auto-recall scoring.

---

## 14. Finding lifecycle

A finding travels through ~9 stages from agent submission to
dashboard. Each stage mutates the finding dict in place.

```
┌─────────────────────┐
│ Agent submits       │  part of `report` tool call
│ (title, severity,   │
│  category, evidence,│
│  cwe, owasp)        │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Finding verification│  modules/agent/finding_verification.py
│ Read-only HTTP re-  │  • sets verification_status (confirmed|false_positive|unverified)
│ tests; demotes      │  • demotes false_positives to info
│ unconfirmed to info │  • sets confidence (0-100)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ CVSS scoring pass   │  LLM assigns CVSS vector where missing
└──────────┬──────────┘  • adds cvss_score, cvss_vector
           ▼
┌─────────────────────┐
│ Auto-triage         │  modules/agent/triage.py
│ Exploitability +    │  • adds exploitability, business_impact, exposure
│ business impact +   │  • computes priority_score
│ exposure → priority │  • assigns action_category (fix_now / plan / monitor / ignore)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Confidence scoring  │  scan_agent._apply_confidence_scores
│ Evidence strength   │
│ → 0-100             │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Attack chain        │  scan_agent._run_attack_chain_analysis (fallback)
│ analysis            │  attaches findings to chains via finding_ref
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Critic sweep        │  modules/agent/critic_agent.py
│ Adversarial verdict │  • adds critic_verdict
│ on high/critical    │    (accept|reject|needs_more_evidence)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Exploitation gate   │  modules/agent/exploitation_gate.py
│ Prove-or-demote     │  • adds exploitation_status, poc_payload,
│ high/critical       │    poc_response_evidence, poc_reproduction_steps
│                     │  • demotes severity on failure (+ severity_original)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Storage             │  • put_json("scans/{id}/report.json")
│ + deduplication     │  • modules/agent/finding_dedup.py matches
│ + ES indexing       │    against prior scans by dedup_key, assigns
│                     │    finding_status (new|open|resolved)
│                     │  • bulk_index to scanner-scan-findings index
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ UI                  │  ScanDetailsPage.jsx reads the final dict
└─────────────────────┘
```

### 14.1 The finding dict at each stage

Agent submission:
```json
{
  "title": "GraphQL introspection enabled",
  "severity": "high",
  "category": "api_security",
  "owasp": "API8:2023 Security Misconfiguration",
  "cwe": "CWE-16",
  "description": "...",
  "evidence": "POST /graphql with {__schema...} returned 200 with schema",
  "remediation": "Disable introspection in production",
  "affected_urls": ["https://example.com/graphql"]
}
```

After verification:
```json
{ ... , "verification_status": "confirmed", "confidence": 92 }
```

After CVSS pass:
```json
{ ... , "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/..." }
```

After triage:
```json
{ ... , "exploitability": "easy", "business_impact": "critical",
        "exposure": "external", "priority_score": 78,
        "action_category": "fix_now" }
```

After critic sweep:
```json
{ ... , "critic_verdict": {
    "verdict": "accept",
    "confidence": 0.85,
    "counter_hypotheses": [...],
    "falsification_tests": [...],
    "summary": "...",
    "model": "claude-haiku-4-5-20251001"
}}
```

After exploitation gate (proven):
```json
{ ... , "exploitation_status": "proven",
        "poc_payload": "{__schema{types{name}}}",
        "poc_response_evidence": "... User, Order, PaymentMethod, AdminSecret ...",
        "poc_reproduction_steps": ["POST /graphql", "Body: {__schema...}", "Observe 200"],
        "poc_duration_seconds": 1.2 }
```

After exploitation gate (failed) — severity demotion:
```json
{ "severity": "medium", "severity_original": "high",
  "verification_status": "unverified_unexploitable",
  "exploitation_status": "attempted_failed",
  "poc_error": "No payload succeeded",
  "poc_duration_seconds": 12.7 }
```

After dedup:
```json
{ ... , "dedup_key": "hash-of-(target, category, affected_url)",
        "finding_status": "open",       (new | open | resolved)
        "first_seen_scan_id": "scan_20260312_abc",
        "first_seen_date": "2026-03-12T10:00:00Z",
        "last_seen_scan_id": "scan_20260416_xyz" }
```

### 14.2 Where each stage reads/writes

| Stage             | Reads                     | Writes                                                   |
|-------------------|---------------------------|----------------------------------------------------------|
| Verification      | title, category, urls     | verification_status, verification_note, confidence, severity (demote) |
| CVSS              | severity, category, cwe   | cvss_score, cvss_vector                                  |
| Triage            | all above                 | exploitability, business_impact, exposure, priority_score, action_category |
| Confidence        | evidence, verification    | confidence                                               |
| Chains            | all findings              | adds top-level `attack_chains` to report                 |
| Critic            | all                       | critic_verdict (on high/critical only)                   |
| Gate              | severity, category, title | exploitation_status, poc_*, severity_original, severity  |
| Dedup             | category, affected_url    | dedup_key, finding_status, first/last_seen_*             |

The pipeline is **strictly ordered**: running the gate before
verification would result in PoC attempts on false positives. The
critic sweep specifically runs AFTER triage so it critiques final
severities.

---

## 15. UI / frontend integration

The operator-facing surface for scans is the React dashboard
(`frontend/src/pages/ScanDetailsPage.jsx`). Three new UI elements
reflect the new primitives.

### 15.1 Risk, status, and duration

Top metric tiles show:
- Total risk score (0-100)
- Status badge (running / completed / failed)
- Duration (seconds → human-readable)
- Tool calls count

### 15.2 Budget tile

`ScanDetailsPage.jsx:228-239`:

```jsx
{report?.scan_metadata?.budget && (
  <div>
    <div>Budget (USD)</div>
    <div>
      ${report.scan_metadata.budget.usd_cost?.used?.toFixed(3) ?? 0}
      <span> / ${report.scan_metadata.budget.usd_cost?.limit ?? 0}</span>
      <span className={
        status === 'exhausted' ? 'text-red-400'
      : status === 'warn_80'   ? 'text-yellow-400'
      :                          'text-green-400'
      }>
        ({status})
      </span>
    </div>
  </div>
)}
```

Rendered as: `$1.782 / $2.00 (warn_80)` in yellow.

### 15.3 Exploit Gate tile

`ScanDetailsPage.jsx:240-249`:

```
EXPLOIT GATE   2 proven / 2 demoted / 4 attempted
```

Only rendered when `attempted > 0`.

### 15.4 Findings table — Proof and Critic columns

`ScanDetailsPage.jsx:296-348`. New columns:

| Column   | Renders                                                                |
|----------|------------------------------------------------------------------------|
| Proof    | `✓ PoC` (green) / `✗ no PoC` (red) / `n/a` (gray) / `—`                 |
| Critic   | `accept` (green) / `reject` (red) / `more evidence` (yellow) / `—`     |

The severity cell also shows strikethrough of `severity_original` when
the exploitation gate demoted the finding:

```
HIGH         ← actual severity (after gate)
high         ← strikethrough of severity_original
```

### 15.5 Timeline tab

Reads activity events from the Redis activity stream. New event types:

| Event type              | Origin                                   |
|-------------------------|------------------------------------------|
| `payload_sweep`         | `_handle_sweep_payloads` — logs URL + top score |
| `critic_verdict`        | `_handle_challenge_finding`              |
| `hypothesis_fork_start` | `_handle_fork_hypothesis_branches`       |
| `hypothesis_fork_complete` |                                       |
| `exploitation_gate`     | Gate enforcement in post-processing      |
| `critic_sweep`          | Auto-sweep in post-processing            |
| `memory_recall`         | First `adapt_plan` call                  |

Each event has `timestamp`, `type`, and per-type fields. The timeline
renders them chronologically with color-coded dots.

### 15.6 Logs tab

Full LLM conversation log from `scans/{id}/agent_log.json`. Roles,
tool calls, tool results — read-only debugging view.

---

## 16. Operations

### 16.1 Docker Compose

Standard build + run:

```bash
docker compose up --build -d
docker compose logs -f worker         # watch the agent
docker compose logs -f api            # watch the API
docker compose down                   # stop everything
```

Rebuild a single service:

```bash
docker compose up --build -d api
docker compose up --build -d worker
```

### 16.2 Environment variables reference

Model selection (§8):

```bash
ANTHROPIC_API_KEY=sk-ant-...
AI_MODEL_DISCOVERY=claude-haiku-4-5-20251001
AI_MODEL_REASONING=claude-sonnet-4-6
AI_MODEL_CRITICAL=claude-opus-4-6
AI_MODEL_LIGHT=claude-haiku-4-5-20251001
EXTENDED_THINKING_BUDGET=0                # 0 disables; 2000-4000 for reasoning-heavy scans
```

Budget (§9):

```bash
BUDGET_QUICK_TOKENS=150000
BUDGET_QUICK_OUTPUT_TOKENS=40000
BUDGET_QUICK_USD=0.50
BUDGET_QUICK_DURATION=900
BUDGET_QUICK_ITERATIONS=60

BUDGET_SECURITY_TOKENS=500000
BUDGET_SECURITY_OUTPUT_TOKENS=120000
BUDGET_SECURITY_USD=2.00
BUDGET_SECURITY_DURATION=3600
BUDGET_SECURITY_ITERATIONS=300

BUDGET_PENTEST_TOKENS=1000000
BUDGET_PENTEST_USD=5.00
BUDGET_PENTEST_DURATION=7200

BUDGET_FULL_TOKENS=2000000
BUDGET_FULL_USD=10.00
BUDGET_FULL_DURATION=14400

BUDGET_HARD_ITERATION_CEILING=500         # absolute safety cap
```

Exploitation gate (§10):

```bash
EXPLOITATION_GATE_POLICY=strict           # strict | lenient | off
EXPLOITATION_GATE_PER_FINDING_SEC=30
EXPLOITATION_GATE_TOTAL_SEC=300
```

Critic (§11):

```bash
CRITIC_AUTO_ENABLED=true
CRITIC_MODEL=claude-haiku-4-5-20251001    # overrides AI_MODEL_LIGHT for critic only
```

Hypothesis executor (§12):

```bash
HYPOTHESIS_MAX_BRANCHES=6
HYPOTHESIS_BRANCH_CONCURRENCY=3
```

Feature flags:

```bash
USE_AUTONOMOUS_AGENT=false                # reserved for #173 — currently inactive
RUNTIME=local                             # local | aws
```

Infrastructure:

```bash
DATABASE_URL=postgresql+psycopg2://scanner:scanner@postgres:5432/scanner
REDIS_URL=redis://redis:6379
ELASTICSEARCH_URL=http://elasticsearch:9200
```

External integrations:

```bash
HIBP_API_KEY=...                           # enables breach_check
NOTIFICATION_CHANNELS='[{"type":"slack","webhook":"..."}]'
REPORT_BASE_URL=https://scanner.example.com
```

### 16.3 Triggering a scan via API

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_type": "security",
    "config": {
      "budget": { "max_usd_cost": 1.50 },
      "auth": null
    }
  }'
```

Response:
```json
{ "scan_id": "scan_20260416_abc123", "status": "queued" }
```

Stream progress:
```bash
curl -N http://localhost:8000/api/scans/scan_20260416_abc123/stream \
  -H "Authorization: Bearer $JWT"
```

See [`api-reference.md`](api-reference.md) for the complete endpoint
reference.

### 16.4 Debugging a stuck scan

**Symptom.** Scan status stays `running` but no new activity events
stream for > 10 minutes.

**Diagnosis steps.**

1. Check worker logs:
   ```bash
   docker compose logs -f worker | grep <scan_id>
   ```
2. Check heartbeat service for auto-recovery:
   ```bash
   docker compose logs -f heartbeat | grep stuck
   ```
   Stuck scans are auto-re-queued with checkpoint context after 15 min.

3. Manually force-retry via the brain chat agent:
   ```json
   { "tool": "force_retry_stuck_scan", "input": { "scan_id": "..." } }
   ```
   Or via the scan control tools:
   ```bash
   curl -X POST .../api/scans/<scan_id>/force-retry
   ```

4. Force-fail (give up):
   ```bash
   curl -X POST .../api/scans/<scan_id>/force-fail
   ```

5. Send a stop signal (agent breaks cleanly on next iteration):
   ```bash
   redis-cli SET "scan:stop:<scan_id>" 1
   ```

### 16.5 Where logs go

| Stream                          | Destination                                          |
|---------------------------------|------------------------------------------------------|
| Agent activity events           | Redis list `scan:activity:{scan_id}` + ES `scanner-scan-activities` |
| Agent LLM conversation          | Storage `scans/{id}/agent_log.json`                  |
| Agent chat messages             | Redis list `scan:chat:{scan_id}`                     |
| Findings                        | ES `scanner-scan-findings`                           |
| Token usage                     | ES `scanner-token-usage`                             |
| Worker stdout                   | Docker logs (`docker compose logs worker`)           |
| Heartbeat status                | ES `scanner-heartbeat`                               |

### 16.6 Testing the new primitives in isolation

Each primitive has a clean isolation point — you can exercise it from a
Python REPL inside the worker container:

```bash
docker compose exec worker python -c "
from modules.agent.payload_sweeper import sweep
r = sweep('https://httpbin.org/get', 'xss_reflected', parameter='q')
print(r['summary'])
"
```

```bash
docker compose exec worker python -c "
from modules.agent.critic_agent import challenge_finding
v = challenge_finding({'title': 'SQL injection in /search', 'severity': 'high', 'evidence': 'scanner said so'})
print(v)
"
```

```bash
docker compose exec worker python -c "
from modules.agent.budget import ScanBudget
b = ScanBudget.for_scan_type('quick')
print(b.summary())
"
```

### 16.7 Common failure modes

| Symptom                                          | Likely cause                                 | Fix                                             |
|--------------------------------------------------|----------------------------------------------|-------------------------------------------------|
| "Budget exhausted" hit immediately               | `BUDGET_*_USD` set to 0 in env               | Unset or raise the limit                        |
| Critic always returns `needs_more_evidence`      | `CRITIC_MODEL` points at a model with no API access | Check the model name and API key; unset to fall back to Haiku |
| Hypothesis fork produces 0 branches              | Attack surface is empty                      | Agent hasn't called `update_attack_surface` yet; check Phase 0/1 |
| Exploitation gate slow (minutes)                 | PoC attempts timing out on unreachable targets | Lower `EXPLOITATION_GATE_PER_FINDING_SEC`     |
| Memory recall returns nothing for a known target | `user_id` missing from scan_context          | Check the API route sets `config.user_id`      |
| sqlmap reports "stacked queries" and fails       | Agent used `--technique=S`                  | Master prompt forbids it; redirect agent via `ask_human` |

---

## 17. Extending the system

### 17.1 Add a new vulnerability class to the payload sweeper

1. Edit `modules/agent/payload_sweeper.py`:

   ```python
   PAYLOAD_CATALOG["ldap_injection"] = [
       {"payload": "*)(uid=*))(|(uid=*", "kind": "error"},
       {"payload": "admin*)((|userPassword=*)",  "kind": "error"},
       {"payload": "*)(&(|(uid=*))",             "kind": "error"},
   ]
   ```

2. If a new oracle kind is needed, add it to `_score_response`:

   ```python
   if kind == "ldap_error":
       for sig in ("ldap: error", "invalid dn syntax", ...):
           if sig in body_lower:
               return 0.8, f"ldap_error:{sig}"
       return 0.05, "no_ldap_error"
   ```

3. Add a mapping in `_safety_check` so the safety guard knows which
   `ExploitType` to validate against:

   ```python
   mapping = {
       ...,
       "ldap_injection": ExploitType.API_VULNERABILITY,
   }
   ```

4. Update the tool description in `modules/agent/tools.py` (the
   `sweep_payloads` tool lists valid `vulnerability_class` values).

5. Add the class to the exploitation gate's eligible set in
   `modules/agent/exploitation_gate.py:_GATE_ELIGIBLE_CLASSES` so the
   gate can attempt PoCs.

6. Update the master prompt's tool description
   (`modules/agent/prompts/master.txt:225`) so the agent knows the new
   class exists.

### 17.2 Add a new hypothesis branch

Edit `modules/agent/hypothesis_executor.py:fork_hypotheses`:

```python
if _has_file_uploads(surface) and scan_type in ("pentest", "full"):
    hypotheses.append({
        "id": "h_ssti",
        "title": "Server-side template injection in upload forms",
        "vulnerability_class": "ssti",
        "focus": "file_ops",
        "task_instructions": (
            "Test file-upload forms that render content back to the user "
            "(filename in success page, content preview, resized thumbnail). "
            "Upload files with names / content containing Jinja2, ERB, Twig, "
            "and Velocity template payloads. Look for template evaluation in "
            "the response."
        ),
    })
```

Add the focus key mapping in `_run_branch` if a new focus is introduced:

```python
focus_key_map = {
    ...,
    "file_ops": ["api_endpoints", "file_uploads"],
}
```

### 17.3 Add a new tool

Two steps.

**Step 1:** Register the tool in `modules/agent/tools.py`:

```python
{
    "name": "check_robots_txt",
    "description": "Fetch and parse /robots.txt for a target; returns disallowed paths.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
        },
        "required": ["target"],
    },
},
```

**Step 2:** Add a handler in `modules/agent/scan_agent.py:handle_tool`:

```python
elif name == "check_robots_txt":
    return _handle_check_robots_txt(input, scan_context)

# ... and further down ...
def _handle_check_robots_txt(input: dict, scan_context: dict | None) -> str:
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{input['target'].rstrip('/')}/robots.txt")
        if r.status_code != 200:
            return f"No robots.txt (status {r.status_code})"
        disallow = [line for line in r.text.splitlines() if line.strip().lower().startswith("disallow:")]
        return f"robots.txt fetched ({len(r.text)} chars). Disallowed paths:\n" + "\n".join(disallow)
    except Exception as e:
        return f"ERROR: {e}"
```

**Step 3 (optional):** Mention the tool in the master prompt so the
agent knows when to use it.

**Step 4 (optional):** If the tool is part of a sub-agent's toolbox,
add it to `_SUBAGENT_TOOL_ACCESS` in `scan_agent.py`.

### 17.4 Change post-processing order

The post-processing pipeline is a linear block in
`scan_agent.py:3500-3645`. Reorder cautiously — the dependency rule is:

- CVSS scoring must run before triage (triage reads CVSS).
- Verification must run before critic + gate (they see final severity).
- Critic should run before gate (gate doesn't know about critic, but
  ordering ensures the critic's verdict doesn't stale from
  severity demotion).
- Dedup must run last so it sees final fields.

---

## 18. Future improvements

### 18.1 Issue references

Every primitive in this round was tracked as a GitHub issue. Read the
issue for the original design rationale and discussion:

| PR    | Issue | Primitive                         | Status |
|-------|-------|-----------------------------------|--------|
| #176  | #167  | Exploitation gate                 | merged |
| #177  | #168  | Parallel hypothesis executor     | merged |
| #178  | #169  | Payload sweeper                  | merged |
| #179  | #170  | Red-team critic                  | merged |
| #180  | #171  | Model tiers + extended thinking  | merged |
| #181  | #172  | Budget-based stopping            | merged |
| #182  | #173  | Autonomous agent feature flag    | merged |
| #187  | #174  | Auto-recall memory                | merged |

### 18.2 Active future lines

**State-machine migration (#173).** `modules/agent/autonomous_agent.py`
is the skeleton of a state-machine replacement for the while-loop in
`scan_agent.py`. It explicitly declares itself inactive and defines
`USE_AUTONOMOUS_AGENT=false`. The migration will move
checkpointing, reflector, loop detection, and the 42-tool registry into
the state machine so the main loop becomes:

```
DISCOVERY → ENUMERATION → PLANNING → VULNERABILITY_SCANNING →
TESTING → EXPLOITATION → REPORTING
```

The current while-loop is more flexible but harder to reason about.
The state machine would make resume-after-crash cleaner (no
`[CONVERSATION SUMMARY]` synthesis needed) and enable per-phase budgets.
Migration is blocked pending a decision on whether to absorb or
replace.

**Payload catalog expansion.** The current 10 classes cover the OWASP
Top 10 web vulnerabilities. Planned additions: LDAP injection, XML
injection, SSTI, prototype pollution, CSS injection, mass assignment.

**Memory graph.** Today memory is flat rows scored by tech overlap. A
graph representation (target → tech stack → attack path → successful
payload) would enable transfer learning between superficially dissimilar
targets — e.g., a payload that worked against any Elixir/Phoenix app.

**Adaptive budget.** Instead of per-scan-type budgets, learn from past
scans: "this target took X tokens in 12 scans average; start with
X * 1.2."

**Critic strength tiers.** The critic currently runs on Haiku. For
high-severity findings, run a Sonnet-tier critic for more rigor;
charge the additional cost against the budget.

**Confidence-weighted dedup.** Two findings with the same dedup_key
but different confidences — merge, but surface the highest-confidence
evidence.

---

## Appendix A — File reference

| Area                              | File                                                     |
|-----------------------------------|----------------------------------------------------------|
| Main scan loop                    | `modules/agent/scan_agent.py` (4,075 lines)              |
| Tool registration                 | `modules/agent/tools.py` (1,441 lines)                   |
| Master prompt                     | `modules/agent/prompts/master.txt` (287 lines)           |
| Critic prompt                     | `modules/agent/prompts/critic.txt` (37 lines)            |
| Budget                            | `modules/agent/budget.py` (173 lines)                    |
| Memory                            | `modules/agent/memory.py` (296 lines)                    |
| Exploitation gate                 | `modules/agent/exploitation_gate.py` (206 lines)         |
| Red-team critic                   | `modules/agent/critic_agent.py` (166 lines)              |
| Payload sweeper                   | `modules/agent/payload_sweeper.py` (428 lines)           |
| Hypothesis executor               | `modules/agent/hypothesis_executor.py` (313 lines)       |
| Safety guard                      | `modules/agent/safety_guard.py` (136 lines)              |
| Central config                    | `modules/config.py`                                      |
| State-machine alternative         | `modules/agent/autonomous_agent.py` (inactive, 885 lines) |
| Finding verification              | `modules/agent/finding_verification.py`                  |
| Triage                            | `modules/agent/triage.py`                                |
| Deduplication                     | `modules/agent/finding_dedup.py`                         |
| Exploitation engine (PoC runner)  | `modules/agent/exploitation_engine.py`                   |
| Frontend scan details             | `frontend/src/pages/ScanDetailsPage.jsx`                 |

## Appendix B — Metrics exposed per scan

Every scan report's `scan_metadata` block contains:

```json
{
  "duration_seconds": 2704,
  "commands_executed": 47,
  "total_tool_calls": 89,
  "scan_id": "scan_20260416_abc",
  "target": "https://example.com",
  "scan_type": "security",
  "phase_timings": {
    "planning":      {"start": 0,    "end": 12,   "duration": 12},
    "scanning":      {"start": 12,   "end": 2350, "duration": 2338},
    "reporting":     {"start": 2350, "end": 2380, "duration": 30},
    "finding_verification": {"duration": 95},
    "attack_chain_analysis": {"duration": 34},
    "post_processing":      {"duration": 145}
  },
  "total_input_tokens":  420187,
  "total_output_tokens": 34512,
  "total_tokens":        454699,
  "estimated_cost_usd":  1.7823,
  "api_calls":           89,
  "by_caller": {
    "main":                { "input": 380000, "output": 28000, "calls": 45 },
    "subagent_pentester":  { "input": 30000,  "output": 5000,  "calls": 20 },
    "subagent_coder":      { "input": 8000,   "output": 1200,  "calls": 12 },
    "summarizer":          { "input": 2187,   "output": 312,   "calls": 1  }
  },
  "budget": {
    "input_tokens":     { "used": 420187, "limit": 500000, "fraction": 0.840 },
    "output_tokens":    { "used": 34512,  "limit": 120000, "fraction": 0.288 },
    "usd_cost":         { "used": 1.7823, "limit": 2.00,   "fraction": 0.891 },
    "duration_seconds": { "used": 2704.2, "limit": 3600,   "fraction": 0.751 },
    "iterations":       { "used": 89,     "limit": 300,    "fraction": 0.297 },
    "status":           "warn_80"
  }
}
```

Plus top-level:
```json
{
  "summary": "...",
  "risk_score": 72,
  "findings": [ ... ],
  "attack_chains": [ ... ],
  "attack_surface": { ... },
  "verification_summary": { "total": 12, "confirmed": 8, "demoted": 2, "unverified": 2 },
  "exploitation_gate": { "policy": "strict", "attempted": 4, "proven": 2, "demoted": 2, ... },
  "recommended_scan_interval": { "recommended_scan_interval": "7d", ... }
}
```

## Appendix C — Glossary

| Term                      | Meaning                                                                |
|---------------------------|------------------------------------------------------------------------|
| **Agent**                 | Claude LLM + tool registry + main loop; drives the scan autonomously  |
| **Attack surface**        | Structured map of what the target exposes (APIs, forms, auth, tech)   |
| **Budget**                | Multi-axis token/cost/duration/iteration cap per scan                 |
| **Chain**                 | Multi-step attack scenario combining 2+ findings                      |
| **Critic**                | Adversarial sub-agent that challenges findings                        |
| **Exploitation gate**     | Post-processing step that demands a PoC for high/critical             |
| **Finding**               | One security issue detected in the scan                               |
| **Hypothesis branch**     | One parallel sub-agent investigation focused on a single vuln class   |
| **Knowledge module**      | Specialized prompt text loaded on demand (auth, chatbot, graphql…)    |
| **Memory**                | Per-tenant cross-scan structured summary                              |
| **Oracle**                | Deterministic test that classifies a payload as hit/miss              |
| **Payload sweep**         | Run curated payload catalog for one vuln class against one endpoint  |
| **Reflector**             | Loop mechanism that nudges the agent back to tool use after text output |
| **Scan context**          | Dict threaded through every tool handler with scan-level state        |
| **Sub-agent**             | Specialized Claude loop (pentester/searcher/coder) invoked from main |
| **target_class**          | Deterministic tech-stack identifier for memory keying                |

---

*Last updated: 2026-04-16 — reflects PRs #176-#187 merged to main.*
