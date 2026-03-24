# CLAUDE.md

## Project Overview

SSSAI is an AI-powered autonomous security scanning platform. A FastAPI backend dispatches scan jobs via Redis to worker containers where Claude AI agents plan strategies, run 69+ security tools, and produce structured reports. The frontend is a React (Vite) dashboard. Written in Python (backend) and JavaScript/JSX (frontend).

## Build & Run Commands

```bash
# Start all services (API, worker, scheduler, monitor, heartbeat, postgres, redis, elasticsearch)
docker compose up --build -d

# Rebuild a single service
docker compose up --build -d api

# View logs
docker compose logs -f worker

# Stop everything
docker compose down

# Frontend dev (from frontend/)
cd frontend && npm install && npm run dev

# Frontend lint
cd frontend && npm run lint

# Frontend build
cd frontend && npm run build
```

There is no top-level Python test suite or linter configured. Backend code runs exclusively inside Docker containers.

## Code Style Rules

- **Python naming**: `snake_case` for variables, functions, modules; `PascalCase` for classes (SQLAlchemy models, Pydantic schemas).
- **File naming**: `snake_case.py` for all Python modules; `PascalCase.jsx` or `kebab-case.jsx` for React components.
- **Imports**: Standard library first, then third-party, then `modules.*` local imports. No import sorting tool enforced.
- **Exports (frontend)**: Named exports preferred. React components use default export from entry files (`App.jsx`, `main.jsx`).
- **Type hints**: Use modern Python syntax (`str | None`, `list[str]`) — no `Optional`/`Union` from `typing`.
- **Error handling**: FastAPI routes raise `HTTPException`; workers use `try/except` with `logging`.
- **ORM style**: SQLAlchemy 2.0 `Mapped[]` / `mapped_column()` declarative pattern.

## Architecture Overview

```
modules/
├── agent/          # Claude AI scan agent, prompts, tools, checkpointing
├── api/            # FastAPI app, routes, models, schemas, auth, static HTML
│   ├── routes/     # Route modules: scans, auth, monitors, schedules, notifications, reports, search, tools
│   └── static/     # Server-rendered HTML dashboards (admin, analytics, uptime)
├── config.py       # Central AI model configuration
├── heartbeat/      # Platform health-check consumer
├── infra/          # Infrastructure adapters (local/AWS): queue, storage, secrets
├── monitor/        # Uptime monitoring service
├── notifications/  # Alert dispatcher (Slack, Discord, email, webhooks)
├── reports/        # Report generation with templates
├── sandbox/        # Sandboxed execution (NemoClaw, OpenClaw, OpenShell)
├── scheduler/      # Cron-based scheduled scan consumer
├── tools/          # Tool registry for scanning instruments
└── worker/         # Redis queue consumer — runs the AI agent
frontend/           # React + Vite SPA dashboard
docker/             # Dockerfiles: api, worker, scheduler, monitor, heartbeat
```

**Dependency rule**: `api/routes/` → `api/models`, `api/auth`, `infra/`; `worker/` → `agent/`, `tools/`, `infra/`; `infra/` has no internal dependencies. Never import from `worker/` or `agent/` inside `api/`.

## Critical Paths — Extra Care Required

- `modules/api/auth.py` — JWT authentication, password hashing, account lockout, TOTP
- `modules/api/models.py` — Database schema (User, Scan, Monitor, etc.)
- `modules/agent/scan_agent.py` — Core AI agent loop driving all scans
- `modules/infra/` — Infrastructure adapters (queue, storage, secrets)
- `modules/sandbox/` — Sandboxed code execution
- `docker-compose.yml` — Service orchestration and environment variables
- `.env` / `.env.example` — Secrets and configuration

Changes to these paths require additional test coverage, must be reviewed by a human, and should include evidence of manual verification. Reference risk tiers in `harness.config.json`.

## Security Constraints

- **Never** commit `.env`, API keys, or credentials. Only `.env.example` with placeholders.
- Never disable authentication middleware or weaken JWT validation.
- Validate all external input at API route boundaries (use Pydantic schemas).
- Use parameterized queries — never interpolate user input into SQL strings.
- Sandbox configuration (`modules/sandbox/`) must enforce least-privilege execution.
- Never expose internal service ports (Redis, Postgres, Elasticsearch) to the host beyond what `docker-compose.yml` already defines.

## Dependency Management

- **Python**: Dependencies are managed in Dockerfiles. To add a Python package, update the relevant `docker/Dockerfile.*` and rebuild.
- **Frontend**: `cd frontend && npm install <pkg>`. Always commit `package-lock.json`.
- Do not upgrade major versions without explicit instruction.

## Harness System Reference

- Risk tiers are defined in `harness.config.json`
- CI gates enforce risk-appropriate checks on every PR
- A review agent will automatically review PRs
- Pre-commit hooks enforce local quality checks
- **Chrome DevTools MCP**: `.mcp.json` at project root configures `@modelcontextprotocol/server-puppeteer` for browser-driven validation
- See `docs/architecture.md` and `docs/conventions.md` for detailed guidelines

## PR Conventions

- **Branch naming**: `<type>/<short-description>` (e.g., `feat/add-auth`, `fix/null-check`, `chore/update-deps`)
- **Commit messages**: Conventional Commits — `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`
- All PRs must pass CI checks before merge
- Classify every PR by risk tier (Tier 1/2/3) in the PR description

## Autonomous Development Mode (AutoDev)

When running in autonomous loop mode (`/loop 15m /implement`), follow this continuous development cycle. Inspired by Karpathy's autoresearch — but adapted for security software engineering.

### Philosophy

- Work independently. The human may be away — keep working until manually stopped.
- Prefer small, focused changes over large rewrites.
- Simplicity wins: if deleting code achieves the same result, that is a victory.
- Never break what already works. The build is your ground truth metric.
- Every loop iteration should leave the codebase better than it found it.

### The Loop (every iteration)

```
SURVEY → PLAN → IMPLEMENT → TEST → REVIEW → DECIDE → LOOP
```

### 1. Survey Phase (~30s)

Check for work in priority order:

1. `gh issue list --state open --sort priority` — open issues are highest priority
2. `gh pr list --state open` — check if any PRs need fixes from review comments
3. `grep -r "TODO\|FIXME\|HACK" modules/ frontend/src/ --include="*.py" --include="*.jsx" --include="*.js"` — code debt
4. Review recent `git log --oneline -20` for incomplete or broken work
5. If nothing above yields work, self-generate improvements (see below)

### 2. Plan Phase (~1m)

- Pick ONE task per iteration — do not bundle unrelated changes
- Read all relevant files before writing any code
- Create a branch from `main`: `<type>/<short-description>` (e.g., `fix/schedule-field-names`)
- For issues: reference the issue number in commits and PR

### 3. Implement Phase

- Make minimal, focused changes that address exactly one concern
- Follow all Code Style Rules from this file
- Respect the Dependency Rule — never cross architectural boundaries
- One logical change per commit with a Conventional Commit message

### 4. Test Phase (~1m)

Quality gates that MUST pass before any commit:

```bash
# Frontend must compile
cd frontend && npm run build

# Backend Docker images must build
docker compose build api worker

# If Python tests exist in tests/
python -m pytest tests/ -x --tb=short 2>/dev/null || true
```

If any gate fails: fix it (max 2 attempts), then discard the branch and log the failure.

### 5. Review Phase (~30s)

Self-review the diff before committing:

- No secrets, credentials, or .env values in the diff
- No new security vulnerabilities (SQL injection, XSS, command injection)
- Changes match the project's code style
- No unnecessary complexity added
- No unrelated changes smuggled in

### 6. Decide Phase

- **Tests pass** → commit, push, create PR with issue reference, assign for review
- **Tests fail after 2 fix attempts** → `git checkout main`, log failure, move to next task
- **Never** force-push, amend published commits, or merge directly to main

### Self-Generated Improvements

When no issues or TODOs remain, generate work in this priority order:

1. **Security hardening** — input validation gaps, missing auth checks, OWASP compliance
2. **Error handling** — API routes without proper error responses, unhandled edge cases
3. **Frontend UX** — missing loading states, error messages, empty states, broken layouts
4. **Test coverage** — unit tests for critical paths (agent, auth, models, infra)
5. **Performance** — slow queries, unnecessary re-renders, missing indexes
6. **Observability** — logging gaps, missing metrics, health check improvements
7. **Documentation** — API docs, inline comments for complex logic only
8. **Dependency updates** — patch versions only, never major bumps

For each self-generated improvement: create a GitHub issue first, then implement it. This keeps the work tracked and reviewable.

### Results Tracking

After each loop iteration, append to `docs/autodev-log.md`:

```
| Date | Branch | Issue/Task | Status | Description |
|------|--------|------------|--------|-------------|
```

### Safeguards

- **Critical paths** (`auth.py`, `models.py`, `scan_agent.py`, `docker-compose.yml`, `.env`) — create the PR but flag it `needs-human-review`. Do not self-merge.
- **Max 1 PR per iteration** — quality over quantity.
- **Stuck detection** — if the same task fails 3 iterations in a row, skip it, label the issue `blocked`, and move on.
- **No destructive operations** — never `git reset --hard`, `rm -rf`, `DROP TABLE`, or `docker system prune` autonomously.
- **Rate limiting** — respect GitHub API limits. If rate-limited, wait until next iteration.
