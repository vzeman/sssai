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
