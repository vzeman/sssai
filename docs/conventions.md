# Coding Conventions

This document is the authoritative reference for coding standards in the SSSAI security scanner. Both human developers and AI coding agents must follow these rules.

## Naming Conventions

### Files

- Python source files use **snake_case**: `scan_agent.py`, `local_queue.py`, `dispatcher.py`
- Prompt files use **snake_case** with `.txt` extension: `api_security.txt`, `pentest.txt`
- Frontend source files use **PascalCase** for components (`App.jsx`) and **kebab-case** for styles (`index.css`)
- Docker files use **PascalCase** prefix with dot-separated service name: `Dockerfile.api`, `Dockerfile.worker`

### Variables and Functions

**snake_case** for all Python variables and functions:

```python
def _update_scan_status(scan_id: str, status: str): ...
def get_cost_per_1m(model: str | None = None): ...
```

Private functions and module-level variables are prefixed with a single underscore: `_REDIS_URL`, `_check_redis()`, `_do_reply()`.

### Classes

**PascalCase** for all classes. No prefixes:

```python
class RedisQueue: ...
class TokenTracker: ...
class NotificationDispatcher: ...
class HeartbeatService: ...
```

### Constants

**UPPER_SNAKE_CASE** for module-level constants:

```python
MAX_OUTPUT_LEN = 50_000
MAX_ITERATIONS = 100
SUMMARIZE_THRESHOLD = 80_000
HEARTBEAT_INTERVAL = 120
```

### Pydantic Models

**PascalCase** with descriptive suffixes — `Create`, `Update`, `Response`:

```python
class ScanCreate(BaseModel): ...
class ScanResponse(BaseModel): ...
class MonitorUpdate(BaseModel): ...
```

## Import Organization

Imports follow this order, separated by blank lines:

1. **Standard library**: `import os`, `import json`, `import logging`
2. **Third-party packages**: `import anthropic`, `from fastapi import ...`, `from sqlalchemy import ...`
3. **Internal modules**: `from modules.config import AI_MODEL`, `from modules.infra import get_queue`

```python
import json
import logging
import os

import anthropic
import httpx
from sqlalchemy import create_engine, text

from modules.agent.tools import TOOLS, SUBAGENT_TOOLS
from modules.config import AI_MODEL, AI_MODEL_LIGHT
from modules.infra import get_storage, get_queue
```

Late/deferred imports are used to avoid circular dependencies or defer heavy imports:

```python
def _recover_orphaned_scans():
    from modules.agent.checkpoint import load_checkpoint, build_resume_context
```

## Module Organization

- Each service (`api`, `worker`, `scheduler`, `monitor`, `heartbeat`) has its own package under `modules/`.
- Each package has an `__init__.py`. Service packages expose a `main()` entry point.
- The `infra/` package uses factory functions (`get_queue()`, `get_storage()`, `get_secrets()`) to abstract local vs AWS implementations.
- Shared configuration lives in `modules/config.py`.

## Error Handling

### Fatal Errors

- **Scan failures**: Caught at the worker consumer level. Scan status set to `failed`, error saved to `scans/{scan_id}/error.json`.
- **Service crashes**: Each service registers SIGTERM/SIGINT handlers for graceful shutdown.

### Non-Fatal Errors

- **Elasticsearch writes**: Wrapped in bare `try/except Exception: pass`. ES is not on the critical path.
- **Notification dispatch**: Each channel is tried independently; one failure doesn't block others.
- **AI summary generation**: Falls back to a plain-text summary if Claude call fails.

Pattern used throughout the codebase:

```python
try:
    from modules.infra.elasticsearch import index_doc
    index_doc("scanner-worker-logs", {...})
except Exception:
    pass  # ES may not be ready; non-critical
```

### Logging

Standard `logging` module. Format: `%(asctime)s [%(levelname)s] %(message)s`. The worker also pushes logs to Redis (`worker:logs` key) for dashboard display and dual-writes to Elasticsearch.

```python
log = logging.getLogger(__name__)
log.info("Starting scan %s: %s (%s)", scan_id, target, scan_type)
log.warning("Could not update scan status: %s", e)
log.exception("Scan %s failed: %s", scan_id, e)
```

## Type Annotations

Python 3.10+ union syntax is used throughout:

```python
def receive(self, queue_name: str, timeout: int = 30) -> dict | None: ...
risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
```

SQLAlchemy `Mapped[]` type annotations are used for all ORM model columns.

## Database Conventions

- **ORM models** live in `modules/api/models.py`. All use SQLAlchemy 2.0 `Mapped` style.
- **Primary keys** are UUID strings generated with `uuid.uuid4()`.
- **Timestamps** use `server_default=func.now()` for `created_at`.
- **Migrations** are inline ALTER TABLE statements in `modules/api/main.py` (no Alembic).
- **Session management**: FastAPI dependency injection via `get_db()` generator. Worker uses direct engine connections.

## Configuration

- All configuration via environment variables. Defaults in code, documented in `.env.example`.
- AI model selection centralized in `modules/config.py` (`AI_MODEL`, `AI_MODEL_LIGHT`).
- Infrastructure switching via `RUNTIME` env var (`local` or `aws`).

## Git Workflow

### Branch Naming

`<type>/<short-description>` where type is one of:

```
feat/    fix/    chore/    docs/    refactor/    test/
```

### Commit Messages

[Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add OWASP scan type with dedicated prompt
fix: handle checkpoint recovery for orphaned scans
chore: update Anthropic SDK to latest
docs: add architecture documentation
refactor: extract notification dispatcher to separate module
```

### PR Size

Keep PRs focused on a single concern. Prefer multiple small PRs over one large PR. Every PR must be classified by risk tier in the description.

## Code Review Standards

### Risk Tiers

| Tier | Scope | Required Checks |
|---|---|---|
| **Tier 1** (low) | Docs, prompts, config, comments | Lint pass |
| **Tier 2** (medium) | API routes, agent tools, new features | Lint, type-check, test, review |
| **Tier 3** (high) | Auth (`auth.py`), agent core (`scan_agent.py`), infra abstraction, Docker, worker consumer | Lint, type-check, test, review, manual sign-off |

### What Reviewers Should Focus On

- **Security**: No secrets in code, no SQL injection via raw strings, proper auth checks on all endpoints
- **Fail-soft pattern**: ES/notification failures must not crash the critical path
- **Agent safety**: Changes to tool definitions or agent prompts must be tested with real scans
- **Infrastructure parity**: Changes to `local_*` implementations must have corresponding `aws_*` changes
