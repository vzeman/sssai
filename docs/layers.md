# Layer Boundaries

SSSAI does not enforce formal architectural layers, but the `modules/` directory has a clear implicit structure. This document identifies those boundaries, defines dependency rules, and provides guidance for maintaining separation as the project grows.

## Observed Boundaries

The codebase organizes into four implicit layers based on what each package depends on and who calls it:

```
┌──────────────────────────────────────────────────────────┐
│  SERVICES (entry points — one per Docker container)      │
│  worker/consumer.py, scheduler/cron.py,                  │
│  monitor/uptime.py, heartbeat/service.py,                │
│  api/main.py                                             │
├──────────────────────────────────────────────────────────┤
│  DOMAIN (core business logic)                            │
│  agent/scan_agent.py, agent/tools.py, agent/prompts/,    │
│  agent/checkpoint.py, notifications/dispatcher.py,       │
│  reports/generator.py, tools/registry.py                 │
├──────────────────────────────────────────────────────────┤
│  DATA (persistence and schemas)                          │
│  api/models.py, api/schemas.py, api/database.py,         │
│  api/auth.py, api/routes/*                               │
├──────────────────────────────────────────────────────────┤
│  INFRASTRUCTURE (external system adapters)               │
│  infra/local_queue.py, infra/aws_queue.py,               │
│  infra/local_storage.py, infra/aws_storage.py,           │
│  infra/elasticsearch.py, infra/*_secrets.py,             │
│  sandbox/ (deprecated)                                   │
└──────────────────────────────────────────────────────────┘
```

## Dependency Direction

Dependencies must flow **downward only**. A package in a higher layer may import from the same layer or any layer below it. Lower layers must never import from higher layers.

| Layer | May depend on | Must not depend on |
|---|---|---|
| **Services** | Domain, Data, Infrastructure, config.py | — |
| **Domain** | Infrastructure, config.py | Services, API routes |
| **Data** | Infrastructure (database engine only), config.py | Services, Domain |
| **Infrastructure** | Standard library, third-party packages | Services, Domain, Data |

### Current Violations

These are existing cross-layer dependencies that should be addressed over time:

1. **`heartbeat/service.py`** imports `modules.agent.checkpoint` (Service → Domain) — acceptable, used for stuck-scan recovery.
2. **`worker/__init__.py`** imports `modules.api.models` indirectly via checkpoint recovery — the worker reaches into the API data layer for scan status updates. Ideally, a shared `models` package would sit in the Data layer independent of the API.
3. **`monitor/uptime.py`** imports directly from `modules.api.database` and `modules.api.models` — the monitor service is tightly coupled to the API's database setup. Extracting database/models to a shared location would fix this.

## Package Responsibilities

### Services Layer

Each service has a single entry point and a main loop. Services are deployed as separate Docker containers.

| Service | Entry Point | Responsibility |
|---|---|---|
| API | `api/main.py` | HTTP endpoints, authentication, dashboard |
| Worker | `worker/consumer.py` | Scan job processing via AI agent |
| Scheduler | `scheduler/cron.py` | Timed scan triggering |
| Monitor | `monitor/uptime.py` | Target availability checking |
| Heartbeat | `heartbeat/service.py` | Platform health monitoring |

### Domain Layer

Contains the core logic that makes SSSAI valuable — the AI agent, tool definitions, report generation, and notification dispatch. This code should be testable without Docker or external services.

### Data Layer

SQLAlchemy models, Pydantic schemas, authentication logic, and API route handlers. Currently co-located under `modules/api/` because FastAPI is the only consumer. If other services need direct model access, `models.py`, `database.py`, and `schemas.py` should be extracted to a shared `modules/data/` package.

### Infrastructure Layer

Adapters for external systems. The factory pattern in `modules/infra/__init__.py` ensures the rest of the codebase depends on abstract interfaces, not concrete implementations:

```python
# Consumer code doesn't know or care about Redis vs SQS
queue = get_queue()
queue.send("scan-jobs", {"scan_id": "...", "target": "..."})
```

## Proposed Improvements

### 1. Extract Shared Data Package

Move `models.py`, `database.py`, and `schemas.py` from `modules/api/` to `modules/data/`. This eliminates the need for the worker, scheduler, monitor, and heartbeat to import from `modules.api.*`.

### 2. Define Service Interfaces

Each infrastructure adapter already follows an implicit interface (e.g., `send()`, `receive()` for queues). Formalize these as Protocol classes:

```python
class Queue(Protocol):
    def send(self, queue_name: str, message: dict) -> None: ...
    def receive(self, queue_name: str, timeout: int = 30) -> dict | None: ...
```

### 3. Decouple Heartbeat from Agent Internals

The heartbeat service imports `modules.agent.checkpoint` for stuck-scan recovery. This could be mediated through a shared interface or Redis-based protocol instead of direct import.

## Adding New Features

When adding new functionality, determine which layer it belongs to:

- **New scan type**: Add a prompt file to `agent/prompts/`, optionally add a knowledge module. Domain layer.
- **New API endpoint**: Add a route module to `api/routes/`. Data layer.
- **New notification channel**: Add a `_send_*` method to `notifications/dispatcher.py`. Domain layer.
- **New infrastructure provider**: Add implementation files to `infra/`, update factory functions. Infrastructure layer.
- **New background service**: Create a new package under `modules/` with `__init__.py` and a `main()` entry point. Add a Dockerfile. Services layer.
