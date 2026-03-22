## Summary
<!-- Brief description of what this PR does and why. Link to the issue if applicable. -->

## Risk Tier
<!-- The risk-policy-gate auto-detects the tier, but classify here for reviewer context. -->
<!-- See harness.config.json for full pattern definitions. -->
- [ ] **Tier 1 (Low)**: Docs, comments, `*.md`, `CHANGELOG*`, `LICENSE*`, `.editorconfig`, `.gitignore`
- [ ] **Tier 2 (Medium)**: Source code (`src/`, `lib/`, `tests/`, `scripts/`), config files (`*.json`, `*.yaml`, `*.yml`)
- [ ] **Tier 3 (High)**: CI/CD (`.github/**`), Docker (`Dockerfile*`, `docker-compose*`), harness infra (`harness.config.json`, `scripts/structural-tests.sh`)

### Critical Paths
<!-- Check if any of these were modified — these require extra care and evidence. -->
- [ ] `modules/api/auth.py` — JWT auth, password hashing, TOTP
- [ ] `modules/api/models.py` — Database schema
- [ ] `modules/agent/scan_agent.py` — Core AI agent loop
- [ ] `modules/infra/` — Infrastructure adapters (queue, storage, secrets)
- [ ] `modules/sandbox/` — Sandboxed code execution
- [ ] `docker-compose.yml` — Service orchestration
- [ ] `.env` / `.env.example` — Secrets and configuration

## Changes
<!-- Group modified files by logical concern. -->

### Added
-

### Changed
-

### Removed
-

## Testing
<!-- How were these changes validated? -->
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed (describe below)
- [ ] Docker services verified: `docker compose up --build -d`

## Evidence
<!-- Tier 1: lint-clean. Tier 2: tests-pass + lint-clean. Tier 3: all of Tier 2 + manual-review. -->

| Check | Result |
|-------|--------|
| Lint | <!-- PASS / FAIL / N/A (not configured) --> |
| Tests | <!-- PASS / FAIL / N/A (not configured) --> |
| Build | <!-- PASS / FAIL / N/A (not configured) --> |
| Structural tests | <!-- PASS / FAIL (Tier 3 only) --> |
| Harness smoke | <!-- PASS / FAIL (Tier 3 only) --> |

## Dependency Rule Compliance
<!-- Confirm architectural boundaries are respected (see docs/layers.md, CLAUDE.md). -->
- [ ] `api/routes/` only imports from `api/models`, `api/auth`, `infra/`
- [ ] `worker/` only imports from `agent/`, `tools/`, `infra/`
- [ ] `infra/` has no internal module dependencies
- [ ] No imports from `worker/` or `agent/` inside `api/`
- [ ] No circular imports introduced

## Security Checklist
- [ ] No `.env`, API keys, or credentials committed (only `.env.example` with placeholders)
- [ ] Authentication middleware not weakened
- [ ] All external input validated via Pydantic schemas
- [ ] No raw SQL interpolation — parameterized queries only
- [ ] Sandbox config enforces least-privilege execution
- [ ] No internal service ports exposed beyond `docker-compose.yml` defaults

## Review Checklist
- [ ] Python: `snake_case` variables/functions, `PascalCase` classes
- [ ] Python: Modern type hints (`str | None`, not `Optional`)
- [ ] Python: SQLAlchemy 2.0 `Mapped[]` / `mapped_column()` pattern
- [ ] Frontend: Named exports preferred, `PascalCase.jsx` or `kebab-case.jsx`
- [ ] Code follows project conventions (`docs/conventions.md`, `CLAUDE.md`)
- [ ] Documentation updated if public API changed
- [ ] Risk tier accurately reflects scope of changes
