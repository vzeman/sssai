# Documentation Gardening Task

Scan this repository for stale, outdated, or inaccurate documentation and fix it. Be conservative — only fix issues you are confident about. Leave a `<!-- TODO: ... -->` comment for anything ambiguous.

## Documentation Files to Scan

- `README.md` — project overview, quick start, architecture summary, scan types, documentation links
- `CLAUDE.md` — agent instructions: build commands, code style, architecture, critical paths, security constraints, PR conventions
- `COMMERCIAL.md` — licensing information
- `docs/architecture.md` — project structure, AI agent loop, sub-agents, infrastructure design
- `docs/conventions.md` — coding conventions, naming rules, import order, error handling
- `docs/layers.md` — layer boundary definitions, dependency rules
- `docs/installation.md` — prerequisites, setup, Docker configuration
- `docs/getting-started.md` — first account, first scan, understanding reports
- `docs/security-checks.md` — scan types and methodologies
- `docs/api-reference.md` — REST API documentation
- `docs/scanning-tools.md` — all scanning tools with descriptions
- `docs/deployment.md` — local and AWS deployment
- `docs/configuration.md` — environment variables, AI models, notifications

## Scanning Checklist

### 1. Broken File References

- Search all markdown files for backtick-quoted paths (e.g., \``modules/agent/scan_agent.py`\`), markdown links, and inline references to source files.
- Verify each referenced file still exists at that path by reading the filesystem.
- If a file was moved, update the reference to the new location.
- If a file was deleted with no replacement, remove the reference and note the deletion.
- Pay special attention to references in `docs/architecture.md` and `CLAUDE.md` — they list specific filenames and directory structures.

### 2. Command Accuracy

Read `docker-compose.yml` and `frontend/package.json` and compare against documented commands in `CLAUDE.md` and `README.md`:

| Expected Command | Source |
|---|---|
| `docker compose up --build -d` | `CLAUDE.md`, `README.md` |
| `docker compose down` | `CLAUDE.md` |
| `docker compose logs -f worker` | `CLAUDE.md` |
| `cd frontend && npm install && npm run dev` | `CLAUDE.md` |
| `cd frontend && npm run lint` | `CLAUDE.md` |
| `cd frontend && npm run build` | `CLAUDE.md` |

If any command in the docs no longer matches the actual configuration, update it. Flag commands documented in markdown that no longer work.

### 3. Architecture Drift

Compare `CLAUDE.md` and `docs/architecture.md` against the actual directory structure under `modules/`:

- **Expected top-level modules** (per `CLAUDE.md`): `agent/`, `api/`, `config.py`, `heartbeat/`, `infra/`, `monitor/`, `notifications/`, `reports/`, `sandbox/`, `scheduler/`, `tools/`, `worker/`
- **Expected api route modules**: `scans`, `auth`, `monitors`, `schedules`, `notifications`, `reports`, `search`, `tools`
- **Expected other directories**: `frontend/`, `docker/`, `docs/`, `scripts/`, `templates/`, `tools/`, `config/`

If modules have been added, renamed, or removed since the docs were last written, update the architecture docs accordingly. Check for directories like `modules/external/` or `modules/internal/` that may exist but not be documented.

### 4. CLAUDE.md Accuracy

Verify each section of `CLAUDE.md` against the actual project state:

1. **Build & Run Commands** — must match actual Docker Compose service names and frontend npm scripts.
2. **Code Style Rules** — verify Python naming conventions and React component file naming match the actual codebase.
3. **Architecture Overview** — the directory tree must match actual `modules/` contents and subdirectories.
4. **Dependency rule** — the import boundary rules (e.g., "Never import from `worker/` or `agent/` inside `api/`") should be verified against actual imports.
5. **Critical Paths** — the listed files must still exist at the documented paths (`modules/api/auth.py`, `modules/agent/scan_agent.py`, `modules/infra/`, `modules/sandbox/`, etc.).
6. **Security Constraints** — verify claims are still accurate (e.g., `.env.example` exists, sandbox module exists).

### 5. Harness Config Consistency

Read `harness.config.json` and verify:

- `docsDrift.trackedDocs` lists documentation patterns that match actual files.
- `riskTiers` patterns reference directories that exist.
- `architecturalBoundaries` (if populated) match the actual `modules/` subdirectories.
- `commands` section accurately reflects the project's actual capabilities (currently no top-level test/lint/build).

If `harness.config.json` has drifted from reality, note the discrepancy as a `<!-- TODO: ... -->` comment in `CLAUDE.md` — do not modify `harness.config.json` directly.

### 6. Broken Internal Links

Check all markdown links in both `[text](url)` and `[text][ref]` styles:

- For relative links (e.g., `[Architecture](docs/architecture.md)`), verify the target file exists.
- For heading anchors (e.g., `#architecture-overview`), verify the heading exists in the target file.
- For external links, leave them as-is — do not attempt to verify or fix.

### 7. Stale Code Examples

Find code examples in documentation that reference imports, functions, classes, or API endpoints:

- Verify referenced Python modules, classes, and functions still exist (e.g., SQLAlchemy models in `modules/api/models.py`, Pydantic schemas).
- Verify referenced API routes match actual route definitions in `modules/api/routes/`.
- Check that documented tool names match entries in `modules/tools/`.
- Update examples if the API has changed; leave a `<!-- TODO: ... -->` if the replacement is unclear.

### 8. Workflow and Script References

Verify that references to CI workflows and scripts in documentation match actual files:

- **Expected workflows** in `.github/workflows/`: `ci.yml`, `code-review-agent.yml`, `remediation-agent.yml`, `review-agent-rerun.yml`, `risk-policy-gate.yml`, `structural-tests.yml`, `harness-smoke.yml`, `auto-resolve-threads.yml`, `doc-gardening.yml`
- **Expected scripts** in `scripts/`: `risk-policy-gate.sh`, `structural-tests.sh`, `remediation-agent-prompt.md`, `risk-policy-gate.ts`, `remediation-guard.ts`, `review-agent-utils.ts`, `doc-gardening-prompt.md`

### 9. Docker Service Consistency

Verify that documented Docker services match `docker-compose.yml`:

- Check that all service names mentioned in docs (api, worker, scheduler, monitor, heartbeat, postgres, redis, elasticsearch) still exist.
- Verify documented ports, environment variables, and volume mounts are accurate.
- Check that Dockerfile paths referenced in docs match actual files in `docker/`.

### 10. Scan Types and Tools Consistency

Verify scan type documentation against actual implementation:

- Check that scan types listed in `README.md` and `docs/security-checks.md` match what the agent and API actually support.
- Verify tool counts (currently documented as "69+") are still approximately correct.
- Check that tool names in `docs/scanning-tools.md` match the tool registry in `modules/tools/`.

## Rules

- Only modify documentation files (`*.md`, `*.mdx`, `*.rst`).
- **NEVER** modify source code (`.py`, `.js`, `.jsx`, `.ts`), configuration files (`.json`, `.yml`, `.yaml`, `.env`), or CI workflows.
- When removing a stale reference, check if there is a replacement to link to.
- Preserve each document's structure, tone, heading hierarchy, and formatting.
- If unsure about a change, leave a `<!-- TODO: verify — [description] -->` comment rather than guessing.
- Add `<!-- Last gardened: YYYY-MM-DD -->` to sections you have verified or updated.
- Do not rewrite paragraphs for style — only fix factual inaccuracies and broken references.
- Do not add new sections or documentation — only maintain what already exists.

## Output

After making changes, provide a plain-text summary listing:

1. **Files modified** and what was changed in each.
2. **Issues found and fixed** (one line per issue).
3. **Issues requiring human decision** (left as `<!-- TODO -->` comments).
4. **Sections verified as up-to-date** (no changes needed).
