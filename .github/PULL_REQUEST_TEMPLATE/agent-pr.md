## Agent-Generated PR

**Agent**: <!-- agent name and version (e.g., Claude Code v1.0, remediation-bot) -->
**Trigger**: <!-- what triggered this PR: review remediation, feature request, scheduled task -->
**Head SHA**: `<!-- exact commit SHA this PR was generated at -->`

## Summary
<!-- Auto-generated summary describing all changes. -->

## Risk Assessment

- **Detected Risk Tier**: <!-- auto-populated by risk-policy-gate -->
- **Critical paths touched**:
  <!-- List any files matching critical paths from CLAUDE.md / harness.config.json:
       modules/api/auth.py, modules/api/models.py, modules/agent/scan_agent.py,
       modules/infra/**, modules/sandbox/**, docker-compose.yml,
       .github/**, Dockerfile*, harness.config.json, scripts/structural-tests.sh -->
  -
- **Confidence level**: <!-- high / medium / low -->

## Changes Made
<!-- Complete list of every file modified. -->

| File | Change Type | Description |
|------|-------------|-------------|
| | added / modified / deleted | |

## Validation Results

| Check | Status | Details |
|-------|--------|---------|
| Lint | <!-- PASS / FAIL / N/A --> | not configured |
| Tests | <!-- PASS / FAIL / N/A --> | not configured |
| Build | <!-- PASS / FAIL / N/A --> | not configured |
| Structural tests | <!-- PASS / FAIL --> | `bash scripts/structural-tests.sh` |
| Harness smoke | <!-- PASS / FAIL --> | harness-smoke workflow |

## Dependency Rule Compliance
<!-- Automated boundary check results (see docs/layers.md, CLAUDE.md). -->
- [ ] `api/routes/` → `api/models`, `api/auth`, `infra/` only
- [ ] `worker/` → `agent/`, `tools/`, `infra/` only
- [ ] `infra/` has no internal dependencies
- [ ] No imports from `worker/` or `agent/` inside `api/`
- [ ] No circular imports

## Security Verification
- [ ] No `.env`, API keys, or credentials in diff
- [ ] Auth middleware unchanged or strengthened
- [ ] External input validated via Pydantic schemas
- [ ] Parameterized queries only — no SQL interpolation
- [ ] Sandbox least-privilege preserved

## Review Agent Status
- [ ] Review agent has analyzed this PR
- [ ] No unresolved blocking findings
- [ ] Review SHA matches current HEAD (`<!-- SHA -->`)
- **Verdict**: <!-- APPROVE / REQUEST_CHANGES / PENDING -->

## Human Review Required
<!-- Tier 3 changes require manual approval. See harness.config.json mergePolicy. -->
- [ ] Required — Tier 3 (high-risk) changes detected
- [ ] Optional but recommended — Tier 2 changes

## Remediation History
<!-- Only if this PR was created or updated by the remediation agent. Remove this section otherwise. -->
- **Original PR**: #<!-- number -->
- **Remediation attempt**: <!-- 1 / 2 / 3 -->
- **Findings fixed**: <!-- count -->
- **Findings skipped**: <!-- count, with brief reasons -->
- **Validation after fix**: <!-- all passed / partial — specify which failed -->
