# CI/CD Integration Examples

## GitHub Actions

Copy `github-actions-scan.yml` to `.github/workflows/security-scan.yml` in your project.

### Setup
1. Go to **Settings > Webhooks** in the scanner dashboard and create a webhook
2. Copy the API key
3. Add repository secrets:
   - `SCANNER_API_KEY`: The webhook API key
   - `SCANNER_URL`: Your scanner URL (e.g., `https://scanner.example.com`)

### Quality Gates
Configure thresholds in the workflow file:
- `max_critical: 0` — Fail if any critical findings
- `max_high: 5` — Fail if more than 5 high-severity findings
- `max_risk_score: 70` — Fail if risk score exceeds 70

## GitLab CI

Include `gitlab-ci-scan.yml` in your `.gitlab-ci.yml`.

### Setup
1. Create a webhook in the scanner dashboard
2. Add CI/CD variables:
   - `SCANNER_API_KEY`: The webhook API key
   - `SCANNER_URL`: Your scanner URL

## API Reference

### Trigger Scan
```
POST /api/webhooks/scan
Header: X-API-Key: <your-key>
```

### Poll Results
```
GET /api/webhooks/scan/{scan_id}/result
Header: X-API-Key: <your-key>
```

Response includes `gate_passed` (boolean) and `gate_details` with per-check results.
