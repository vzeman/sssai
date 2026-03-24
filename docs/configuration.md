# Configuration

All configuration is done through environment variables in the `.env` file. Copy `.env.example` to `.env` and customize as needed.

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key. [Get one here](https://console.anthropic.com/). |

### AI Models

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_MODEL` | `claude-haiku-4-5-20251001` | Primary model for scans, chat, and sub-agents |
| `AI_MODEL_LIGHT` | `claude-haiku-4-5-20251001` | Lightweight model for heartbeat, execution monitor, chain summarization, reflector |

**Available models:**

| Model | ID | Input $/1M tokens | Output $/1M tokens | Best For |
|-------|----|-------------------|--------------------| ---------|
| Haiku 4.5 | `claude-haiku-4-5-20251001` | $0.80 | $4.00 | Cost-efficient scanning, high volume |
| Sonnet 4 | `claude-sonnet-4-20250514` | $3.00 | $15.00 | Balanced quality and cost |
| Opus 4 | `claude-opus-4-20250514` | $15.00 | $75.00 | Maximum accuracy, complex targets |

**Recommended configurations:**

```bash
# Cheapest — Haiku for everything (default)
AI_MODEL=claude-haiku-4-5-20251001
AI_MODEL_LIGHT=claude-haiku-4-5-20251001

# Balanced — Sonnet for scans, Haiku for utilities
AI_MODEL=claude-sonnet-4-20250514
AI_MODEL_LIGHT=claude-haiku-4-5-20251001

# Maximum quality — Opus for scans, Sonnet for utilities
AI_MODEL=claude-opus-4-20250514
AI_MODEL_LIGHT=claude-sonnet-4-20250514
```

Token costs are calculated automatically based on the selected model and displayed in scan reports.

### Infrastructure

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNTIME` | `local` | `local` or `aws` — switches backend implementations |
| `DATABASE_URL` | `postgresql://scanner:scanner@postgres:5432/scanner` | PostgreSQL connection URL |
| `REDIS_URL` | `redis://redis:6379` | Redis connection URL |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | Elasticsearch URL |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `dev-secret-change-in-production` | **Change this in production.** Secret key for signing JWT tokens. |

### Platform Services

| Variable | Default | Description |
|----------|---------|-------------|
| `HEARTBEAT_INTERVAL` | `120` | Seconds between platform health checks |

### Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `NOTIFICATION_CHANNELS` | `[]` | JSON array of notification channel configs (see below) |

### AWS-Only Variables

These are only needed when `RUNTIME=aws`:

| Variable | Description |
|----------|-------------|
| `S3_BUCKET` | S3 bucket name for report storage |
| `SQS_SCAN_QUEUE_URL` | SQS queue URL for scan jobs |

### Optional Integrations

| Variable | Default | Description |
|----------|---------|-------------|
| *(none currently)* | | |

---

## Notification Configuration

You can configure notifications via the `NOTIFICATION_CHANNELS` environment variable or through the API at runtime. API-configured channels are stored per-user in the database.

### Slack

```json
{
  "type": "slack",
  "config": {
    "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
  },
  "min_severity": "warning"
}
```

**Setup:** Create a Slack app → Incoming Webhooks → Add New Webhook → Copy URL.

### Discord

```json
{
  "type": "discord",
  "config": {
    "webhook_url": "https://discord.com/api/webhooks/000000000000000000/XXXXXXXX"
  },
  "min_severity": "critical"
}
```

**Setup:** Server Settings → Integrations → Webhooks → New Webhook → Copy URL.

### Email

```json
{
  "type": "email",
  "config": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "to_email": "alerts@example.com"
  },
  "min_severity": "info"
}
```

**For Gmail:** Use an [App Password](https://support.google.com/accounts/answer/185833), not your regular password.

### Webhook

```json
{
  "type": "webhook",
  "config": {
    "url": "https://your-service.com/hooks/scan"
  },
  "min_severity": "info"
}
```

Sends a POST request with the scan report JSON to your endpoint.

### Severity Routing

| min_severity | Triggers When |
|--------------|---------------|
| `critical` | risk_score >= 80 |
| `warning` | risk_score >= 50 |
| `info` | Every completed scan |

### Environment Variable Example

To configure multiple channels via `.env`:

```bash
NOTIFICATION_CHANNELS=[{"type":"slack","config":{"webhook_url":"https://hooks.slack.com/services/..."},"min_severity":"warning"},{"type":"email","config":{"smtp_host":"smtp.gmail.com","smtp_port":587,"username":"you@gmail.com","password":"app-password","to_email":"alerts@example.com"},"min_severity":"critical"}]
```

---

## Database Schema

### Users

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | User ID |
| email | VARCHAR (unique) | Email address |
| hashed_password | VARCHAR | bcrypt hash |
| plan | VARCHAR | free, pro, enterprise |
| failed_attempts | INTEGER | Login failure count |
| locked_until | TIMESTAMP | Account lockout expiry |
| last_login | TIMESTAMP | Last successful login |
| totp_secret | VARCHAR | 2FA secret (optional) |
| totp_enabled | BOOLEAN | 2FA enabled flag |
| created_at | TIMESTAMP | Registration time |

### Scans

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Scan ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR (indexed) | Scan target |
| scan_type | VARCHAR | security, pentest, seo, etc. |
| status | VARCHAR | queued, running, completed, failed |
| risk_score | FLOAT | 0-100 risk score |
| findings_count | INTEGER | Number of findings |
| config | JSON | Scan configuration |
| created_at | TIMESTAMP | Creation time |
| completed_at | TIMESTAMP | Completion time |
| schedule_id | UUID (FK, nullable) | If triggered by schedule |

### Scheduled Scans

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Schedule ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR | Scan target |
| scan_type | VARCHAR | Scan type |
| cron_expression | VARCHAR | hourly, daily, 12h, etc. |
| config | JSON | Scan config |
| is_active | BOOLEAN | Active flag |
| next_run_at | TIMESTAMP | Next execution |
| last_run_at | TIMESTAMP | Last execution |
| run_count | INTEGER | Times executed |
| max_runs | INTEGER (nullable) | Max executions |

### Monitors

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Monitor ID |
| user_id | UUID (FK) | Owner |
| target | VARCHAR | Target to monitor |
| check_type | VARCHAR | http, tcp, dns, tls |
| interval_seconds | INTEGER | Check interval (default 300) |
| is_active | BOOLEAN | Active flag |
| last_status | VARCHAR | up, down, degraded |
| last_response_ms | INTEGER | Response time |
| last_checked_at | TIMESTAMP | Last check time |

### Notification Channels

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Channel ID |
| user_id | UUID (FK) | Owner |
| name | VARCHAR | Channel name |
| channel_type | VARCHAR | email, slack, discord, webhook |
| config | JSON | Channel-specific config |
| min_severity | VARCHAR | info, warning, critical |
| is_active | BOOLEAN | Active flag |

### Scan Memory

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL (PK) | Memory ID |
| content | TEXT | Stored knowledge |
| memory_type | VARCHAR | guide, finding, answer |
| tags | TEXT[] | Searchability tags |
| metadata | JSONB | Additional data |
| scan_id | VARCHAR | Source scan |
| target | VARCHAR | Related target |
| created_at | TIMESTAMP | Storage time |

## Further Reading

- [Installation](installation.md) — Setup and prerequisites
- [Deployment](deployment.md) — Production deployment with AWS
- [Architecture](architecture.md) — System design and agent loop
