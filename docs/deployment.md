# Deployment

SSSAI supports two deployment modes: **local** (Docker Compose) and **AWS** (ECS Fargate). The same codebase is used for both — the `RUNTIME` environment variable switches between backend implementations.

## Local Deployment (Docker Compose)

This is the default mode. See [Installation](installation.md) for setup.

```bash
RUNTIME=local  # default
docker compose up --build -d
```

**Backend mapping:**

| Component | Implementation |
|-----------|---------------|
| Queue | Redis (BRPOP/LPUSH) |
| Storage | Filesystem (`/output/`) |
| Secrets | `.env` file |
| Compute | Docker Compose |
| Database | Local PostgreSQL container |

### Docker Compose Services

The `docker-compose.yml` defines 8 services:

```yaml
services:
  api:          # FastAPI on port 8000
  worker:       # AI agent + 69+ scanning tools
  scheduler:    # Cron-based scheduled scan triggering
  monitor:      # Uptime/availability monitoring
  heartbeat:    # AI-powered platform health checks
  elasticsearch: # 8.13.0, single-node, security disabled
  redis:        # 7-alpine, no auth
  postgres:     # 16-alpine, credentials: scanner/scanner
```

### Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 8 GB | 20 GB |

The worker container is the heaviest — it includes a full Ubuntu 22.04 base with 69+ scanning tools installed.

### Data Persistence

Docker volumes persist data across restarts:

| Volume | Data |
|--------|------|
| `pgdata` | PostgreSQL database (users, scans, schedules, memory) |
| `esdata` | Elasticsearch indices (logs, heartbeat history) |
| `./output` | Scan reports and agent logs (bind mount) |

To reset all data:
```bash
docker compose down -v
```

### Security Notes for Local

The default configuration is designed for development. For any network-accessible deployment:

1. **Change `JWT_SECRET`** — The default `dev-secret-change-in-production` is not secure
2. **Change database credentials** — Default is `scanner/scanner`
3. **Enable Redis authentication** — Default has no auth
4. **Restrict port exposure** — Only port 8000 needs external access
5. **Use HTTPS** — Put a reverse proxy (nginx, Caddy) in front of the API

---

## AWS Deployment

Set `RUNTIME=aws` to use AWS-native backends.

```bash
RUNTIME=aws
```

**Backend mapping:**

| Component | Implementation |
|-----------|---------------|
| Queue | Amazon SQS |
| Storage | Amazon S3 |
| Secrets | AWS Secrets Manager |
| Compute | ECS Fargate |
| Database | Amazon RDS PostgreSQL |

### Required AWS Variables

| Variable | Description |
|----------|-------------|
| `S3_BUCKET` | S3 bucket for report storage |
| `SQS_SCAN_QUEUE_URL` | SQS queue URL for scan jobs |
| `DATABASE_URL` | RDS PostgreSQL connection URL |

### Infrastructure Components

**ECS Fargate Tasks:**
- API service (public, load balanced)
- Worker service (private, pulls from SQS)
- Scheduler service (private)
- Monitor service (private)
- Heartbeat service (private)

**Supporting Services:**
- RDS PostgreSQL (Multi-AZ recommended for production)
- ElastiCache Redis (for pub/sub and live logs)
- S3 bucket (for reports and agent logs)
- SQS queue (for scan jobs)
- Secrets Manager (for API keys and credentials)
- ALB (Application Load Balancer for the API)

### IAM Permissions

The ECS task roles need:
- SQS: `SendMessage`, `ReceiveMessage`, `DeleteMessage`
- S3: `PutObject`, `GetObject`, `ListBucket`
- Secrets Manager: `GetSecretValue`
- CloudWatch Logs: `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`

### Infrastructure Abstraction

The code uses factory functions that return the correct implementation based on `RUNTIME`:

```python
from modules.infra import get_queue, get_storage, get_secrets

queue = get_queue()      # Redis queue (local) or SQS (aws)
storage = get_storage()  # Filesystem (local) or S3 (aws)
secrets = get_secrets()  # .env (local) or Secrets Manager (aws)
```

---

## Production Checklist

Regardless of deployment mode, ensure these for production:

- [ ] Change `JWT_SECRET` to a strong, random value
- [ ] Set `AI_MODEL` to desired quality level
- [ ] Configure notification channels for alerting
- [ ] Set up HTTPS (reverse proxy or ALB)
- [ ] Restrict network access to internal services
- [ ] Set up database backups
- [ ] Monitor disk space (scan reports accumulate)
- [ ] Configure log rotation

## Further Reading

- [Installation](installation.md) — Local setup guide
- [Configuration](configuration.md) — All environment variables
- [Architecture](architecture.md) — System design
