# Installation Guide

## Prerequisites

Before installing SSSAI, make sure you have the following:

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| **Docker** | 20.10+ | [Install Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | 2.0+ | Included with Docker Desktop |
| **Anthropic API Key** | — | [Get your API key](https://console.anthropic.com/) |
| **Disk Space** | ~8 GB | Worker image contains 69+ scanning tools |
| **RAM** | 4 GB minimum | Elasticsearch alone needs ~512 MB |

## Step 1: Clone the Repository

```bash
git clone https://github.com/vzeman/sssai.git
cd sssai/security-scanner
```

## Step 2: Configure Environment

Copy the example environment file and add your API key:

```bash
cp .env.example .env
```

Open `.env` in your editor and set the required values:

```bash
# REQUIRED — your Anthropic API key
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

That's all you need to get started. The defaults work for local development. See [Configuration](configuration.md) for all available options.

### Production Checklist

If you're deploying beyond local development, also change these:

```bash
# IMPORTANT — change the JWT secret for production
JWT_SECRET=your-strong-random-secret-here

# Optional — upgrade AI model for better scan quality
AI_MODEL=claude-sonnet-4-20250514
```

## Step 3: Start the Platform

```bash
docker compose up --build -d
```

This starts 8 services:

| Service | What It Does | Port |
|---------|-------------|------|
| **api** | REST API + web dashboard | `localhost:8000` |
| **worker** | Queue consumer that runs AI agent + scanning tools | internal |
| **scheduler** | Triggers scans on cron schedules | internal |
| **monitor** | Uptime/availability checks | internal |
| **heartbeat** | Periodic AI-powered platform health checks | internal |
| **redis** | Message queue, pub/sub, live logs | internal |
| **postgres** | Users, scans, schedules, memory storage | internal |
| **elasticsearch** | Logs, historical data, search | internal |

The first build takes 5-10 minutes because the worker image installs 69+ scanning tools.

### Verify Everything Is Running

```bash
docker compose ps
```

All services should show `Up` or `healthy` status.

```bash
# Check API health
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "ok"}
```

## Step 4: Open the Dashboard

Open your browser and navigate to:

```
http://localhost:8000
```

You'll see the SSSAI dashboard with a registration form. Continue to [Getting Started](getting-started.md) for your first scan.

## Stopping the Platform

```bash
# Stop all services (data is preserved in Docker volumes)
docker compose down

# Stop and remove all data (clean slate)
docker compose down -v
```

## Updating

```bash
git pull
docker compose up --build -d
```

The `--build` flag ensures the worker image is rebuilt with any new tools or code changes.

## Troubleshooting

### Worker container fails to start

The worker image is large (~8 GB) and installs many system packages. If it fails:

```bash
# Check build logs
docker compose logs worker

# Rebuild from scratch
docker compose build --no-cache worker
docker compose up -d
```

### Elasticsearch won't start

Elasticsearch needs sufficient virtual memory:

```bash
# On Linux, you may need to increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
```

On macOS with Docker Desktop, this is handled automatically.

### Port 8000 is already in use

Edit `docker-compose.yml` and change the API port mapping:

```yaml
api:
  ports:
    - "9000:8000"  # Change 8000 to any available port
```

### API key errors

If scans fail immediately, verify your Anthropic API key:

```bash
# Test your API key
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

### Checking logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f worker
docker compose logs -f api
```

## Next Steps

- [Getting Started](getting-started.md) — Register your account and run your first scan
- [Configuration](configuration.md) — Customize AI models, notifications, and more
- [Security Checks](security-checks.md) — Understand what each scan type does
