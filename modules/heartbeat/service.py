"""
Heartbeat service — periodically checks health of all platform modules
and uses AI to generate a status summary posted to the global heartbeat feed.

Checks: API, Worker, Scheduler, Monitor, Redis, PostgreSQL, Elasticsearch.
"""

import json
import logging
import os
import signal
import time
from datetime import datetime

import httpx
import redis

from modules.config import AI_MODEL_LIGHT
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

log = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "120"))  # seconds
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@postgres:5432/scanner")
API_URL = os.getenv("API_URL", "http://api:8000")
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
REDIS_KEY = "heartbeat:messages"
MAX_MESSAGES = 100


def _check_redis(r: redis.Redis) -> dict:
    """Check Redis connectivity and basic stats."""
    try:
        info = r.info("server")
        mem = r.info("memory")
        clients = r.info("clients")
        return {
            "name": "Redis",
            "status": "up",
            "version": info.get("redis_version", "?"),
            "used_memory_mb": round(mem.get("used_memory", 0) / 1024 / 1024, 1),
            "connected_clients": clients.get("connected_clients", 0),
        }
    except Exception as e:
        return {"name": "Redis", "status": "down", "error": str(e)}


def _check_postgres(engine) -> dict:
    """Check PostgreSQL connectivity and table stats."""
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT version()")).scalar()
            scan_count = conn.execute(text("SELECT count(*) FROM scans")).scalar()
            running = conn.execute(text("SELECT count(*) FROM scans WHERE status='running'")).scalar()
            user_count = conn.execute(text("SELECT count(*) FROM users")).scalar()
        return {
            "name": "PostgreSQL",
            "status": "up",
            "version": (row or "").split(",")[0].replace("PostgreSQL ", ""),
            "total_scans": scan_count,
            "running_scans": running,
            "users": user_count,
        }
    except Exception as e:
        return {"name": "PostgreSQL", "status": "down", "error": str(e)}


def _check_elasticsearch() -> dict:
    """Check Elasticsearch cluster health."""
    try:
        resp = httpx.get(f"{ES_URL}/_cluster/health", timeout=5)
        data = resp.json()
        return {
            "name": "Elasticsearch",
            "status": "up",
            "cluster_status": data.get("status", "?"),
            "nodes": data.get("number_of_nodes", 0),
            "indices": data.get("active_shards", 0),
        }
    except Exception as e:
        return {"name": "Elasticsearch", "status": "down", "error": str(e)}


def _check_api() -> dict:
    """Check API health endpoint."""
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=5)
        data = resp.json()
        return {
            "name": "API",
            "status": "up",
            "version": data.get("version", "?"),
            "response_ms": round(resp.elapsed.total_seconds() * 1000),
        }
    except Exception as e:
        return {"name": "API", "status": "down", "error": str(e)}


def _check_worker(r: redis.Redis) -> dict:
    """Check worker health by looking at recent log activity."""
    try:
        logs = r.lrange("worker:logs", -5, -1)
        queue_len = r.llen("scan-jobs")
        last_log = ""
        if logs:
            last_log = (logs[-1].decode() if isinstance(logs[-1], bytes) else logs[-1])[:120]
        return {
            "name": "Worker",
            "status": "up" if logs else "idle",
            "queue_depth": queue_len,
            "last_log": last_log,
        }
    except Exception as e:
        return {"name": "Worker", "status": "unknown", "error": str(e)}


def _check_monitor(engine) -> dict:
    """Check monitor service by looking at recent monitor checks."""
    try:
        with engine.connect() as conn:
            active = conn.execute(text("SELECT count(*) FROM monitors WHERE is_active = TRUE")).scalar()
            recent = conn.execute(text(
                "SELECT count(*) FROM monitor_checks WHERE checked_at > NOW() - INTERVAL '5 minutes'"
            )).scalar()
            down = conn.execute(text(
                "SELECT count(*) FROM monitors WHERE is_active = TRUE AND last_status = 'down'"
            )).scalar()
        return {
            "name": "Monitor",
            "status": "up" if recent > 0 or active == 0 else "idle",
            "active_monitors": active,
            "recent_checks": recent,
            "monitors_down": down,
        }
    except Exception as e:
        return {"name": "Monitor", "status": "unknown", "error": str(e)}


def _generate_ai_summary(checks: list[dict]) -> str:
    """Use Claude to generate a concise heartbeat status summary."""
    try:
        import anthropic

        all_up = all(c["status"] in ("up", "idle") for c in checks)
        down = [c["name"] for c in checks if c["status"] == "down"]

        checks_json = json.dumps(checks, indent=1)

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=AI_MODEL_LIGHT,
            max_tokens=300,
            system=(
                "You are a platform health monitor. Generate a brief, single-paragraph status update "
                "for the security scanner platform based on the module health checks below. "
                "Be concise (2-4 sentences max). Use plain text, no markdown. "
                "Mention any issues or noteworthy stats. If everything is healthy, say so briefly. "
                "Include key metrics like queue depth, running scans, memory usage if notable."
            ),
            messages=[{"role": "user", "content": f"Module health checks:\n{checks_json}"}],
        )

        for block in response.content:
            if hasattr(block, "text"):
                return block.text

    except Exception as e:
        log.warning("AI summary failed: %s", e)

    # Fallback: plain text summary
    down = [c["name"] for c in checks if c["status"] == "down"]
    if down:
        return f"WARNING: {', '.join(down)} {'is' if len(down)==1 else 'are'} down. Other modules operational."
    return "All platform modules are operational."


def _post_heartbeat(r: redis.Redis, checks: list[dict], summary: str):
    """Store heartbeat message in Redis for the dashboard to read."""
    msg = json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "display_time": time.strftime("%H:%M:%S"),
        "summary": summary,
        "checks": checks,
        "all_ok": all(c["status"] in ("up", "idle") for c in checks),
    })
    r.rpush(REDIS_KEY, msg)
    r.ltrim(REDIS_KEY, -MAX_MESSAGES, -1)
    r.expire(REDIS_KEY, 86400 * 7)

    # Also dual-write to ES
    try:
        from modules.infra.elasticsearch import index_doc
        index_doc("scanner-heartbeat", {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": summary,
            "checks": checks,
            "all_ok": all(c["status"] in ("up", "idle") for c in checks),
        })
    except Exception:
        pass


class HeartbeatService:
    def __init__(self):
        self.running = True
        self.r = redis.from_url(REDIS_URL)
        self.engine = create_engine(DATABASE_URL)
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _shutdown(self, *_):
        log.info("Heartbeat service shutting down...")
        self.running = False

    def run(self):
        log.info("Heartbeat service started (interval=%ds)", HEARTBEAT_INTERVAL)
        while self.running:
            try:
                self._tick()
            except Exception as e:
                log.error("Heartbeat tick failed: %s", e)
            for _ in range(HEARTBEAT_INTERVAL):
                if not self.running:
                    break
                time.sleep(1)

    def _tick(self):
        log.info("Running heartbeat checks...")
        checks = [
            _check_redis(self.r),
            _check_postgres(self.engine),
            _check_elasticsearch(),
            _check_api(),
            _check_worker(self.r),
            _check_monitor(self.engine),
        ]

        statuses = {c["name"]: c["status"] for c in checks}
        log.info("Health: %s", statuses)

        summary = _generate_ai_summary(checks)
        _post_heartbeat(self.r, checks, summary)
        log.info("Heartbeat posted: %s", summary[:100])
