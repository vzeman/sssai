"""
Heartbeat service — periodically checks health of all platform modules
and uses AI to generate a status summary posted to the global heartbeat feed.

Checks: API, Worker, Scheduler, Monitor, Redis, PostgreSQL, Elasticsearch, ScanHealth.
The AI agent has tools to retry or fail stuck scans.
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
STUCK_SCAN_TIMEOUT = int(os.getenv("STUCK_SCAN_TIMEOUT_SECONDS", "600"))  # 10 min
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@postgres:5432/scanner")
API_URL = os.getenv("API_URL", "http://api:8000")
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
REDIS_KEY = "heartbeat:messages"
MAX_MESSAGES = 100

# ── AI tools for heartbeat agent ──

HEARTBEAT_TOOLS = [
    {
        "name": "retry_stuck_scan",
        "description": "Retry a stuck scan using its checkpoint if available. Use when a scan has been silent for 10-30 minutes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "The scan ID to retry"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "fail_stuck_scan",
        "description": "Mark a stuck scan as failed. Use when a scan has been silent for 30+ minutes or has already been retried once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "The scan ID to fail"},
                "reason": {"type": "string", "description": "Why the scan is being failed"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "post_scan_recommendation",
        "description": "Post a recommendation to the global advisor chat suggesting a scan that needs attention.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to scan"},
                "scan_type": {"type": "string", "description": "Recommended scan type"},
                "reason": {"type": "string", "description": "Why this scan is needed"},
                "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            },
            "required": ["target", "scan_type", "reason", "priority"],
        },
    },
]


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


def _check_stuck_scans(engine, r: redis.Redis) -> dict:
    """Detect scans that are in 'running' status but have no recent heartbeat."""
    try:
        with engine.connect() as conn:
            running = conn.execute(text(
                "SELECT id, target, scan_type, created_at FROM scans WHERE status = 'running'"
            )).fetchall()

        stuck = []
        healthy = 0
        for row in running:
            scan_id, target, scan_type, created_at = row[0], row[1], row[2], row[3]
            last_beat = r.get(f"scan:heartbeat:{scan_id}")
            if last_beat:
                age = time.time() - float(last_beat)
                if age > STUCK_SCAN_TIMEOUT:
                    already_retried = r.exists(f"scan:stuck_retry:{scan_id}")
                    stuck.append({
                        "scan_id": scan_id,
                        "target": target,
                        "scan_type": scan_type,
                        "silent_seconds": int(age),
                        "already_retried": bool(already_retried),
                    })
                else:
                    healthy += 1
            else:
                # No heartbeat key — possibly orphaned from before checkpointing existed
                if created_at:
                    created_age = (datetime.utcnow() - created_at).total_seconds()
                else:
                    created_age = STUCK_SCAN_TIMEOUT + 1
                if created_age > STUCK_SCAN_TIMEOUT:
                    already_retried = r.exists(f"scan:stuck_retry:{scan_id}")
                    stuck.append({
                        "scan_id": scan_id,
                        "target": target,
                        "scan_type": scan_type,
                        "silent_seconds": int(created_age),
                        "no_heartbeat_key": True,
                        "already_retried": bool(already_retried),
                    })
                else:
                    healthy += 1

        return {
            "name": "ScanHealth",
            "status": "warning" if stuck else "up",
            "running_scans": len(running),
            "healthy_scans": healthy,
            "stuck_scans": stuck,
        }
    except Exception as e:
        return {"name": "ScanHealth", "status": "unknown", "error": str(e)}


def _check_scan_attention_needed(engine) -> dict:
    """Review scans that may need AI attention: high-severity findings, coverage gaps, degrading posture."""
    result = {
        "name": "ScanAttention",
        "status": "up",
        "high_severity_scans": [],
        "coverage_gaps": [],
        "degrading_targets": [],
    }
    try:
        with engine.connect() as conn:
            # 1. Completed scans in the last 24h with critical/high findings needing follow-up
            rows = conn.execute(text(
                "SELECT s.id, s.target, s.scan_type, s.risk_score "
                "FROM scans s "
                "WHERE s.status = 'completed' "
                "AND s.completed_at > NOW() - INTERVAL '24 hours' "
                "AND s.risk_score >= 70 "
                "ORDER BY s.risk_score DESC "
                "LIMIT 10"
            )).fetchall()
            for row in rows:
                result["high_severity_scans"].append({
                    "scan_id": row[0],
                    "target": row[1],
                    "scan_type": row[2],
                    "risk_score": row[3],
                })

            # 2. Coverage gaps — targets scanned with one type but missing other common types
            coverage = conn.execute(text(
                "SELECT DISTINCT target, array_agg(DISTINCT scan_type) AS types "
                "FROM scans "
                "WHERE status = 'completed' "
                "AND created_at > NOW() - INTERVAL '30 days' "
                "GROUP BY target"
            )).fetchall()
            recommended_types = {"security", "ssl", "api", "headers"}
            for row in coverage:
                target = row[0]
                completed_types = set(row[1]) if row[1] else set()
                missing = recommended_types - completed_types
                if missing:
                    result["coverage_gaps"].append({
                        "target": target,
                        "completed_types": list(completed_types),
                        "missing_types": list(missing),
                    })

            # 3. Degrading posture — targets where risk scores are trending upward
            trending = conn.execute(text(
                "SELECT target, "
                "  AVG(risk_score) FILTER (WHERE completed_at > NOW() - INTERVAL '7 days') AS recent_avg, "
                "  AVG(risk_score) FILTER (WHERE completed_at BETWEEN NOW() - INTERVAL '30 days' AND NOW() - INTERVAL '7 days') AS older_avg "
                "FROM scans "
                "WHERE status = 'completed' AND risk_score IS NOT NULL "
                "GROUP BY target "
                "HAVING COUNT(*) FILTER (WHERE completed_at > NOW() - INTERVAL '7 days') >= 1 "
                "  AND COUNT(*) FILTER (WHERE completed_at BETWEEN NOW() - INTERVAL '30 days' AND NOW() - INTERVAL '7 days') >= 1"
            )).fetchall()
            for row in trending:
                target, recent_avg, older_avg = row[0], row[1], row[2]
                if recent_avg is not None and older_avg is not None and recent_avg > older_avg + 10:
                    result["degrading_targets"].append({
                        "target": target,
                        "recent_avg_risk": round(float(recent_avg), 1),
                        "older_avg_risk": round(float(older_avg), 1),
                        "delta": round(float(recent_avg - older_avg), 1),
                    })

        needs_attention = (
            result["high_severity_scans"]
            or result["coverage_gaps"]
            or result["degrading_targets"]
        )
        result["status"] = "warning" if needs_attention else "up"

    except Exception as e:
        result["status"] = "unknown"
        result["error"] = str(e)

    return result


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
            _check_stuck_scans(self.engine, self.r),
            _check_scan_attention_needed(self.engine),
        ]

        statuses = {c["name"]: c["status"] for c in checks}
        log.info("Health: %s", statuses)

        # Check if any scans are stuck or need attention — if so, give AI tools to handle them
        scan_health = next((c for c in checks if c["name"] == "ScanHealth"), {})
        stuck_scans = scan_health.get("stuck_scans", [])

        scan_attention = next((c for c in checks if c["name"] == "ScanAttention"), {})
        needs_attention = (
            scan_attention.get("high_severity_scans")
            or scan_attention.get("coverage_gaps")
            or scan_attention.get("degrading_targets")
        )

        if stuck_scans or needs_attention:
            summary = self._generate_ai_summary_with_tools(checks)
        else:
            summary = _generate_ai_summary(checks)

        _post_heartbeat(self.r, checks, summary)
        log.info("Heartbeat posted: %s", summary[:100])

    def _generate_ai_summary_with_tools(self, checks: list[dict]) -> str:
        """Use Claude with tools to analyze health AND take action on stuck scans."""
        try:
            import anthropic

            client = anthropic.Anthropic()
            checks_json = json.dumps(checks, indent=1)

            system = (
                "You are a platform health monitor for a security scanner. "
                "Review the health checks and take action on any stuck scans or scan attention items.\n\n"
                "Rules for stuck scans:\n"
                "- If a scan has been silent for 10+ minutes and already_retried is false: retry it\n"
                "- If a scan has been silent for 30+ minutes OR already_retried is true: fail it\n\n"
                "Rules for scan attention (ScanAttention check):\n"
                "- For high_severity_scans: recommend a follow-up scan using post_scan_recommendation\n"
                "- For coverage_gaps: recommend the missing scan types using post_scan_recommendation\n"
                "- For degrading_targets: recommend a comprehensive security scan using post_scan_recommendation with high/critical priority\n"
                "- Use post_scan_recommendation to post recommendations to the advisor chat\n\n"
                "After taking actions, provide a brief 2-4 sentence status summary in plain text.\n"
                "Include what actions you took on stuck scans and recommendations in your summary."
            )

            messages = [{"role": "user", "content": f"Module health checks:\n{checks_json}"}]

            for _ in range(5):
                response = client.messages.create(
                    model=AI_MODEL_LIGHT,
                    max_tokens=500,
                    system=system,
                    tools=HEARTBEAT_TOOLS,
                    messages=messages,
                )

                if response.stop_reason == "end_turn":
                    return "".join(b.text for b in response.content if hasattr(b, "text"))

                if response.stop_reason == "tool_use":
                    tool_results = []
                    for block in response.content:
                        if block.type == "tool_use":
                            result = self._handle_heartbeat_tool(block.name, block.input)
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": result,
                            })
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": tool_results})
                    continue
                break

        except Exception as e:
            log.warning("AI summary with tools failed: %s", e)

        return _generate_ai_summary(checks)

    def _handle_heartbeat_tool(self, name: str, input_data: dict) -> str:
        """Execute a heartbeat AI tool."""
        if name == "retry_stuck_scan":
            scan_id = input_data["scan_id"]
            return self._retry_scan(scan_id)
        elif name == "fail_stuck_scan":
            scan_id = input_data["scan_id"]
            reason = input_data.get("reason", "Marked failed by heartbeat AI — no activity detected")
            return self._fail_scan(scan_id, reason)
        elif name == "post_scan_recommendation":
            return self._post_scan_recommendation(input_data)
        return f"Unknown tool: {name}"

    def _post_scan_recommendation(self, input_data: dict) -> str:
        """Post a scan recommendation to the global advisor chat."""
        try:
            target = input_data["target"]
            scan_type = input_data["scan_type"]
            reason = input_data["reason"]
            priority = input_data["priority"]

            msg = json.dumps({
                "role": "system",
                "message": (
                    f"[Scan Recommendation] Target: {target} | Type: {scan_type} | "
                    f"Priority: {priority}\n{reason}"
                ),
                "type": "recommendation",
                "target": target,
                "scan_type": scan_type,
                "priority": priority,
                "reason": reason,
                "timestamp": time.strftime("%H:%M:%S"),
                "ts": time.time(),
            })
            self.r.rpush("advisor:chat:history", msg)
            self.r.ltrim("advisor:chat:history", -500, -1)
            self.r.expire("advisor:chat:history", 86400 * 7)

            log.info("Posted scan recommendation: %s %s (%s)", target, scan_type, priority)
            return f"Recommendation posted to advisor chat: {scan_type} scan of {target} ({priority} priority)."

        except Exception as e:
            log.error("Failed to post scan recommendation: %s", e)
            return f"Failed to post recommendation: {e}"

    def _retry_scan(self, scan_id: str) -> str:
        """Re-queue a stuck scan with checkpoint context if available."""
        try:
            from modules.infra.checkpoint import load_checkpoint, build_resume_context
            from modules.infra import get_queue

            with self.engine.connect() as conn:
                row = conn.execute(text(
                    "SELECT target, scan_type, config FROM scans WHERE id = :sid"
                ), {"sid": scan_id}).fetchone()
                if not row:
                    return f"Scan {scan_id} not found in database."
                target, scan_type, config = row[0], row[1], row[2]
                config = config or {}

            checkpoint = load_checkpoint(scan_id)
            if checkpoint:
                config = {**config, "resume_context": build_resume_context(checkpoint)}

            with self.engine.connect() as conn:
                conn.execute(text("UPDATE scans SET status = 'queued' WHERE id = :sid"), {"sid": scan_id})
                conn.commit()

            # Mark that we already retried this scan (1h TTL)
            self.r.set(f"scan:stuck_retry:{scan_id}", "1", ex=3600)

            get_queue().send("scan-jobs", {
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "config": config,
            })

            msg = f"Scan {scan_id} re-queued"
            if checkpoint:
                msg += f" with checkpoint (iteration {checkpoint.get('iteration', '?')})"
            log.info(msg)
            return msg + "."

        except Exception as e:
            log.error("Failed to retry scan %s: %s", scan_id, e)
            return f"Failed to retry scan {scan_id}: {e}"

    def _fail_scan(self, scan_id: str, reason: str) -> str:
        """Mark a scan as failed."""
        try:
            from modules.infra import get_storage
            from modules.infra.checkpoint import delete_checkpoint

            with self.engine.connect() as conn:
                conn.execute(text("UPDATE scans SET status = 'failed' WHERE id = :sid"), {"sid": scan_id})
                conn.commit()

            get_storage().put_json(f"scans/{scan_id}/error.json", {
                "error": reason,
                "scan_id": scan_id,
            })

            delete_checkpoint(scan_id)
            self.r.delete(f"scan:stuck_retry:{scan_id}")

            log.info("Scan %s marked as failed: %s", scan_id, reason)
            return f"Scan {scan_id} marked as failed."

        except Exception as e:
            log.error("Failed to mark scan %s as failed: %s", scan_id, e)
            return f"Failed to mark scan {scan_id} as failed: {e}"
