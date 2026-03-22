"""Queue consumer — picks up scan jobs and runs the AI agent."""

import json
import logging
import os
import signal
import sys

from modules.agent.scan_agent import run_scan, run_validation
from modules.infra import get_queue

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


class RedisLogHandler(logging.Handler):
    """Push log lines to a Redis list so the dashboard can read them."""

    def __init__(self, redis_url: str, key: str = "worker:logs", maxlen: int = 500):
        super().__init__()
        try:
            import redis
            self._r = redis.from_url(redis_url)
            self._key = key
            self._maxlen = maxlen
        except Exception:
            self._r = None

    def emit(self, record):
        if not self._r:
            return
        try:
            msg = self.format(record)
            self._r.rpush(self._key, msg)
            self._r.ltrim(self._key, -self._maxlen, -1)
        except Exception:
            pass
        # Dual-write to Elasticsearch
        try:
            from modules.infra.elasticsearch import index_doc
            from datetime import datetime, timezone
            index_doc("scanner-worker-logs", {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
                "service": "worker",
            })
        except Exception:
            pass


_redis_url = os.environ.get("REDIS_URL", "redis://redis:6379")
_rh = RedisLogHandler(_redis_url)
_rh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(_rh)

QUEUE_NAME = "scan-jobs"
VALIDATION_QUEUE = "validation-jobs"
_DB_URL = os.environ.get("DATABASE_URL", "")


def _update_scan_status(scan_id: str, status: str, risk_score=None, findings_count=None):
    """Update scan status in the database via direct DB connection."""
    if not _DB_URL:
        return
    try:
        from sqlalchemy import create_engine, text
        from datetime import datetime, timezone
        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            params = {"status": status, "scan_id": scan_id}
            sql = "UPDATE scans SET status = :status"
            if risk_score is not None:
                sql += ", risk_score = :risk_score"
                params["risk_score"] = risk_score
            if findings_count is not None:
                sql += ", findings_count = :findings_count"
                params["findings_count"] = findings_count
            if status == "completed":
                sql += ", completed_at = :completed_at"
                params["completed_at"] = datetime.now(timezone.utc)
            sql += " WHERE id = :scan_id"
            conn.execute(text(sql), params)
            conn.commit()
    except Exception as e:
        log.warning("Could not update scan status: %s", e)
running = True


def shutdown(sig, frame):
    global running
    log.info("Shutting down worker...")
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def main():
    queue = get_queue()
    log.info("Worker started, listening on queue: %s", QUEUE_NAME)

    while running:
        # Check scan jobs first
        job = queue.receive(QUEUE_NAME, timeout=5)
        if job:
            scan_id = job["scan_id"]
            target = job["target"]
            scan_type = job.get("scan_type", "security")
            config = job.get("config", {})

            log.info("Starting scan %s: %s (%s)", scan_id, target, scan_type)
            _update_scan_status(scan_id, "running")

            try:
                report = run_scan(scan_id, target, scan_type, config)
                findings = len(report.get("findings", []))
                score = report.get("risk_score", 0)
                log.info("Scan %s completed: %d findings, risk score %s", scan_id, findings, score)
                _update_scan_status(scan_id, "completed", risk_score=score, findings_count=findings)
            except Exception as e:
                log.exception("Scan %s failed: %s", scan_id, e)
                _update_scan_status(scan_id, "failed")
                from modules.infra import get_storage
                get_storage().put_json(f"scans/{scan_id}/error.json", {
                    "error": str(e),
                    "scan_id": scan_id,
                })
            continue

        # Check validation jobs
        val_job = queue.receive(VALIDATION_QUEUE, timeout=5)
        if val_job:
            task_id = val_job["task_id"]
            user_id = val_job["user_id"]
            log.info("Starting validation task %s", task_id)
            try:
                run_validation(task_id, user_id, val_job)
                log.info("Validation task %s completed", task_id)
            except Exception as e:
                log.exception("Validation task %s failed: %s", task_id, e)


if __name__ == "__main__":
    main()
