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
        self._emitting = False
        try:
            import redis
            self._r = redis.from_url(redis_url)
            self._key = key
            self._maxlen = maxlen
        except Exception:
            self._r = None

    def emit(self, record):
        if not self._r or self._emitting:
            return
        self._emitting = True
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
        finally:
            self._emitting = False


_redis_url = os.environ.get("REDIS_URL", "redis://redis:6379")
_rh = RedisLogHandler(_redis_url)
_rh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(_rh)

QUEUE_NAME = "scan-jobs"
VALIDATION_QUEUE = "validation-jobs"
_DB_URL = os.environ.get("DATABASE_URL", "")


def _update_scan_status(scan_id: str, status: str, risk_score=None, findings_count=None,
                        token_usage=None):
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
            if token_usage:
                sql += ", total_input_tokens = :input_tokens, total_output_tokens = :output_tokens, estimated_cost = :cost"
                params["input_tokens"] = token_usage.get("total_input_tokens", 0)
                params["output_tokens"] = token_usage.get("total_output_tokens", 0)
                params["cost"] = token_usage.get("estimated_cost_usd", 0.0)
            sql += " WHERE id = :scan_id"
            conn.execute(text(sql), params)
            conn.commit()
    except Exception as e:
        log.warning("Could not update scan status: %s", e)


def _get_scan_user_id(scan_id: str) -> str | None:
    """Look up the user_id for a completed scan."""
    if not _DB_URL:
        return None
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT user_id FROM scans WHERE id = :scan_id"),
                {"scan_id": scan_id},
            ).fetchone()
            return row[0] if row else None
    except Exception as e:
        log.warning("Could not fetch user_id for scan %s: %s", scan_id, e)
        return None


running = True


def shutdown(sig, frame):
    global running
    log.info("Shutting down worker...")
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def _recover_orphaned_scans():
    """Find scans stuck in 'running' status from a previous worker instance and recover them."""
    if not _DB_URL:
        return
    try:
        from sqlalchemy import create_engine, text
        from modules.agent.checkpoint import load_checkpoint, build_resume_context

        engine = create_engine(_DB_URL)
        queue = get_queue()

        with engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT id, target, scan_type, config FROM scans WHERE status = 'running'"
            )).fetchall()

        if not rows:
            log.info("No orphaned scans found in 'running' status")
            return

        log.info("Found %d orphaned scan(s) in 'running' status", len(rows))

        recovered_count = 0
        failed_count = 0
        for row in rows:
            scan_id, target, scan_type, config = row[0], row[1], row[2], row[3]
            config = config or {}

            checkpoint = load_checkpoint(scan_id)
            if checkpoint:
                checkpoint_iteration = checkpoint.get("iteration", 0)
                checkpoint_tools = checkpoint.get("tools_run", [])
                log.info(
                    "Recovering scan %s from checkpoint: iteration=%d, tools_run=%d, scan_type=%s, target=%s",
                    scan_id, checkpoint_iteration, len(checkpoint_tools), scan_type, target,
                )
                resume_config = {**config, "resume_context": build_resume_context(checkpoint)}
                _update_scan_status(scan_id, "queued")
                queue.send(QUEUE_NAME, {
                    "scan_id": scan_id,
                    "target": target,
                    "scan_type": scan_type,
                    "config": resume_config,
                })
                recovered_count += 1
            else:
                log.warning(
                    "No checkpoint for orphaned scan %s (target=%s, scan_type=%s) — marking failed",
                    scan_id, target, scan_type,
                )
                _update_scan_status(scan_id, "failed")
                from modules.infra import get_storage
                get_storage().put_json(f"scans/{scan_id}/error.json", {
                    "error": "Worker restarted with no checkpoint available. Scan could not be recovered.",
                    "scan_id": scan_id,
                })
                failed_count += 1

        log.info(
            "Orphaned scan recovery complete: %d recovered, %d failed out of %d total",
            recovered_count, failed_count, len(rows),
        )
    except Exception as e:
        log.error("Orphaned scan recovery failed: %s", e)


def main():
    queue = get_queue()
    log.info("Worker started, listening on queue: %s", QUEUE_NAME)
    _recover_orphaned_scans()

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

            # Inject user_id into run_scan config so the agent can use it for
            # per-tenant memory recall (#174) without re-querying the DB.
            _user_id = _get_scan_user_id(scan_id)
            if _user_id:
                config = {**(config or {}), "user_id": _user_id}

            try:
                report = run_scan(scan_id, target, scan_type, config)
                raw_findings = report.get("findings", [])
                findings = len(raw_findings)
                score = report.get("risk_score", 0)
                # Extract token usage from report metadata
                token_usage = None
                meta = report.get("scan_metadata", {})
                if meta and meta.get("total_input_tokens"):
                    token_usage = meta
                log.info("Scan %s completed: %d findings, risk score %s", scan_id, findings, score)
                _update_scan_status(scan_id, "completed", risk_score=score, findings_count=findings,
                                    token_usage=token_usage)

                # Store detected technologies in asset inventory for CVE monitoring
                try:
                    user_id = _get_scan_user_id(scan_id)
                    if user_id:
                        from modules.cve_monitor.inventory import store_technologies_from_report
                        store_technologies_from_report(scan_id, user_id, target, report, _DB_URL)
                except Exception as inv_err:
                    log.warning("Asset inventory update failed for scan %s: %s", scan_id, inv_err)

                # Update security posture score after scan completes
                try:
                    posture_user_id = _user_id or _get_scan_user_id(scan_id)
                    if posture_user_id:
                        from modules.agent.posture_score import run_posture_update
                        run_posture_update(
                            scan_id, target, posture_user_id,
                            raw_findings, score,
                        )
                except Exception as posture_err:
                    log.warning("Posture score update failed for scan %s: %s", scan_id, posture_err)

                # Auto-store scan summary in cross-scan memory for future recall (#174)
                try:
                    from modules.agent.memory import auto_store_scan_summary
                    auto_store_scan_summary(scan_id, _user_id, target, scan_type, report)
                except Exception as mem_err:
                    log.warning("auto_store_scan_summary failed for scan %s: %s", scan_id, mem_err)
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
