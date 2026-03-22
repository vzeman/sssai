"""Scan checkpoint — save and restore scan state for crash recovery."""

import json
import logging
import os
import time

log = logging.getLogger(__name__)

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
CHECKPOINT_TTL = 14400  # 4 hours


def save_checkpoint(scan_id: str, data: dict) -> None:
    """Save a scan checkpoint to Redis."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        r.set(f"scan:checkpoint:{scan_id}", json.dumps(data), ex=CHECKPOINT_TTL)
    except Exception as e:
        log.warning("Failed to save checkpoint for %s: %s", scan_id, e)


def load_checkpoint(scan_id: str) -> dict | None:
    """Load a scan checkpoint from Redis. Returns None if not found."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        raw = r.get(f"scan:checkpoint:{scan_id}")
        if raw:
            return json.loads(raw)
    except Exception as e:
        log.warning("Failed to load checkpoint for %s: %s", scan_id, e)
    return None


def delete_checkpoint(scan_id: str) -> None:
    """Remove checkpoint after scan completes."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        r.delete(f"scan:checkpoint:{scan_id}")
        r.delete(f"scan:heartbeat:{scan_id}")
    except Exception:
        pass


def build_resume_context(checkpoint: dict) -> dict:
    """Build a resume_context dict from a checkpoint for injection into run_scan config."""
    return {
        "summary_of_progress": checkpoint.get("summary_of_progress", ""),
        "findings_so_far": checkpoint.get("findings_so_far", []),
        "iteration": checkpoint.get("iteration", 0),
        "commands_executed": checkpoint.get("commands_executed", 0),
        "attack_surface": checkpoint.get("attack_surface"),
        "plan_history": checkpoint.get("plan_history"),
        "previous_token_usage": checkpoint.get("token_usage"),
        "original_start_time": checkpoint.get("start_time"),
    }
