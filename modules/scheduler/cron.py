"""
Scheduler service — triggers scans on configured cron schedules.
Reads ScheduledScan records from the database and enqueues scan jobs.
"""

import logging
import signal
import time
import uuid
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from modules.infra import get_queue

log = logging.getLogger(__name__)


class SchedulerService:
    """Polls for due scheduled scans and enqueues them."""

    def __init__(self, database_url: str, poll_interval: int = 30):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.queue = get_queue()
        self.poll_interval = poll_interval
        self.running = True

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _shutdown(self, sig, frame):
        log.info("Scheduler shutting down...")
        self.running = False

    def run(self):
        """Main loop — check for due schedules and enqueue scans."""
        # Import here to avoid circular imports
        from modules.api.models import ScheduledScan, Scan

        log.info("Scheduler started (poll every %ds)", self.poll_interval)

        while self.running:
            try:
                with self.SessionLocal() as db:
                    now = datetime.utcnow()
                    due_schedules = (
                        db.query(ScheduledScan)
                        .filter(
                            ScheduledScan.is_active == True,
                            ScheduledScan.next_run_at <= now,
                        )
                        .all()
                    )

                    for schedule in due_schedules:
                        scan_id = str(uuid.uuid4())
                        log.info(
                            "Triggering scheduled scan %s: %s (%s)",
                            schedule.id,
                            schedule.target,
                            schedule.scan_type,
                        )

                        # Create a scan record
                        scan = Scan(
                            id=scan_id,
                            user_id=schedule.user_id,
                            target=schedule.target,
                            scan_type=schedule.scan_type,
                            config=schedule.config,
                        )
                        db.add(scan)

                        # Enqueue the job
                        self.queue.send("scan-jobs", {
                            "scan_id": scan_id,
                            "target": schedule.target,
                            "scan_type": schedule.scan_type,
                            "config": schedule.config or {},
                        })

                        # Calculate next run
                        schedule.last_run_at = now
                        schedule.next_run_at = self._calc_next_run(
                            schedule.cron_expression, now
                        )
                        schedule.run_count += 1

                        # Deactivate if max runs reached
                        if schedule.max_runs and schedule.run_count >= schedule.max_runs:
                            schedule.is_active = False
                            log.info("Schedule %s reached max runs (%d), deactivated", schedule.id, schedule.max_runs)

                    db.commit()

            except Exception as e:
                log.exception("Scheduler error: %s", e)

            time.sleep(self.poll_interval)

    @staticmethod
    def _calc_next_run(cron_expression: str, from_time: datetime) -> datetime:
        """
        Simple interval-based scheduling.
        Supports: "hourly", "daily", "weekly", "monthly", or "{N}h" / "{N}m" / "{N}d" formats.
        """
        expr = cron_expression.strip().lower()

        if expr == "hourly":
            return from_time + timedelta(hours=1)
        elif expr == "daily":
            return from_time + timedelta(days=1)
        elif expr == "weekly":
            return from_time + timedelta(weeks=1)
        elif expr == "monthly":
            return from_time + timedelta(days=30)
        elif expr.endswith("h"):
            hours = int(expr[:-1])
            return from_time + timedelta(hours=hours)
        elif expr.endswith("m"):
            minutes = int(expr[:-1])
            return from_time + timedelta(minutes=minutes)
        elif expr.endswith("d"):
            days = int(expr[:-1])
            return from_time + timedelta(days=days)
        else:
            # Default: daily
            return from_time + timedelta(days=1)
