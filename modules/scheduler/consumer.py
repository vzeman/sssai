"""Scheduler entry point."""

import logging
import os

from modules.scheduler.cron import SchedulerService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    database_url = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@postgres:5432/scanner")
    service = SchedulerService(database_url)
    service.run()
