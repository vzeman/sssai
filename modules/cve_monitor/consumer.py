"""CVE monitor entry point — runs the daily CVE checking job."""

import logging
import os

from modules.cve_monitor.checker import CveCheckerService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    database_url = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@postgres:5432/scanner")
    service = CveCheckerService(database_url)
    service.run()
