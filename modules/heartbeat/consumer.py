"""Heartbeat service entry point."""

import logging
import os

from modules.heartbeat.service import HeartbeatService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    service = HeartbeatService()
    service.run()
