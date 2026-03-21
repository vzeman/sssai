"""Uptime monitor — periodically checks targets and updates status."""

import logging
import signal
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from modules.api.database import SessionLocal
from modules.api.models import Monitor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

running = True


def shutdown(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def check_http(target: str) -> tuple[str, int]:
    url = target if target.startswith("http") else f"https://{target}"
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True)
        return ("up" if r.status_code < 400 else "degraded"), int(r.elapsed.total_seconds() * 1000)
    except Exception:
        return "down", 0


def check_tcp(target: str, port: int = 443) -> tuple[str, int]:
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else port
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return "up", int((time.time() - start) * 1000)
    except Exception:
        return "down", 0


def check_dns(target: str) -> tuple[str, int]:
    start = time.time()
    try:
        socket.getaddrinfo(target, None)
        return "up", int((time.time() - start) * 1000)
    except Exception:
        return "down", 0


def check_tls(target: str) -> tuple[str, int]:
    start = time.time()
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            status = "up" if days_left > 7 else "degraded"
            return status, int((time.time() - start) * 1000)
    except Exception:
        return "down", 0


CHECKERS = {"http": check_http, "tcp": check_tcp, "dns": check_dns, "tls": check_tls}


def run_checks():
    db: Session = SessionLocal()
    try:
        monitors = db.query(Monitor).filter(Monitor.is_active == True).all()
        now = datetime.now(timezone.utc)

        for m in monitors:
            if m.last_checked_at:
                elapsed = (now - m.last_checked_at.replace(tzinfo=timezone.utc)).total_seconds()
                if elapsed < m.interval_seconds:
                    continue

            checker = CHECKERS.get(m.check_type, check_http)
            status, response_ms = checker(m.target)

            m.last_status = status
            m.last_response_ms = response_ms
            m.last_checked_at = now

            log.info("Monitor %s (%s): %s %dms", m.target, m.check_type, status, response_ms)

        db.commit()
    finally:
        db.close()


def main():
    log.info("Uptime monitor started")
    while running:
        try:
            run_checks()
        except Exception:
            log.exception("Monitor check cycle failed")
        time.sleep(30)


if __name__ == "__main__":
    main()
