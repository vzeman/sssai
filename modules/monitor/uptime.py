"""Uptime monitor — periodically checks targets, records history, detects state changes."""

import logging
import signal
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from modules.api.database import SessionLocal
from modules.api.models import Monitor, MonitorCheck

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

running = True


def shutdown(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def check_http(target: str) -> tuple[str, int, int | None, str | None]:
    """Returns (status, response_ms, status_code, error)."""
    url = target if target.startswith("http") else f"https://{target}"
    try:
        r = httpx.get(url, timeout=15, follow_redirects=True)
        ms = int(r.elapsed.total_seconds() * 1000)
        if r.status_code < 400:
            return "up", ms, r.status_code, None
        else:
            return "degraded", ms, r.status_code, f"HTTP {r.status_code}"
    except httpx.TimeoutException:
        return "down", 0, None, "Connection timeout"
    except httpx.ConnectError as e:
        return "down", 0, None, f"Connection failed: {e}"
    except Exception as e:
        return "down", 0, None, str(e)[:500]


def check_tcp(target: str, port: int = 443) -> tuple[str, int, int | None, str | None]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    if ":" in host:
        host, port = host.rsplit(":", 1)
        port = int(port)
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return "up", int((time.time() - start) * 1000), None, None
    except Exception as e:
        return "down", 0, None, str(e)[:500]


def check_dns(target: str) -> tuple[str, int, int | None, str | None]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    start = time.time()
    try:
        socket.getaddrinfo(host, None)
        return "up", int((time.time() - start) * 1000), None, None
    except Exception as e:
        return "down", 0, None, str(e)[:500]


def check_tls(target: str) -> tuple[str, int, int | None, str | None]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    start = time.time()
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            ms = int((time.time() - start) * 1000)
            if days_left > 7:
                return "up", ms, None, None
            else:
                return "degraded", ms, None, f"TLS cert expires in {days_left} days"
    except Exception as e:
        return "down", 0, None, str(e)[:500]


CHECKERS = {"http": check_http, "tcp": check_tcp, "dns": check_dns, "tls": check_tls}


def run_checks():
    db: Session = SessionLocal()
    try:
        monitors = db.query(Monitor).filter(Monitor.is_active == True).all()
        now = datetime.now(timezone.utc)

        for m in monitors:
            # Respect interval
            if m.last_checked_at:
                elapsed = (now - m.last_checked_at.replace(tzinfo=timezone.utc)).total_seconds()
                if elapsed < m.interval_seconds:
                    continue

            checker = CHECKERS.get(m.check_type, check_http)
            status, response_ms, status_code, error = checker(m.target)

            prev_status = m.last_status

            # Update monitor
            m.last_status = status
            m.last_response_ms = response_ms
            m.last_checked_at = now

            # Record check history
            check = MonitorCheck(
                monitor_id=m.id,
                status=status,
                status_code=status_code,
                response_ms=response_ms,
                error=error,
                checked_at=now,
            )
            db.add(check)

            # Dual-write to Elasticsearch
            try:
                from modules.infra.elasticsearch import index_doc
                index_doc("scanner-monitor-checks", {
                    "timestamp": now.isoformat(),
                    "monitor_id": m.id,
                    "monitor_name": m.name or m.target,
                    "target": m.target,
                    "check_type": m.check_type,
                    "status": status,
                    "status_code": status_code,
                    "response_ms": response_ms,
                    "error": error,
                })
            except Exception:
                pass

            # Detect state change
            if prev_status and prev_status != status:
                if status == "down":
                    log.warning("ALERT: %s (%s) is DOWN — %s", m.name or m.target, m.target, error or "no response")
                elif status == "degraded":
                    log.warning("ALERT: %s (%s) is DEGRADED — %s", m.name or m.target, m.target, error or "slow/error")
                elif prev_status in ("down", "degraded") and status == "up":
                    log.info("RECOVERY: %s (%s) is back UP (%dms)", m.name or m.target, m.target, response_ms)
            else:
                log.info("Check: %s (%s): %s %dms", m.name or m.target, m.check_type, status, response_ms)

        db.commit()

        # Cleanup old checks (keep 30 days)
        cutoff = now - __import__("datetime").timedelta(days=30)
        db.query(MonitorCheck).filter(MonitorCheck.checked_at < cutoff).delete()
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
