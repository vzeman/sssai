"""
CVE monitoring background job.
Runs daily, queries NVD for new CVEs matching technologies in the asset inventory,
creates CveAlert records, and dispatches notifications.
"""

import asyncio
import logging
import os
import signal
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from modules.cve_monitor.nvd_client import query_cves_by_keyword, query_cves_by_cpe, _REQUEST_DELAY

log = logging.getLogger(__name__)

_DB_URL = os.environ.get("DATABASE_URL", "")
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # Optional — increases rate limit
_CVE_LOOKBACK_DAYS = int(os.environ.get("CVE_LOOKBACK_DAYS", "7"))  # How many days back to check for new CVEs
_AUTO_RESCAN = os.environ.get("CVE_AUTO_RESCAN", "false").lower() == "true"
_POLL_INTERVAL = int(os.environ.get("CVE_CHECK_INTERVAL_SECONDS", str(24 * 3600)))  # default: daily


class CveCheckerService:
    """Daily background job that checks NVD for CVEs affecting detected technologies."""

    def __init__(self, database_url: str, poll_interval: int = _POLL_INTERVAL):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.poll_interval = poll_interval
        self.running = True

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _shutdown(self, sig, frame):
        log.info("CVE checker shutting down...")
        self.running = False

    def run(self):
        log.info("CVE checker started (poll every %ds)", self.poll_interval)
        while self.running:
            try:
                self._check_all_assets()
            except Exception as e:
                log.exception("CVE checker error: %s", e)
            # Sleep in small chunks so SIGTERM is handled promptly
            for _ in range(self.poll_interval):
                if not self.running:
                    break
                time.sleep(1)

    def _check_all_assets(self):
        """Fetch all unique technologies from asset inventory and query NVD."""
        from modules.api.models import AssetInventory, CveAlert, NotificationChannel

        published_after = datetime.now(timezone.utc) - timedelta(days=_CVE_LOOKBACK_DAYS)

        with self.SessionLocal() as db:
            # Get all asset entries (grouped by user+technology+version)
            assets = db.query(AssetInventory).all()
            if not assets:
                log.info("No assets in inventory — nothing to check")
                return

            log.info("Checking CVEs for %d asset inventory entries", len(assets))

            # Track (user_id, technology_name, version) combos already processed
            # in this run to avoid duplicate NVD calls
            checked: set[tuple] = set()

            for asset in assets:
                key = (asset.technology_name, asset.technology_version or "")
                if key in checked:
                    continue
                checked.add(key)

                cves = self._fetch_cves_for_asset(asset, published_after)

                for cve_data in cves:
                    self._upsert_cve_alert(db, asset, cve_data)

                # Respect NVD rate limit between assets
                time.sleep(_REQUEST_DELAY)

            db.commit()

        # Now send notifications for unsent alerts
        self._send_pending_notifications()

    def _fetch_cves_for_asset(self, asset, published_after: datetime) -> list[dict]:
        """Query NVD for CVEs matching this asset's technology."""
        cves: list[dict] = []

        # If CPE entries are available, use precise CPE-based lookup
        if asset.cpe_entries:
            for cpe in asset.cpe_entries:
                try:
                    results = query_cves_by_cpe(
                        cpe,
                        published_after=published_after,
                        api_key=_NVD_API_KEY or None,
                    )
                    cves.extend(results)
                except Exception as e:
                    log.warning("CPE query failed for %s: %s", cpe, e)
        else:
            # Fall back to keyword search
            keyword = asset.technology_name
            version = asset.technology_version
            try:
                results = query_cves_by_keyword(
                    keyword,
                    version=version,
                    published_after=published_after,
                    api_key=_NVD_API_KEY or None,
                )
                cves.extend(results)
            except Exception as e:
                log.warning("Keyword CVE query failed for %s: %s", keyword, e)

        return cves

    def _upsert_cve_alert(self, db: Session, asset, cve_data: dict):
        """Insert a CVE alert if it doesn't already exist for this asset+CVE pair."""
        from modules.api.models import CveAlert

        cve_id = cve_data.get("cve_id", "")
        if not cve_id:
            return

        # Check if alert already exists
        existing = db.query(CveAlert).filter(
            CveAlert.asset_id == asset.id,
            CveAlert.cve_id == cve_id,
        ).first()

        if existing:
            return  # Already recorded

        log.info(
            "New CVE %s affects %s %s on %s (CVSS: %s)",
            cve_id, asset.technology_name, asset.technology_version or "?",
            asset.target, cve_data.get("cvss_score"),
        )

        alert = CveAlert(
            user_id=asset.user_id,
            asset_id=asset.id,
            cve_id=cve_id,
            technology_name=asset.technology_name,
            technology_version=asset.technology_version,
            cvss_score=cve_data.get("cvss_score"),
            cvss_severity=cve_data.get("cvss_severity"),
            description=cve_data.get("description"),
            exploit_available=cve_data.get("exploit_available", False),
            affected_endpoints=None,  # Populated from asset inventory context if available
            published_date=cve_data.get("published_date"),
        )
        db.add(alert)

        # Optionally trigger an automatic re-scan
        if _AUTO_RESCAN:
            self._trigger_rescan(db, asset, alert)

    def _trigger_rescan(self, db: Session, asset, alert):
        """Enqueue a targeted re-scan to verify CVE exposure."""
        try:
            from modules.api.models import Scan
            from modules.infra import get_queue
            import uuid

            scan_id = str(uuid.uuid4())
            scan = Scan(
                id=scan_id,
                user_id=asset.user_id,
                target=asset.target,
                scan_type="security",
                config={
                    "cve_triggered": True,
                    "cve_id": alert.cve_id,
                    "technology": asset.technology_name,
                    "technology_version": asset.technology_version,
                },
            )
            db.add(scan)
            get_queue().send("scan-jobs", {
                "scan_id": scan_id,
                "target": asset.target,
                "scan_type": "security",
                "config": scan.config,
            })
            alert.auto_rescan_triggered = True
            alert.rescan_id = scan_id
            log.info("Auto-triggered re-scan %s for CVE %s on %s", scan_id, alert.cve_id, asset.target)
        except Exception as e:
            log.warning("Could not trigger auto-rescan for CVE %s: %s", alert.cve_id, e)

    def _send_pending_notifications(self):
        """Send notifications for CVE alerts that haven't been notified yet."""
        from modules.api.models import CveAlert, AssetInventory, NotificationChannel
        from modules.notifications.dispatcher import NotificationDispatcher, Notification

        with self.SessionLocal() as db:
            # Get all unnotified alerts grouped by user
            unsent = (
                db.query(CveAlert)
                .filter(CveAlert.notification_sent == False)
                .all()
            )
            if not unsent:
                return

            log.info("Sending notifications for %d new CVE alerts", len(unsent))

            # Group by user
            by_user: dict[str, list] = {}
            for alert in unsent:
                by_user.setdefault(alert.user_id, []).append(alert)

            for user_id, alerts in by_user.items():
                # Load user's notification channels
                channels_rows = db.query(NotificationChannel).filter(
                    NotificationChannel.user_id == user_id,
                    NotificationChannel.is_active == True,
                ).all()

                if not channels_rows:
                    # No channels configured — mark as notified to avoid re-checking
                    for alert in alerts:
                        alert.notification_sent = True
                    continue

                channels = [
                    {
                        "type": ch.channel_type,
                        "config": ch.config,
                        "min_severity": ch.min_severity,
                    }
                    for ch in channels_rows
                ]

                for alert in alerts:
                    # Determine notification severity from CVSS
                    if alert.cvss_score and alert.cvss_score >= 9.0:
                        sev = "critical"
                    elif alert.cvss_score and alert.cvss_score >= 7.0:
                        sev = "critical"
                    elif alert.cvss_score and alert.cvss_score >= 4.0:
                        sev = "warning"
                    else:
                        sev = "info"

                    # Load target from asset
                    asset = db.query(AssetInventory).filter(AssetInventory.id == alert.asset_id).first()
                    target = asset.target if asset else "unknown"

                    version_str = f" {alert.technology_version}" if alert.technology_version else ""
                    title = (
                        f"New {alert.cvss_severity or 'CVE'}: {alert.cve_id} affects "
                        f"{alert.technology_name}{version_str} on {target}"
                    )

                    lines = [alert.description or "No description available."]
                    if alert.cvss_score is not None:
                        lines.append(f"CVSS Score: {alert.cvss_score} ({alert.cvss_severity})")
                    if alert.exploit_available:
                        lines.append("⚠️  Exploit code publicly available")
                    if alert.affected_endpoints:
                        lines.append(f"Affected endpoints: {', '.join(alert.affected_endpoints[:5])}")
                    if alert.auto_rescan_triggered and alert.rescan_id:
                        lines.append(f"Auto-triggered re-scan: {alert.rescan_id}")

                    notification = Notification(
                        title=title,
                        message="\n".join(lines),
                        severity=sev,
                        target=target,
                        metadata={
                            "cve_id": alert.cve_id,
                            "technology": alert.technology_name,
                            "version": alert.technology_version,
                            "cvss_score": alert.cvss_score,
                            "exploit_available": alert.exploit_available,
                        },
                    )

                    dispatcher = NotificationDispatcher(channels)
                    try:
                        asyncio.run(dispatcher.dispatch(notification))
                    except Exception as e:
                        log.warning("Failed to dispatch CVE notification for %s: %s", alert.cve_id, e)

                    alert.notification_sent = True

            db.commit()
