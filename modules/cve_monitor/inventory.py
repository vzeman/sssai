"""
Utility functions for updating the asset inventory from completed scan reports.
Called by the worker after each scan completes.
"""

import logging
import re
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Common technology name normalizations
_TECH_ALIASES: dict[str, str] = {
    "apache httpd": "Apache HTTP Server",
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
    "php": "PHP",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "react": "React",
    "angular": "Angular",
    "vue.js": "Vue.js",
    "node.js": "Node.js",
    "express": "Express.js",
    "django": "Django",
    "flask": "Flask",
    "laravel": "Laravel",
    "ruby on rails": "Ruby on Rails",
    "spring": "Spring Framework",
    "tomcat": "Apache Tomcat",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
}

_VERSION_RE = re.compile(r"[\d]+(?:\.[\d]+)*")


def _normalize_technology(raw: str) -> tuple[str, str | None]:
    """
    Parse a raw technology string like "Apache/2.4.51" or "PHP 8.1.2"
    into (technology_name, version).
    """
    raw = raw.strip()

    # Try splitting on common separators
    name = raw
    version: str | None = None

    for sep in ("/", " "):
        parts = raw.split(sep, 1)
        if len(parts) == 2 and _VERSION_RE.match(parts[1].strip()):
            name = parts[0].strip()
            version = parts[1].strip()
            break

    # Normalize name
    name_lower = name.lower()
    name = _TECH_ALIASES.get(name_lower, name)

    return name, version


def _build_cpe_entries(name: str, version: str | None) -> list[str] | None:
    """Build candidate CPE 2.3 identifiers for NVD lookup."""
    if not version:
        return None
    name_slug = name.lower().replace(" ", "_").replace(".", "")
    # Rough CPE format — NVD will validate the exact match
    return [f"cpe:2.3:a:*:{name_slug}:{version}:*:*:*:*:*:*:*"]


def store_technologies_from_report(
    scan_id: str,
    user_id: str,
    target: str,
    report: dict,
    db_url: str,
):
    """
    Extract technologies_detected from a completed scan report and persist
    them into the asset_inventory table.

    This is designed to be called from the worker process (no ORM session
    passed in — creates its own DB connection).
    """
    technologies: list[str] = report.get("technologies_detected", [])
    if not technologies:
        # Also check the attack surface metadata if available
        attack_surface = report.get("attack_surface", {})
        if attack_surface:
            technologies = attack_surface.get("technologies", [])

    if not technologies:
        log.debug("No technologies found in report for scan %s", scan_id)
        return

    if not db_url:
        log.warning("No DATABASE_URL configured — cannot store technology inventory")
        return

    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from modules.api.models import AssetInventory

        engine = create_engine(db_url)
        SessionLocal = sessionmaker(bind=engine)
        now = datetime.now(timezone.utc)

        with SessionLocal() as db:
            for raw_tech in technologies:
                if not raw_tech or not isinstance(raw_tech, str):
                    continue

                tech_name, tech_version = _normalize_technology(raw_tech)
                cpe_entries = _build_cpe_entries(tech_name, tech_version)

                # Check if an entry already exists for this user+target+technology
                existing = db.query(AssetInventory).filter(
                    AssetInventory.user_id == user_id,
                    AssetInventory.target == target,
                    AssetInventory.technology_name == tech_name,
                ).first()

                if existing:
                    existing.last_seen = now
                    if tech_version and existing.technology_version != tech_version:
                        existing.technology_version = tech_version
                    if cpe_entries and not existing.cpe_entries:
                        existing.cpe_entries = cpe_entries
                    existing.scan_id = scan_id
                else:
                    entry = AssetInventory(
                        user_id=user_id,
                        scan_id=scan_id,
                        target=target,
                        asset_type="technology",  # technology type for CVE matching
                        technology_name=tech_name,
                        technology_version=tech_version,
                        cpe_entries=cpe_entries,
                        first_seen=now,
                        last_seen=now,
                    )
                    db.add(entry)

            db.commit()
            log.info(
                "Stored %d technologies for scan %s (target: %s)",
                len(technologies), scan_id, target,
            )
    except Exception as e:
        log.warning("Failed to store technology inventory for scan %s: %s", scan_id, e)
