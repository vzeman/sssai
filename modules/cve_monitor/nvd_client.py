"""
NVD (National Vulnerability Database) API client.
Queries the NVD REST API v2.0 for CVEs matching detected technologies.
API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
import time
from datetime import datetime, timezone

import httpx

log = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 6  # NVD rate limit: 5 requests per 30s without API key (6s gap is safe)


def _cvss_severity(score: float | None) -> str | None:
    """Map CVSS score to severity label."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def query_cves_by_keyword(
    keyword: str,
    version: str | None = None,
    published_after: datetime | None = None,
    api_key: str | None = None,
) -> list[dict]:
    """
    Query NVD for CVEs matching a technology keyword (and optional version).

    Returns a list of simplified CVE dicts:
        {
          "cve_id": str,
          "description": str,
          "cvss_score": float | None,
          "cvss_severity": str | None,
          "exploit_available": bool,
          "published_date": datetime,
        }
    """
    params: dict = {"keywordSearch": keyword, "resultsPerPage": 20}
    if published_after:
        params["pubStartDate"] = published_after.strftime("%Y-%m-%dT%H:%M:%S.000")
    if version:
        # Narrow by CPE version string when possible
        params["virtualMatchString"] = f"cpe:2.3:*:*:{keyword.lower()}:{version}:*:*:*:*:*:*:*"

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(NVD_BASE_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        log.warning("NVD API HTTP error for keyword=%s: %s", keyword, e)
        return []
    except Exception as e:
        log.warning("NVD API request failed for keyword=%s: %s", keyword, e)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract English description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS score (prefer v3.1 > v3.0 > v2)
        cvss_score: float | None = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                raw = cvss_data.get("baseScore")
                if raw is not None:
                    cvss_score = float(raw)
                break

        # Check for known exploits (via references or EPSS/KEV mentions)
        exploit_available = False
        for ref in cve.get("references", []):
            tags = ref.get("tags", [])
            if any(t in ("Exploit", "Exploit Code", "Proof of Concept") for t in tags):
                exploit_available = True
                break

        # Parse published date
        pub_str = cve.get("published", "")
        published_date: datetime | None = None
        if pub_str:
            try:
                published_date = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except Exception:
                pass

        results.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": _cvss_severity(cvss_score),
            "exploit_available": exploit_available,
            "published_date": published_date,
        })

        time.sleep(0.1)  # Small delay between parsing

    return results


def query_cves_by_cpe(
    cpe_name: str,
    published_after: datetime | None = None,
    api_key: str | None = None,
) -> list[dict]:
    """
    Query NVD for CVEs matching an exact CPE name.
    cpe_name format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """
    params: dict = {"cpeName": cpe_name, "resultsPerPage": 20}
    if published_after:
        params["pubStartDate"] = published_after.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(NVD_BASE_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        log.warning("NVD CPE query failed for cpe=%s: %s", cpe_name, e)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        cvss_score: float | None = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                raw = cvss_data.get("baseScore")
                if raw is not None:
                    cvss_score = float(raw)
                break

        exploit_available = False
        for ref in cve.get("references", []):
            tags = ref.get("tags", [])
            if any(t in ("Exploit", "Exploit Code", "Proof of Concept") for t in tags):
                exploit_available = True
                break

        pub_str = cve.get("published", "")
        published_date: datetime | None = None
        if pub_str:
            try:
                published_date = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except Exception:
                pass

        results.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": _cvss_severity(cvss_score),
            "exploit_available": exploit_available,
            "published_date": published_date,
        })

    return results
