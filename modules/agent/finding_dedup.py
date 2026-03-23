"""Finding deduplication and lifecycle tracking for the security scanner."""

import hashlib
import logging
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_SIMILARITY_THRESHOLD = 0.75  # title similarity required for a match


def _normalize_title(title: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    t = title.lower()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _url_domain(url: str) -> str:
    """Extract the netloc (host:port) from a URL; return the raw value on failure."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or url
    except Exception:
        return url


def _title_similarity(a: str, b: str) -> float:
    """Return a similarity score 0–1 for two finding titles."""
    return SequenceMatcher(None, _normalize_title(a), _normalize_title(b)).ratio()


def make_dedup_key(title: str, category: str, affected_url: str) -> str:
    """
    Create a stable dedup key for a finding.

    Uses: normalized-title + category + URL domain so that minor title
    rewording or path changes within the same host do not create duplicates.
    """
    norm_title = _normalize_title(title)
    norm_category = (category or "").lower().strip()
    norm_url = _url_domain(affected_url or "").lower()
    raw = f"{norm_title}|{norm_category}|{norm_url}"
    return hashlib.sha1(raw.encode()).hexdigest()


def _best_previous_match(
    finding: dict,
    previous_docs: list[dict],
) -> dict | None:
    """
    Return the best-matching previous ES document for *finding*, or None.

    Matching rules (all three must hold):
    1. category must match exactly (or both empty)
    2. affected_url domain must match (or both empty)
    3. title similarity ≥ _SIMILARITY_THRESHOLD
    """
    title = finding.get("title", "")
    category = (finding.get("category") or "").lower()
    affected_url = finding.get("affected_url") or (
        finding.get("affected_urls") or [""]
    )[0]
    url_domain = _url_domain(affected_url).lower()

    best_score = 0.0
    best_doc = None
    for doc in previous_docs:
        doc_category = (doc.get("category") or "").lower()
        if doc_category != category:
            continue
        doc_url = (doc.get("affected_url") or "").lower()
        doc_url_domain = _url_domain(doc_url).lower()
        if url_domain and doc_url_domain and url_domain != doc_url_domain:
            continue
        score = _title_similarity(title, doc.get("title", ""))
        if score >= _SIMILARITY_THRESHOLD and score > best_score:
            best_score = score
            best_doc = doc
    return best_doc


def deduplicate_findings(
    findings: list[dict],
    target: str,
    scan_id: str,
    now: str,
) -> tuple[list[dict], list[str]]:
    """
    Enrich *findings* with lifecycle fields and return IDs of resolved docs.

    Args:
        findings:  Raw findings from the current scan.
        target:    Scan target (used to query ES for previous findings).
        scan_id:   Current scan ID.
        now:       ISO-8601 timestamp for this scan.

    Returns:
        (enriched_findings, resolved_doc_ids)
        - enriched_findings: findings with finding_status, first_seen_*, last_seen_* set
        - resolved_doc_ids:  ES document IDs of previously-seen findings that are
                             no longer present (→ should be marked resolved).
    """
    try:
        from modules.infra.elasticsearch import search as es_search, get_client
    except Exception as exc:
        log.warning("finding_dedup: ES import failed: %s", exc)
        return _stamp_all_new(findings, scan_id, now), []

    # ── Fetch all active findings for this target from ES ────────────────
    try:
        result = es_search(
            "scanner-scan-findings",
            query={
                "bool": {
                    "filter": [
                        {"term": {"target": target}},
                        {"terms": {"finding_status": ["new", "existing", "regressed"]}},
                    ]
                }
            },
            size=1000,
            sort=[{"timestamp": "desc"}],
        )
        previous_docs_raw = result.get("hits", {}).get("hits", [])
        previous_docs = [
            {"_id": h["_id"], **h["_source"]} for h in previous_docs_raw
        ]
    except Exception as exc:
        log.warning("finding_dedup: ES query failed: %s", exc)
        return _stamp_all_new(findings, scan_id, now), []

    # De-duplicate the previous_docs list: keep only the most-recent doc per
    # dedup_key (ES may have accumulated multiple docs for the same finding).
    seen_keys: dict[str, dict] = {}
    for doc in previous_docs:
        key = doc.get("dedup_key") or make_dedup_key(
            doc.get("title", ""),
            doc.get("category", ""),
            doc.get("affected_url", ""),
        )
        if key not in seen_keys:
            seen_keys[key] = doc

    previous_unique = list(seen_keys.values())

    # ── Match current findings against previous ──────────────────────────
    matched_previous_ids: set[str] = set()
    enriched: list[dict] = []

    for f in findings:
        affected_url = (f.get("affected_urls") or [""])[0]
        dedup_key = make_dedup_key(f.get("title", ""), f.get("category", ""), affected_url)

        prev = _best_previous_match(f, previous_unique)

        if prev is None:
            # Brand-new finding
            status = "new"
            first_seen_scan_id = scan_id
            first_seen_date = now
        else:
            matched_previous_ids.add(prev["_id"])
            prev_status = prev.get("finding_status", "new")
            first_seen_scan_id = prev.get("first_seen_scan_id", prev.get("scan_id", scan_id))
            first_seen_date = prev.get("first_seen_date", prev.get("timestamp", now))
            if prev_status == "resolved":
                status = "regressed"
            else:
                status = "existing"

        enriched.append({
            **f,
            "affected_url": affected_url,
            "dedup_key": dedup_key,
            "finding_status": status,
            "first_seen_scan_id": first_seen_scan_id,
            "first_seen_date": first_seen_date,
            "last_seen_scan_id": scan_id,
        })

    # ── Compute resolved IDs ─────────────────────────────────────────────
    resolved_ids = [
        doc["_id"]
        for doc in previous_unique
        if doc["_id"] not in matched_previous_ids
    ]

    return enriched, resolved_ids


def _stamp_all_new(findings: list[dict], scan_id: str, now: str) -> list[dict]:
    """Fallback: mark all findings as 'new' when ES is unavailable."""
    result = []
    for f in findings:
        affected_url = (f.get("affected_urls") or [""])[0]
        result.append({
            **f,
            "affected_url": affected_url,
            "dedup_key": make_dedup_key(f.get("title", ""), f.get("category", ""), affected_url),
            "finding_status": "new",
            "first_seen_scan_id": scan_id,
            "first_seen_date": now,
            "last_seen_scan_id": scan_id,
        })
    return result


def mark_resolved_in_es(resolved_ids: list[str], scan_id: str, now: str) -> int:
    """
    Update ES documents for resolved findings.

    Sets finding_status = 'resolved' and last_seen_scan_id on each document.
    Returns the number of successfully updated documents.
    """
    if not resolved_ids:
        return 0
    try:
        from modules.infra.elasticsearch import get_client
        es = get_client()
        updated = 0
        for doc_id in resolved_ids:
            try:
                es.update(
                    index="scanner-scan-findings",
                    id=doc_id,
                    body={
                        "doc": {
                            "finding_status": "resolved",
                            "last_seen_scan_id": scan_id,
                            "resolved_date": now,
                        }
                    },
                )
                updated += 1
            except Exception as e:
                log.debug("mark_resolved_in_es: failed for doc %s: %s", doc_id, e)
        return updated
    except Exception as exc:
        log.warning("mark_resolved_in_es: %s", exc)
        return 0
