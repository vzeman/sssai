"""Elasticsearch client singleton and helpers for the scanner platform."""

import logging
import os
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)

_ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
_client: Elasticsearch | None = None


def get_client() -> Elasticsearch:
    """Return a shared ES client (lazy singleton)."""
    global _client
    if _client is None:
        _client = Elasticsearch(_ES_URL, request_timeout=30)
    return _client


def index_doc(index: str, body: dict, doc_id: str | None = None) -> str | None:
    """Index a single document. Returns the doc ID or None on failure."""
    try:
        es = get_client()
        resp = es.index(index=index, id=doc_id, document=body)
        return resp.get("_id")
    except Exception as e:
        log.warning("ES index_doc failed (%s): %s", index, e)
        return None


def search(index: str, query: dict, size: int = 50, sort: list | None = None,
           aggs: dict | None = None, from_: int = 0) -> dict:
    """Run a search query. Returns the raw ES response body."""
    try:
        es = get_client()
        body: dict[str, Any] = {"query": query, "size": size, "from": from_}
        if sort:
            body["sort"] = sort
        if aggs:
            body["aggs"] = aggs
        return es.search(index=index, body=body)
    except Exception as e:
        log.warning("ES search failed (%s): %s", index, e)
        return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}


def bulk_index(index: str, docs: list[dict]) -> int:
    """Bulk-index documents. Returns count of successfully indexed docs."""
    if not docs:
        return 0
    try:
        from elasticsearch.helpers import bulk
        es = get_client()
        actions = [{"_index": index, "_source": doc} for doc in docs]
        success, _ = bulk(es, actions, raise_on_error=False)
        return success
    except Exception as e:
        log.warning("ES bulk_index failed (%s): %s", index, e)
        return 0


def delete_by_query(index: str, query: dict) -> int:
    """Delete documents matching a query. Returns deleted count."""
    try:
        es = get_client()
        resp = es.delete_by_query(index=index, body={"query": query})
        return resp.get("deleted", 0)
    except Exception as e:
        log.warning("ES delete_by_query failed (%s): %s", index, e)
        return 0


# ─── Index definitions ──────────────────────────────────────────────

INDEX_SETTINGS = {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "5s",
}

INDICES = {
    "scanner-worker-logs": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "level": {"type": "keyword"},
                "message": {"type": "text", "analyzer": "standard"},
                "service": {"type": "keyword"},
                "scan_id": {"type": "keyword"},
                "task_id": {"type": "keyword"},
            }
        },
    },
    "scanner-scan-activity": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "scan_id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "tool": {"type": "keyword"},
                "action": {"type": "keyword"},
                "message": {"type": "text"},
                "command": {"type": "text"},
                "output": {"type": "text"},
                "status": {"type": "keyword"},
                "duration_ms": {"type": "integer"},
            }
        },
    },
    "scanner-chat-messages": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "user_id": {"type": "keyword"},
                "scan_id": {"type": "keyword"},
                "role": {"type": "keyword"},
                "message": {"type": "text", "analyzer": "standard"},
                "msg_type": {"type": "keyword"},
                "channel": {"type": "keyword"},
            }
        },
    },
    "scanner-monitor-checks": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "monitor_id": {"type": "keyword"},
                "monitor_name": {"type": "keyword"},
                "target": {"type": "keyword"},
                "check_type": {"type": "keyword"},
                "status": {"type": "keyword"},
                "status_code": {"type": "integer"},
                "response_ms": {"type": "integer"},
                "error": {"type": "text"},
            }
        },
    },
    "scanner-scan-findings": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "scan_id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "target": {"type": "keyword"},
                "scan_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "description": {"type": "text"},
                "category": {"type": "keyword"},
                "remediation": {"type": "text"},
                "cvss_score": {"type": "float"},
                "cve_id": {"type": "keyword"},
                "tool": {"type": "keyword"},
                "evidence": {"type": "text"},
                "risk_score": {"type": "float"},
                # Lifecycle / deduplication fields
                "finding_status": {"type": "keyword"},      # new | existing | resolved | regressed
                "dedup_key": {"type": "keyword"},           # sha1(title+category+url_domain)
                "affected_url": {"type": "keyword"},        # primary affected URL
                "first_seen_scan_id": {"type": "keyword"},
                "first_seen_date": {"type": "date"},
                "last_seen_scan_id": {"type": "keyword"},
                "resolved_date": {"type": "date"},
            }
        },
    },
    "scanner-validations": {
        "settings": INDEX_SETTINGS,
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "task_id": {"type": "keyword"},
                "scan_id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "target": {"type": "keyword"},
                "finding": {"type": "text"},
                "validated": {"type": "boolean"},
                "severity": {"type": "keyword"},
                "summary": {"type": "text"},
                "proof_of_concept": {"type": "text"},
                "risk_rating": {"type": "keyword"},
                "status": {"type": "keyword"},
            }
        },
    },
}


# ─── ILM policies ───────────────────────────────────────────────────

ILM_POLICIES = {
    "scanner-logs-policy": {
        "policy": {
            "phases": {
                "hot": {"actions": {"rollover": {"max_age": "7d", "max_size": "1gb"}}},
                "warm": {"min_age": "7d", "actions": {"shrink": {"number_of_shards": 1}}},
                "delete": {"min_age": "30d", "actions": {"delete": {}}},
            }
        }
    },
    "scanner-data-policy": {
        "policy": {
            "phases": {
                "hot": {"actions": {"rollover": {"max_age": "30d", "max_size": "5gb"}}},
                "warm": {"min_age": "30d", "actions": {}},
                "delete": {"min_age": "90d", "actions": {"delete": {}}},
            }
        }
    },
}


def setup_indices():
    """Create indices and ILM policies if they don't exist."""
    try:
        es = get_client()
        if not es.ping():
            log.warning("Elasticsearch not reachable, skipping index setup")
            return False

        # Create ILM policies
        for name, policy in ILM_POLICIES.items():
            try:
                es.ilm.put_lifecycle(name=name, body=policy)
                log.info("ILM policy created/updated: %s", name)
            except Exception as e:
                log.warning("ILM policy %s: %s", name, e)

        # Create indices
        for name, config in INDICES.items():
            try:
                if not es.indices.exists(index=name):
                    es.indices.create(index=name, body=config)
                    log.info("Index created: %s", name)
                else:
                    # Update mapping if index exists
                    es.indices.put_mapping(index=name, body=config["mappings"])
                    log.info("Index mapping updated: %s", name)
            except Exception as e:
                log.warning("Index %s: %s", name, e)

        log.info("Elasticsearch index setup complete")
        return True
    except Exception as e:
        log.warning("Elasticsearch setup failed: %s", e)
        return False
