"""Elasticsearch-powered search and analytics endpoints."""

from fastapi import APIRouter, Depends, Query
from modules.api.auth import get_current_user
from modules.api.models import User
from modules.infra.elasticsearch import search, get_client

router = APIRouter()


@router.get("/findings")
def search_findings(
    q: str = Query("", description="Search query"),
    severity: str = Query("", description="Filter by severity: critical,high,medium,low,info"),
    scan_type: str = Query("", description="Filter by scan type"),
    target: str = Query("", description="Filter by target"),
    scan_id: str = Query("", description="Filter by scan ID"),
    size: int = Query(50, le=200),
    page: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
):
    """Full-text search across all scan findings."""
    must = []
    if q:
        must.append({"multi_match": {
            "query": q,
            "fields": ["title^3", "description^2", "remediation", "evidence", "category"],
            "fuzziness": "AUTO",
        }})
    filters = []
    if severity:
        filters.append({"terms": {"severity": severity.split(",")}})
    if scan_type:
        filters.append({"term": {"scan_type": scan_type}})
    if target:
        filters.append({"match_phrase_prefix": {"target": target}})
    if scan_id:
        filters.append({"term": {"scan_id": scan_id}})

    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filters}}
    result = search(
        "scanner-scan-findings", query,
        size=size, from_=page * size,
        sort=[{"timestamp": "desc"}],
        aggs={
            "severity_counts": {"terms": {"field": "severity"}},
            "scan_type_counts": {"terms": {"field": "scan_type"}},
            "top_targets": {"terms": {"field": "target", "size": 10}},
        },
    )

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    return {
        "total": hits.get("total", {}).get("value", 0),
        "findings": [h["_source"] for h in hits.get("hits", [])],
        "aggregations": {
            "severity": {b["key"]: b["doc_count"] for b in aggs.get("severity_counts", {}).get("buckets", [])},
            "scan_types": {b["key"]: b["doc_count"] for b in aggs.get("scan_type_counts", {}).get("buckets", [])},
            "targets": {b["key"]: b["doc_count"] for b in aggs.get("top_targets", {}).get("buckets", [])},
        },
    }


@router.get("/logs")
def search_logs(
    q: str = Query("", description="Search query"),
    level: str = Query("", description="Filter by level: INFO,WARNING,ERROR"),
    service: str = Query("", description="Filter by service"),
    scan_id: str = Query("", description="Filter by scan ID"),
    hours: int = Query(24, le=720),
    size: int = Query(100, le=500),
    user: User = Depends(get_current_user),
):
    """Search worker logs."""
    must = []
    if q:
        must.append({"match": {"message": {"query": q, "fuzziness": "AUTO"}}})
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]
    if level:
        filters.append({"terms": {"level.keyword": level.upper().split(",")}})
    if service:
        filters.append({"term": {"service.keyword": service}})
    if scan_id:
        filters.append({"term": {"scan_id.keyword": scan_id}})

    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filters}}
    result = search(
        "scanner-worker-logs", query,
        size=size, sort=[{"timestamp": "desc"}],
        aggs={"level_counts": {"terms": {"field": "level.keyword"}}},
    )

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    return {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
        "levels": {b["key"]: b["doc_count"] for b in aggs.get("level_counts", {}).get("buckets", [])},
    }


@router.get("/activity")
def search_activity(
    q: str = Query("", description="Search query"),
    scan_id: str = Query("", description="Filter by scan ID"),
    tool: str = Query("", description="Filter by tool name"),
    hours: int = Query(24, le=720),
    size: int = Query(100, le=500),
    user: User = Depends(get_current_user),
):
    """Search scan activity (commands executed, tools used)."""
    must = []
    if q:
        must.append({"multi_match": {
            "query": q,
            "fields": ["message^2", "command", "output"],
            "fuzziness": "AUTO",
        }})
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]
    if scan_id:
        filters.append({"term": {"scan_id": scan_id}})
    if tool:
        filters.append({"term": {"tool": tool}})

    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filters}}
    result = search(
        "scanner-scan-activity", query,
        size=size, sort=[{"timestamp": "desc"}],
        aggs={"tools_used": {"terms": {"field": "tool", "size": 20}}},
    )

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    return {
        "total": hits.get("total", {}).get("value", 0),
        "activities": [h["_source"] for h in hits.get("hits", [])],
        "tools": {b["key"]: b["doc_count"] for b in aggs.get("tools_used", {}).get("buckets", [])},
    }


@router.get("/chat")
def search_chat(
    q: str = Query("", description="Search query"),
    role: str = Query("", description="Filter by role: human,agent"),
    channel: str = Query("", description="Filter by channel: global,scan"),
    scan_id: str = Query("", description="Filter by scan ID"),
    hours: int = Query(168, le=720),
    size: int = Query(50, le=200),
    user: User = Depends(get_current_user),
):
    """Search chat messages across all channels."""
    must = []
    if q:
        must.append({"match": {"message": {"query": q, "fuzziness": "AUTO"}}})
    filters = [
        {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        {"term": {"user_id": user.id}},
    ]
    if role:
        filters.append({"term": {"role": role}})
    if channel:
        filters.append({"term": {"channel": channel}})
    if scan_id:
        filters.append({"term": {"scan_id": scan_id}})

    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filters}}
    result = search(
        "scanner-chat-messages", query,
        size=size, sort=[{"timestamp": "desc"}],
    )

    hits = result.get("hits", {})
    return {
        "total": hits.get("total", {}).get("value", 0),
        "messages": [h["_source"] for h in hits.get("hits", [])],
    }


@router.get("/global")
def global_search(
    q: str = Query("", description="Search query (empty = recent items)"),
    size: int = Query(20, le=100),
    user: User = Depends(get_current_user),
):
    """Search across all indices — findings, logs, chat, activity. Empty query returns recent items."""
    results = {}
    per_section = size // 4 + 1

    if q:
        findings_query = {"bool": {"must": [{"multi_match": {
            "query": q,
            "fields": ["title^3", "description^2", "remediation", "evidence"],
            "fuzziness": "AUTO",
        }}]}}
        logs_query = {"bool": {"must": [{"match": {"message": q}}]}}
        activity_query = {"bool": {"must": [{"multi_match": {"query": q, "fields": ["message", "command", "output"]}}]}}
        chat_query = {"bool": {"must": [{"match": {"message": q}}], "filter": [{"term": {"user_id": user.id}}]}}
    else:
        findings_query = {"match_all": {}}
        logs_query = {"match_all": {}}
        activity_query = {"match_all": {}}
        chat_query = {"bool": {"filter": [{"term": {"user_id": user.id}}]}}

    # Search findings
    findings_result = search(
        "scanner-scan-findings", findings_query,
        size=per_section, sort=[{"timestamp": "desc"}],
    )
    results["findings"] = {
        "total": findings_result.get("hits", {}).get("total", {}).get("value", 0),
        "items": [h["_source"] for h in findings_result.get("hits", {}).get("hits", [])],
    }

    # Search logs
    logs_result = search(
        "scanner-worker-logs", logs_query,
        size=per_section, sort=[{"timestamp": "desc"}],
    )
    results["logs"] = {
        "total": logs_result.get("hits", {}).get("total", {}).get("value", 0),
        "items": [h["_source"] for h in logs_result.get("hits", {}).get("hits", [])],
    }

    # Search activity
    activity_result = search(
        "scanner-scan-activity", activity_query,
        size=per_section, sort=[{"timestamp": "desc"}],
    )
    results["activity"] = {
        "total": activity_result.get("hits", {}).get("total", {}).get("value", 0),
        "items": [h["_source"] for h in activity_result.get("hits", {}).get("hits", [])],
    }

    # Search chat
    chat_result = search(
        "scanner-chat-messages", chat_query,
        size=per_section, sort=[{"timestamp": "desc"}],
    )
    results["chat"] = {
        "total": chat_result.get("hits", {}).get("total", {}).get("value", 0),
        "items": [h["_source"] for h in chat_result.get("hits", {}).get("hits", [])],
    }

    return results


@router.get("/analytics/findings")
def findings_analytics(
    days: int = Query(30, le=90),
    user: User = Depends(get_current_user),
):
    """Aggregated analytics for scan findings — severity trends, top categories, etc."""
    query = {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]}}
    result = search(
        "scanner-scan-findings", query, size=0,
        aggs={
            "severity_over_time": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "day"},
                "aggs": {"by_severity": {"terms": {"field": "severity"}}},
            },
            "top_categories": {"terms": {"field": "category", "size": 20}},
            "top_titles": {"terms": {"field": "title.raw", "size": 20}},
            "by_scan_type": {"terms": {"field": "scan_type"}},
            "by_target": {"terms": {"field": "target", "size": 10}},
            "avg_risk": {"avg": {"field": "risk_score"}},
            "severity_dist": {"terms": {"field": "severity"}},
        },
    )

    aggs = result.get("aggregations", {})

    # Format timeline
    timeline = []
    for bucket in aggs.get("severity_over_time", {}).get("buckets", []):
        day_data = {"date": bucket["key_as_string"], "total": bucket["doc_count"]}
        for sev in bucket.get("by_severity", {}).get("buckets", []):
            day_data[sev["key"]] = sev["doc_count"]
        timeline.append(day_data)

    return {
        "timeline": timeline,
        "categories": {b["key"]: b["doc_count"] for b in aggs.get("top_categories", {}).get("buckets", [])},
        "top_findings": {b["key"]: b["doc_count"] for b in aggs.get("top_titles", {}).get("buckets", [])},
        "by_scan_type": {b["key"]: b["doc_count"] for b in aggs.get("by_scan_type", {}).get("buckets", [])},
        "by_target": {b["key"]: b["doc_count"] for b in aggs.get("by_target", {}).get("buckets", [])},
        "avg_risk_score": aggs.get("avg_risk", {}).get("value"),
        "severity_distribution": {b["key"]: b["doc_count"] for b in aggs.get("severity_dist", {}).get("buckets", [])},
    }


@router.get("/analytics/lifecycle")
def lifecycle_analytics(
    days: int = Query(30, le=90),
    target: str = Query("", description="Filter by target"),
    user: User = Depends(get_current_user),
):
    """Finding lifecycle analytics — new/existing/resolved/regressed counts and trends."""
    filters: list[dict] = [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]
    if target:
        filters.append({"match_phrase_prefix": {"target": target}})

    query = {"bool": {"filter": filters}}
    result = search(
        "scanner-scan-findings", query, size=0,
        aggs={
            "status_distribution": {"terms": {"field": "finding_status", "size": 10}},
            "status_over_time": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "day"},
                "aggs": {"by_status": {"terms": {"field": "finding_status", "size": 10}}},
            },
            "top_recurring": {
                "filter": {"terms": {"finding_status": ["existing", "regressed"]}},
                "aggs": {"titles": {"terms": {"field": "title.raw", "size": 10}}},
            },
            "regression_rate_base": {
                "filter": {"term": {"finding_status": "resolved"}},
            },
            "regression_count": {
                "filter": {"term": {"finding_status": "regressed"}},
            },
        },
    )

    aggs = result.get("aggregations", {})

    status_dist = {
        b["key"]: b["doc_count"]
        for b in aggs.get("status_distribution", {}).get("buckets", [])
    }

    timeline = []
    for bucket in aggs.get("status_over_time", {}).get("buckets", []):
        day_data: dict = {"date": bucket["key_as_string"], "total": bucket["doc_count"]}
        for s in bucket.get("by_status", {}).get("buckets", []):
            day_data[s["key"]] = s["doc_count"]
        timeline.append(day_data)

    top_recurring = {
        b["key"]: b["doc_count"]
        for b in aggs.get("top_recurring", {}).get("titles", {}).get("buckets", [])
    }

    resolved_count = aggs.get("regression_rate_base", {}).get("doc_count", 0)
    regressed_count = aggs.get("regression_count", {}).get("doc_count", 0)
    regression_rate = (
        round(regressed_count / (resolved_count + regressed_count) * 100, 1)
        if (resolved_count + regressed_count) > 0
        else 0
    )

    return {
        "status_distribution": status_dist,
        "timeline": timeline,
        "top_recurring_findings": top_recurring,
        "regression_rate_pct": regression_rate,
    }


@router.get("/analytics/mttr")
def mttr_analytics(
    days: int = Query(90, le=365),
    user: User = Depends(get_current_user),
):
    """Mean Time to Remediate per severity level (days from first_seen to resolved)."""
    try:
        es = get_client()
        # Use scripted metric to compute MTTR per severity
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"finding_status": "resolved"}},
                        {"exists": {"field": "first_seen_date"}},
                        {"exists": {"field": "resolved_date"}},
                        {"range": {"resolved_date": {"gte": f"now-{days}d"}}},
                    ]
                }
            },
            "aggs": {
                "by_severity": {
                    "terms": {"field": "severity", "size": 10},
                    "aggs": {
                        "avg_days_to_fix": {
                            "avg": {
                                "script": {
                                    "source": """
                                        if (doc.containsKey('resolved_date') && doc.containsKey('first_seen_date')
                                            && !doc['resolved_date'].empty && !doc['first_seen_date'].empty) {
                                            return (doc['resolved_date'].value.toInstant().toEpochMilli()
                                                    - doc['first_seen_date'].value.toInstant().toEpochMilli())
                                                   / 86400000.0;
                                        }
                                        return null;
                                    """
                                }
                            }
                        },
                        "count": {"value_count": {"field": "severity"}},
                    },
                }
            },
        }
        resp = es.search(index="scanner-scan-findings", body=body)
        aggs = resp.get("aggregations", {})
        mttr: dict = {}
        for bucket in aggs.get("by_severity", {}).get("buckets", []):
            avg = bucket.get("avg_days_to_fix", {}).get("value")
            mttr[bucket["key"]] = {
                "avg_days": round(avg, 1) if avg is not None else None,
                "resolved_count": bucket.get("count", {}).get("value", 0),
            }
        return {"mttr_by_severity": mttr, "days_window": days}
    except Exception as e:
        import logging as _log
        _log.getLogger(__name__).warning("mttr_analytics failed: %s", e)
        return {"mttr_by_severity": {}, "days_window": days}


@router.get("/analytics/uptime")
def uptime_analytics(
    days: int = Query(7, le=30),
    monitor_id: str = Query("", description="Filter by monitor ID"),
    user: User = Depends(get_current_user),
):
    """Uptime analytics — response time trends, availability percentages."""
    filters = [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]
    if monitor_id:
        filters.append({"term": {"monitor_id": monitor_id}})

    query = {"bool": {"filter": filters}}
    result = search(
        "scanner-monitor-checks", query, size=0,
        aggs={
            "response_time_over_time": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "1h"},
                "aggs": {
                    "avg_ms": {"avg": {"field": "response_ms"}},
                    "max_ms": {"max": {"field": "response_ms"}},
                },
            },
            "by_status": {"terms": {"field": "status"}},
            "by_monitor": {
                "terms": {"field": "monitor_name", "size": 50},
                "aggs": {
                    "avg_ms": {"avg": {"field": "response_ms"}},
                    "status_breakdown": {"terms": {"field": "status"}},
                },
            },
            "avg_response": {"avg": {"field": "response_ms"}},
            "p95_response": {"percentiles": {"field": "response_ms", "percents": [50, 95, 99]}},
        },
    )

    aggs = result.get("aggregations", {})

    timeline = []
    for bucket in aggs.get("response_time_over_time", {}).get("buckets", []):
        timeline.append({
            "time": bucket["key_as_string"],
            "avg_ms": bucket.get("avg_ms", {}).get("value"),
            "max_ms": bucket.get("max_ms", {}).get("value"),
            "checks": bucket["doc_count"],
        })

    monitors = []
    for bucket in aggs.get("by_monitor", {}).get("buckets", []):
        status_map = {s["key"]: s["doc_count"] for s in bucket.get("status_breakdown", {}).get("buckets", [])}
        total = bucket["doc_count"]
        up = status_map.get("up", 0)
        monitors.append({
            "name": bucket["key"],
            "total_checks": total,
            "avg_ms": bucket.get("avg_ms", {}).get("value"),
            "uptime_pct": round(up / total * 100, 2) if total > 0 else None,
            "status_breakdown": status_map,
        })

    return {
        "timeline": timeline,
        "status_distribution": {b["key"]: b["doc_count"] for b in aggs.get("by_status", {}).get("buckets", [])},
        "monitors": monitors,
        "avg_response_ms": aggs.get("avg_response", {}).get("value"),
        "percentiles": aggs.get("p95_response", {}).get("values", {}),
    }


@router.get("/analytics/scans")
def scan_analytics(
    days: int = Query(30, le=90),
    user: User = Depends(get_current_user),
):
    """Scan activity analytics — scans over time, tool usage, etc."""
    query = {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]}}
    result = search(
        "scanner-scan-activity", query, size=0,
        aggs={
            "activity_over_time": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "day"},
            },
            "tools_used": {"terms": {"field": "tool", "size": 30}},
            "by_scan": {"terms": {"field": "scan_id", "size": 20}},
        },
    )

    aggs = result.get("aggregations", {})
    return {
        "timeline": [
            {"date": b["key_as_string"], "activities": b["doc_count"]}
            for b in aggs.get("activity_over_time", {}).get("buckets", [])
        ],
        "tools": {b["key"]: b["doc_count"] for b in aggs.get("tools_used", {}).get("buckets", [])},
        "scans": {b["key"]: b["doc_count"] for b in aggs.get("by_scan", {}).get("buckets", [])},
    }
