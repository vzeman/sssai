"""Security posture score API endpoints.

Provides per-target and aggregate posture scores, historical sparkline data,
trend analysis, and AI-generated weekly security briefs.
"""

from fastapi import APIRouter, Depends, Query
from modules.api.auth import get_current_user
from modules.api.models import User
from modules.infra.elasticsearch import search

router = APIRouter()

_INDEX = "scanner-security-posture"


@router.get("")
def get_posture_summary(
    days: int = Query(30, le=90, description="Lookback window in days"),
    user: User = Depends(get_current_user),
):
    """Aggregate posture summary across all targets for the authenticated user."""
    query = {
        "bool": {
            "filter": [
                {"term": {"user_id": user.id}},
                {"range": {"timestamp": {"gte": f"now-{days}d"}}},
            ]
        }
    }
    result = search(
        _INDEX, query, size=0,
        aggs={
            "by_target": {
                "terms": {"field": "target", "size": 50},
                "aggs": {
                    "latest_score": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"timestamp": "desc"}],
                            "_source": [
                                "posture_score", "trend", "trend_delta",
                                "finding_counts", "commentary", "timestamp",
                            ],
                        }
                    },
                    "score_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day",
                        },
                        "aggs": {"avg_score": {"avg": {"field": "posture_score"}}},
                    },
                },
            },
            "overall_avg": {"avg": {"field": "posture_score"}},
            "trend_dist": {"terms": {"field": "trend"}},
        },
    )

    aggs = result.get("aggregations", {})
    targets = []
    for bucket in aggs.get("by_target", {}).get("buckets", []):
        top = bucket.get("latest_score", {}).get("hits", {}).get("hits", [])
        if not top:
            continue
        src = top[0]["_source"]
        sparkline = [
            {
                "date": b["key_as_string"],
                "score": b.get("avg_score", {}).get("value"),
            }
            for b in bucket.get("score_over_time", {}).get("buckets", [])
            if b.get("avg_score", {}).get("value") is not None
        ]
        targets.append({
            "target": bucket["key"],
            "posture_score": src.get("posture_score"),
            "trend": src.get("trend", "stable"),
            "trend_delta": src.get("trend_delta", 0.0),
            "finding_counts": src.get("finding_counts", {}),
            "commentary": src.get("commentary", ""),
            "last_updated": src.get("timestamp"),
            "sparkline": sparkline,
        })

    # Sort by posture_score ascending (worst first)
    targets.sort(key=lambda t: t.get("posture_score") or 100)

    return {
        "aggregate_score": aggs.get("overall_avg", {}).get("value"),
        "targets": targets,
        "trend_distribution": {
            b["key"]: b["doc_count"]
            for b in aggs.get("trend_dist", {}).get("buckets", [])
        },
        "period_days": days,
    }


@router.get("/history")
def get_posture_history(
    days: int = Query(90, le=365, description="Lookback window in days"),
    target: str = Query("", description="Filter to a specific target"),
    user: User = Depends(get_current_user),
):
    """Historical posture scores for sparkline/chart rendering.

    Returns daily aggregated scores, optionally filtered by target.
    """
    filters = [
        {"term": {"user_id": user.id}},
        {"range": {"timestamp": {"gte": f"now-{days}d"}}},
    ]
    if target:
        filters.append({"term": {"target": target}})

    query = {"bool": {"filter": filters}}
    result = search(
        _INDEX, query, size=0,
        aggs={
            "daily": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "day",
                },
                "aggs": {
                    "avg_score": {"avg": {"field": "posture_score"}},
                    "min_score": {"min": {"field": "posture_score"}},
                    "max_score": {"max": {"field": "posture_score"}},
                },
            }
        },
    )

    aggs = result.get("aggregations", {})
    timeline = [
        {
            "date": b["key_as_string"],
            "avg_score": b.get("avg_score", {}).get("value"),
            "min_score": b.get("min_score", {}).get("value"),
            "max_score": b.get("max_score", {}).get("value"),
            "data_points": b["doc_count"],
        }
        for b in aggs.get("daily", {}).get("buckets", [])
    ]

    return {"timeline": timeline, "target": target or None, "period_days": days}


@router.get("/target/{target:path}")
def get_target_posture(
    target: str,
    days: int = Query(90, le=365),
    user: User = Depends(get_current_user),
):
    """Detailed posture card for a single target: score, trend, sparkline, forecast."""
    query = {
        "bool": {
            "filter": [
                {"term": {"user_id": user.id}},
                {"term": {"target": target}},
                {"range": {"timestamp": {"gte": f"now-{days}d"}}},
            ]
        }
    }
    result = search(
        _INDEX, query,
        size=1,
        sort=[{"timestamp": "desc"}],
        aggs={
            "sparkline": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "day",
                },
                "aggs": {"avg_score": {"avg": {"field": "posture_score"}}},
            },
            "avg_score": {"avg": {"field": "posture_score"}},
        },
    )

    hits = result.get("hits", {}).get("hits", [])
    aggs = result.get("aggregations", {})

    if not hits:
        return {"target": target, "found": False}

    latest = hits[0]["_source"]
    sparkline = [
        {
            "date": b["key_as_string"],
            "score": b.get("avg_score", {}).get("value"),
        }
        for b in aggs.get("sparkline", {}).get("buckets", [])
        if b.get("avg_score", {}).get("value") is not None
    ]

    return {
        "found": True,
        "target": target,
        "posture_score": latest.get("posture_score"),
        "trend": latest.get("trend", "stable"),
        "trend_delta": latest.get("trend_delta", 0.0),
        "finding_counts": latest.get("finding_counts", {}),
        "components": latest.get("components", {}),
        "commentary": latest.get("commentary", ""),
        "forecast": latest.get("forecast", ""),
        "forecast_date": latest.get("forecast_date"),
        "last_updated": latest.get("timestamp"),
        "avg_score_period": aggs.get("avg_score", {}).get("value"),
        "sparkline": sparkline,
        "period_days": days,
    }


@router.get("/brief")
def get_weekly_brief(
    user: User = Depends(get_current_user),
):
    """AI-generated weekly security brief aggregating posture across all targets."""
    # Get latest posture snapshot per target (last 7 days)
    query = {
        "bool": {
            "filter": [
                {"term": {"user_id": user.id}},
                {"range": {"timestamp": {"gte": "now-7d"}}},
            ]
        }
    }
    result = search(
        _INDEX, query, size=0,
        aggs={
            "by_target": {
                "terms": {"field": "target", "size": 50},
                "aggs": {
                    "latest": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"timestamp": "desc"}],
                            "_source": [
                                "posture_score", "trend", "finding_counts",
                                "commentary", "forecast",
                            ],
                        }
                    }
                },
            },
            "overall_avg": {"avg": {"field": "posture_score"}},
        },
    )

    aggs = result.get("aggregations", {})
    overall_avg = aggs.get("overall_avg", {}).get("value")
    target_summaries = []
    for bucket in aggs.get("by_target", {}).get("buckets", []):
        top = bucket.get("latest", {}).get("hits", {}).get("hits", [])
        if not top:
            continue
        src = top[0]["_source"]
        target_summaries.append({
            "target": bucket["key"],
            "posture_score": src.get("posture_score"),
            "trend": src.get("trend", "stable"),
            "finding_counts": src.get("finding_counts", {}),
            "commentary": src.get("commentary", ""),
            "forecast": src.get("forecast", ""),
        })

    # Sort degrading targets first for the brief
    target_summaries.sort(key=lambda t: (
        0 if t.get("trend") == "degrading" else (1 if t.get("trend") == "stable" else 2),
        t.get("posture_score") or 100,
    ))

    brief_text = _generate_weekly_brief_text(overall_avg, target_summaries)

    return {
        "overall_score": overall_avg,
        "targets": target_summaries,
        "brief": brief_text,
        "generated_at": _now_iso(),
    }


def _generate_weekly_brief_text(overall_avg: float | None, targets: list[dict]) -> str:
    """Generate a weekly security brief using Claude."""
    try:
        import anthropic
        import json
        from modules.config import AI_MODEL

        if not targets:
            return "No posture data available for the past 7 days."

        context = json.dumps(
            [
                {
                    "target": t["target"],
                    "score": t.get("posture_score"),
                    "trend": t.get("trend"),
                    "critical": t.get("finding_counts", {}).get("critical", 0),
                    "high": t.get("finding_counts", {}).get("high", 0),
                }
                for t in targets[:10]
            ],
            indent=1,
        )

        prompt = (
            f"Weekly security posture brief. Overall score: {(overall_avg or 0.0):.1f}/100.\n"
            f"Per-target data:\n{context}\n\n"
            "Write a concise 3-5 sentence weekly security brief suitable for a CISO or team lead. "
            "Highlight the most critical risks, notable improvements, and top 1-2 remediation priorities. "
            "Be specific and actionable."
        )

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=AI_MODEL,
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = ""
        for block in response.content:
            if hasattr(block, "text"):
                text += block.text
        return text.strip()
    except Exception:
        if overall_avg is not None:
            return (
                f"Overall security posture score this week: {overall_avg:.1f}/100. "
                f"{len(targets)} target(s) monitored."
            )
        return "Weekly brief unavailable — no posture data for the past 7 days."


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
