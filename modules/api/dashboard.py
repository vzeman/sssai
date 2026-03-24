"""
Dashboard aggregation service for real-time metrics and insights.
Aggregates data from database and Elasticsearch for live dashboard updates.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from elasticsearch import Elasticsearch
import os

from modules.api.models import Scan, Monitor, MonitorCheck, Asset, User, Campaign

logger = logging.getLogger(__name__)


class DashboardAggregator:
    """Aggregates dashboard metrics from database and Elasticsearch."""

    def __init__(self, db: Session, es_client: Optional[Elasticsearch] = None):
        self.db = db
        self.es_client = es_client or self._init_elasticsearch()

    @staticmethod
    def _init_elasticsearch() -> Optional[Elasticsearch]:
        """Initialize Elasticsearch client."""
        try:
            es_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
            return Elasticsearch([es_url])
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch: {e}")
            return None

    async def get_dashboard_stats(self, user_id: str) -> Dict[str, Any]:
        """Get aggregated dashboard statistics for a user."""
        try:
            stats = {
                "timestamp": datetime.utcnow().isoformat(),
                "summary": await self._get_summary_stats(user_id),
                "recent_scans": await self._get_recent_scans(user_id),
                "risk_distribution": await self._get_risk_distribution(user_id),
                "scan_types": await self._get_scan_type_distribution(user_id),
                "uptime_status": await self._get_uptime_status(user_id),
                "top_findings": await self._get_top_findings(user_id),
                "activity_timeline": await self._get_activity_timeline(user_id),
            }
            return stats
        except Exception as e:
            logger.error(f"Error aggregating dashboard stats for user {user_id}: {e}")
            return {}

    async def _get_summary_stats(self, user_id: str) -> Dict[str, Any]:
        """Get summary statistics (totals, averages)."""
        try:
            total_scans = self.db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
            
            active_monitors = self.db.query(func.count(Monitor.id)).filter(
                Monitor.user_id == user_id,
                Monitor.is_active == True
            ).scalar() or 0
            
            avg_risk = self.db.query(func.avg(Scan.risk_score)).filter(
                Scan.user_id == user_id,
                Scan.risk_score.isnot(None)
            ).scalar() or 0
            
            total_findings = self.db.query(func.sum(Scan.findings_count)).filter(
                Scan.user_id == user_id
            ).scalar() or 0
            
            assets_count = self.db.query(func.count(Asset.id)).filter(
                Asset.user_id == user_id,
                Asset.is_active == True
            ).scalar() or 0
            
            running_scans = self.db.query(func.count(Scan.id)).filter(
                Scan.user_id == user_id,
                Scan.status == "running"
            ).scalar() or 0

            return {
                "total_scans": int(total_scans),
                "active_monitors": int(active_monitors),
                "average_risk_score": round(float(avg_risk), 2),
                "total_findings": int(total_findings),
                "active_assets": int(assets_count),
                "running_scans": int(running_scans),
            }
        except Exception as e:
            logger.error(f"Error getting summary stats: {e}")
            return {}

    async def _get_recent_scans(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans with status and risk info."""
        try:
            scans = self.db.query(Scan).filter(
                Scan.user_id == user_id
            ).order_by(desc(Scan.created_at)).limit(limit).all()

            return [
                {
                    "id": scan.id,
                    "target": scan.target,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "risk_score": scan.risk_score,
                    "findings_count": scan.findings_count,
                    "created_at": scan.created_at.isoformat(),
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "progress": self._estimate_scan_progress(scan),
                }
                for scan in scans
            ]
        except Exception as e:
            logger.error(f"Error getting recent scans: {e}")
            return []

    async def _get_risk_distribution(self, user_id: str) -> Dict[str, int]:
        """Get distribution of findings by risk level."""
        try:
            # This would query Elasticsearch for findings aggregation
            # For now, we estimate from scan risk scores
            if not self.es_client:
                return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            body = {
                "query": {"match": {"user_id": user_id}},
                "size": 0,
                "aggs": {
                    "risk_levels": {
                        "terms": {
                            "field": "severity",
                            "size": 10
                        }
                    }
                }
            }

            result = self.es_client.search(index="findings", body=body)
            distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for bucket in result.get("aggregations", {}).get("risk_levels", {}).get("buckets", []):
                severity = bucket["key"].lower()
                if severity in distribution:
                    distribution[severity] = bucket["doc_count"]

            return distribution
        except Exception as e:
            logger.warning(f"Error getting risk distribution from ES: {e}")
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    async def _get_scan_type_distribution(self, user_id: str) -> Dict[str, int]:
        """Get count of scans by type."""
        try:
            result = self.db.query(
                Scan.scan_type,
                func.count(Scan.id).label("count")
            ).filter(
                Scan.user_id == user_id
            ).group_by(Scan.scan_type).all()

            return {row[0]: row[1] for row in result}
        except Exception as e:
            logger.error(f"Error getting scan type distribution: {e}")
            return {}

    async def _get_uptime_status(self, user_id: str) -> Dict[str, Any]:
        """Get overall uptime status from monitors."""
        try:
            monitors = self.db.query(Monitor).filter(
                Monitor.user_id == user_id,
                Monitor.is_active == True
            ).all()

            if not monitors:
                return {"up": 0, "down": 0, "degraded": 0, "total": 0}

            status_counts = {"up": 0, "down": 0, "degraded": 0}
            for monitor in monitors:
                status = monitor.last_status or "unknown"
                if status in status_counts:
                    status_counts[status] += 1

            return {
                **status_counts,
                "total": len(monitors),
                "uptime_percentage": round((status_counts["up"] / len(monitors) * 100), 2) if monitors else 0,
            }
        except Exception as e:
            logger.error(f"Error getting uptime status: {e}")
            return {"up": 0, "down": 0, "degraded": 0, "total": 0}

    async def _get_top_findings(self, user_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top critical findings."""
        try:
            if not self.es_client:
                return []

            body = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"user_id": user_id}},
                            {"match": {"severity": "critical"}}
                        ]
                    }
                },
                "size": limit,
                "sort": [{"created_at": {"order": "desc"}}]
            }

            result = self.es_client.search(index="findings", body=body)
            findings = []

            for hit in result.get("hits", {}).get("hits", []):
                source = hit["_source"]
                findings.append({
                    "id": hit["_id"],
                    "title": source.get("title"),
                    "severity": source.get("severity"),
                    "scan_id": source.get("scan_id"),
                    "discovered_at": source.get("created_at"),
                })

            return findings
        except Exception as e:
            logger.warning(f"Error getting top findings from ES: {e}")
            return []

    async def _get_activity_timeline(self, user_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get activity timeline for the last N hours."""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)

            scans = self.db.query(Scan).filter(
                Scan.user_id == user_id,
                Scan.created_at >= cutoff
            ).order_by(desc(Scan.created_at)).all()

            timeline = []
            for scan in scans:
                duration = None
                if scan.completed_at:
                    duration = (scan.completed_at - scan.created_at).total_seconds()

                timeline.append({
                    "id": scan.id,
                    "type": "scan",
                    "action": f"Started {scan.scan_type} scan",
                    "target": scan.target,
                    "status": scan.status,
                    "timestamp": scan.created_at.isoformat(),
                    "duration_seconds": duration,
                    "risk_score": scan.risk_score,
                })

            return timeline
        except Exception as e:
            logger.error(f"Error getting activity timeline: {e}")
            return []

    @staticmethod
    def _estimate_scan_progress(scan: Scan) -> int:
        """Estimate scan progress percentage based on status."""
        if scan.status == "completed":
            return 100
        elif scan.status == "running":
            # Estimate based on how long it's been running
            if scan.created_at:
                elapsed = (datetime.utcnow() - scan.created_at).total_seconds()
                # Assume typical scan takes 30-60 seconds
                progress = min(int((elapsed / 60) * 100), 90)
                return max(progress, 20)
            return 50
        elif scan.status == "failed":
            return 0
        else:  # queued
            return 0


class HeatmapGenerator:
    """Generates heatmap data for visualization."""

    @staticmethod
    def generate_risk_heatmap(user_id: str, db: Session, es_client: Optional[Elasticsearch] = None) -> Dict[str, Any]:
        """Generate risk heatmap by scan type and target."""
        try:
            scans = db.query(Scan).filter(Scan.user_id == user_id).all()

            heatmap_data = {}
            for scan in scans:
                key = f"{scan.scan_type}:{scan.target}"
                if key not in heatmap_data:
                    heatmap_data[key] = {
                        "scan_type": scan.scan_type,
                        "target": scan.target,
                        "latest_risk": scan.risk_score or 0,
                        "findings": scan.findings_count,
                        "last_scan": scan.completed_at or scan.created_at,
                    }

            # Convert to list and sort by risk
            heatmap_list = sorted(
                heatmap_data.values(),
                key=lambda x: x["latest_risk"],
                reverse=True
            )

            return {
                "data": heatmap_list,
                "timestamp": datetime.utcnow().isoformat(),
                "count": len(heatmap_list),
            }
        except Exception as e:
            logger.error(f"Error generating heatmap: {e}")
            return {"data": [], "timestamp": datetime.utcnow().isoformat(), "count": 0}


class ChartDataGenerator:
    """Generates data for various charts."""

    @staticmethod
    def generate_risk_trend(user_id: str, db: Session, days: int = 30) -> Dict[str, Any]:
        """Generate risk score trend over time."""
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            scans = db.query(Scan).filter(
                Scan.user_id == user_id,
                Scan.created_at >= cutoff,
                Scan.risk_score.isnot(None)
            ).order_by(Scan.created_at).all()

            # Group by day
            daily_data = {}
            for scan in scans:
                day = scan.created_at.date().isoformat()
                if day not in daily_data:
                    daily_data[day] = []
                daily_data[day].append(scan.risk_score)

            # Calculate daily average
            trend = [
                {
                    "date": day,
                    "average_risk": round(sum(scores) / len(scores), 2),
                    "max_risk": max(scores),
                    "scan_count": len(scores),
                }
                for day, scores in sorted(daily_data.items())
            ]

            return {
                "trend": trend,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"Error generating risk trend: {e}")
            return {"trend": [], "timestamp": datetime.utcnow().isoformat()}

    @staticmethod
    def generate_findings_by_type(user_id: str, es_client: Optional[Elasticsearch] = None) -> Dict[str, Any]:
        """Generate findings aggregation by type."""
        try:
            if not es_client:
                return {"data": [], "timestamp": datetime.utcnow().isoformat()}

            body = {
                "query": {"match": {"user_id": user_id}},
                "size": 0,
                "aggs": {
                    "finding_types": {
                        "terms": {
                            "field": "type",
                            "size": 20
                        }
                    }
                }
            }

            result = es_client.search(index="findings", body=body)
            data = [
                {
                    "type": bucket["key"],
                    "count": bucket["doc_count"],
                }
                for bucket in result.get("aggregations", {}).get("finding_types", {}).get("buckets", [])
            ]

            return {
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.warning(f"Error generating findings by type: {e}")
            return {"data": [], "timestamp": datetime.utcnow().isoformat()}
