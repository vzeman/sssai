"""
Query optimization utilities for improved database performance.
Includes pagination, efficient filtering, and N+1 prevention.
"""

from typing import TypeVar, Generic, Optional, Any, List, Tuple
from dataclasses import dataclass
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session
from sqlalchemy.sql import select

T = TypeVar('T')


@dataclass
class PaginationParams:
    """Pagination parameters."""
    skip: int = 0
    limit: int = 20
    
    def __post_init__(self):
        """Validate pagination params."""
        if self.skip < 0:
            self.skip = 0
        if self.limit < 1:
            self.limit = 1
        if self.limit > 500:
            self.limit = 500  # Max 500 items per page


@dataclass
class PaginatedResult(Generic[T]):
    """Paginated result with metadata."""
    items: List[T]
    total: int
    skip: int
    limit: int
    has_next: bool
    has_prev: bool
    
    @property
    def total_pages(self) -> int:
        """Calculate total pages."""
        if self.limit == 0:
            return 0
        return (self.total + self.limit - 1) // self.limit
    
    @property
    def current_page(self) -> int:
        """Calculate current page (1-indexed)."""
        if self.limit == 0:
            return 1
        return (self.skip // self.limit) + 1


class QueryOptimizer:
    """Helper class for optimized database queries."""
    
    @staticmethod
    def paginate(
        session: Session,
        query,
        params: PaginationParams,
        order_by=None,
        ascending: bool = False
    ) -> PaginatedResult:
        """
        Paginate query results efficiently.
        
        Args:
            session: SQLAlchemy session
            query: SQLAlchemy query object
            params: Pagination parameters
            order_by: Column to order by
            ascending: Sort ascending if True, descending if False
        
        Returns:
            PaginatedResult with paginated items and metadata
        """
        # Get total count (separate query for efficiency)
        total = session.query(query.statement.froms[0]).count()
        
        # Apply ordering
        if order_by is not None:
            query = query.order_by(
                asc(order_by) if ascending else desc(order_by)
            )
        
        # Apply pagination
        items = query.offset(params.skip).limit(params.limit).all()
        
        return PaginatedResult(
            items=items,
            total=total,
            skip=params.skip,
            limit=params.limit,
            has_next=(params.skip + params.limit) < total,
            has_prev=params.skip > 0
        )
    
    @staticmethod
    def get_user_scans_optimized(
        session: Session,
        user_id: str,
        skip: int = 0,
        limit: int = 20,
        status: Optional[str] = None,
        order_by_created: bool = True
    ) -> Tuple[List[Any], int]:
        """
        Optimized query for user scans with filtering.
        Uses indexes: idx_scan_user_created, idx_scan_user_status
        
        Args:
            session: SQLAlchemy session
            user_id: User ID
            skip: Number of items to skip
            limit: Number of items to return
            status: Optional status filter
            order_by_created: Order by created_at if True
        
        Returns:
            Tuple of (scans, total_count)
        """
        from modules.api.models import Scan
        
        # Build filtered query
        query = session.query(Scan).filter(Scan.user_id == user_id)
        
        if status:
            query = query.filter(Scan.status == status)
        
        # Count total (before pagination)
        total = query.count()
        
        # Apply ordering
        if order_by_created:
            query = query.order_by(desc(Scan.created_at))
        
        # Apply pagination
        scans = query.offset(skip).limit(limit).all()
        
        return scans, total
    
    @staticmethod
    def get_user_assets_optimized(
        session: Session,
        user_id: str,
        target: Optional[str] = None,
        asset_type: Optional[str] = None,
        is_active: bool = True,
        skip: int = 0,
        limit: int = 20
    ) -> Tuple[List[Any], int]:
        """
        Optimized query for user assets.
        Uses indexes: idx_asset_user_target, idx_asset_target_active
        
        Args:
            session: SQLAlchemy session
            user_id: User ID
            target: Optional target filter
            asset_type: Optional asset type filter
            is_active: Filter by active status
            skip: Number of items to skip
            limit: Number of items to return
        
        Returns:
            Tuple of (assets, total_count)
        """
        from modules.api.models import Asset
        
        # Build filtered query
        query = session.query(Asset).filter(
            Asset.user_id == user_id,
            Asset.is_active == is_active
        )
        
        if target:
            query = query.filter(Asset.target == target)
        
        if asset_type:
            query = query.filter(Asset.asset_type == asset_type)
        
        # Count total
        total = query.count()
        
        # Order by last_seen (most recent first)
        query = query.order_by(desc(Asset.last_seen))
        
        # Apply pagination
        assets = query.offset(skip).limit(limit).all()
        
        return assets, total
    
    @staticmethod
    def get_user_campaigns_optimized(
        session: Session,
        user_id: str,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 20
    ) -> Tuple[List[Any], int]:
        """
        Optimized query for user campaigns.
        Uses indexes: idx_campaign_user_created, idx_campaign_user_status
        
        Args:
            session: SQLAlchemy session
            user_id: User ID
            status: Optional status filter
            skip: Number of items to skip
            limit: Number of items to return
        
        Returns:
            Tuple of (campaigns, total_count)
        """
        from modules.api.models import Campaign
        
        # Build filtered query
        query = session.query(Campaign).filter(Campaign.user_id == user_id)
        
        if status:
            query = query.filter(Campaign.status == status)
        
        # Count total
        total = query.count()
        
        # Order by created_at (newest first)
        query = query.order_by(desc(Campaign.created_at))
        
        # Apply pagination
        campaigns = query.offset(skip).limit(limit).all()
        
        return campaigns, total
    
    @staticmethod
    def get_user_monitors_optimized(
        session: Session,
        user_id: str,
        is_active: bool = True,
        skip: int = 0,
        limit: int = 20
    ) -> Tuple[List[Any], int]:
        """
        Optimized query for user monitors.
        Uses indexes: idx_monitor_user_active
        
        Args:
            session: SQLAlchemy session
            user_id: User ID
            is_active: Filter by active status
            skip: Number of items to skip
            limit: Number of items to return
        
        Returns:
            Tuple of (monitors, total_count)
        """
        from modules.api.models import Monitor
        
        # Build filtered query
        query = session.query(Monitor).filter(
            Monitor.user_id == user_id,
            Monitor.is_active == is_active
        )
        
        # Count total
        total = query.count()
        
        # Order by created_at (newest first)
        query = query.order_by(desc(Monitor.created_at))
        
        # Apply pagination
        monitors = query.offset(skip).limit(limit).all()
        
        return monitors, total


# Recommended index creation script (for reference)
INDEX_CREATION_SQL = """
-- Scan indexes
CREATE INDEX IF NOT EXISTS idx_scan_user_created ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_user_status ON scans(user_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_status_created ON scans(status, created_at DESC);

-- Campaign indexes
CREATE INDEX IF NOT EXISTS idx_campaign_user_created ON campaigns(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaign_user_status ON campaigns(user_id, status);

-- Monitor indexes
CREATE INDEX IF NOT EXISTS idx_monitor_user_active ON monitors(user_id, is_active);

-- Asset indexes
CREATE INDEX IF NOT EXISTS idx_asset_user_target ON assets(user_id, target);
CREATE INDEX IF NOT EXISTS idx_asset_target_active ON assets(target, is_active);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_created ON audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);
"""
