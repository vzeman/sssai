"""
Dashboard routes for real-time metrics and WebSocket updates.
"""

import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.auth import get_current_user
from modules.api.websocket import ws_manager
from modules.api.dashboard import (
    DashboardAggregator,
    HeatmapGenerator,
    ChartDataGenerator,
)
from modules.api.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get current dashboard statistics."""
    try:
        aggregator = DashboardAggregator(db)
        stats = await aggregator.get_dashboard_stats(current_user.id)
        return stats
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch dashboard stats")


@router.get("/heatmap")
async def get_heatmap(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get risk heatmap data for visualization."""
    try:
        heatmap = HeatmapGenerator.generate_risk_heatmap(current_user.id, db)
        return heatmap
    except Exception as e:
        logger.error(f"Error getting heatmap: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch heatmap")


@router.get("/trends")
async def get_risk_trends(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get risk score trends over time."""
    try:
        if days < 1 or days > 365:
            raise HTTPException(status_code=400, detail="Days must be between 1 and 365")

        trend = ChartDataGenerator.generate_risk_trend(current_user.id, db, days)
        return trend
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting trends: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch trends")


@router.get("/findings-summary")
async def get_findings_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get findings summary by type."""
    try:
        summary = ChartDataGenerator.generate_findings_by_type(current_user.id)
        return summary
    except Exception as e:
        logger.error(f"Error getting findings summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch findings summary")


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = None,
):
    """
    WebSocket endpoint for real-time dashboard updates.
    Clients should connect with their JWT token as a query parameter.
    """
    # Token validation would happen here in production
    # For now, we accept the connection
    
    user_id = None
    try:
        # In production, validate token and extract user_id
        # For this implementation, we'll use the connection itself
        await websocket.accept()
        
        # Client should send their user_id in first message
        initial_message = await websocket.receive_text()
        data = json.loads(initial_message)
        user_id = data.get("user_id")
        
        if not user_id:
            await websocket.send_json({"error": "user_id required"})
            await websocket.close(code=4000)
            return

        # Register this connection
        await ws_manager.connect(websocket, user_id)
        logger.info(f"WebSocket connection established for user {user_id}")

        # Send welcome message
        await ws_manager.send_to_connection(
            websocket,
            {
                "type": "connection",
                "status": "connected",
                "message": "Connected to dashboard stream",
            },
        )

        # Keep connection alive and process messages
        while True:
            try:
                message = await websocket.receive_text()
                data = json.loads(message)
                
                # Handle different message types
                msg_type = data.get("type")
                if msg_type == "ping":
                    await ws_manager.send_to_connection(
                        websocket,
                        {"type": "pong", "timestamp": data.get("timestamp")},
                    )
                elif msg_type == "subscribe":
                    # Client subscribing to specific updates
                    channel = data.get("channel")
                    logger.debug(f"User {user_id} subscribed to {channel}")

            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from user {user_id}")
            except Exception as e:
                logger.error(f"Error processing message for user {user_id}: {e}")

    except WebSocketDisconnect:
        if user_id:
            ws_manager.disconnect(websocket, user_id)
            logger.info(f"WebSocket disconnected for user {user_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.close(code=1000)
        except Exception:
            pass


@router.post("/send-update")
async def trigger_dashboard_update(
    user_id: str,
    update_type: str = "stats",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Manually trigger a dashboard update broadcast.
    Used by worker/scheduler to push updates to connected clients.
    """
    # Only allow user to trigger updates for themselves
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        if update_type == "stats":
            aggregator = DashboardAggregator(db)
            stats = await aggregator.get_dashboard_stats(user_id)
            message = {"type": "stats_update", "data": stats}
        elif update_type == "heatmap":
            heatmap = HeatmapGenerator.generate_risk_heatmap(user_id, db)
            message = {"type": "heatmap_update", "data": heatmap}
        elif update_type == "trends":
            trends = ChartDataGenerator.generate_risk_trend(user_id, db)
            message = {"type": "trends_update", "data": trends}
        else:
            raise HTTPException(status_code=400, detail="Invalid update_type")

        # Broadcast to all connections of this user
        await ws_manager.broadcast_to_user(user_id, message)

        return {"status": "update_sent"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering update: {e}")
        raise HTTPException(status_code=500, detail="Failed to send update")
