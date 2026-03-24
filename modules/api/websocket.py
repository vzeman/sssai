"""
WebSocket manager for real-time dashboard updates.
Handles live updates from scans, monitors, and aggregated data.
"""

import json
from fastapi import WebSocket
import logging

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasts real-time updates."""

    def __init__(self):
        self.active_connections: dict[str, set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        """Register a new WebSocket connection."""
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        logger.info(f"User {user_id} connected. Active connections: {len(self.active_connections[user_id])}")

    def disconnect(self, websocket: WebSocket, user_id: str):
        """Remove a disconnected WebSocket."""
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            logger.info(f"User {user_id} disconnected.")

    async def broadcast_to_user(self, user_id: str, message: dict):
        """Send a message to all connections of a specific user."""
        if user_id not in self.active_connections:
            return

        disconnected = set()
        for connection in self.active_connections[user_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send message to user {user_id}: {e}")
                disconnected.add(connection)

        # Clean up disconnected connections
        for conn in disconnected:
            self.active_connections[user_id].discard(conn)

    async def broadcast_scan_update(self, user_id: str, scan_id: str, status: str, data: dict | None = None):
        """Broadcast a scan status update to all user connections."""
        message = {
            "type": "scan_update",
            "scan_id": scan_id,
            "status": status,
        }
        if data:
            message["data"] = data
        await self.broadcast_to_user(user_id, message)

    async def broadcast_all(self, message: dict):
        """Send a message to all connected users."""
        for user_id in list(self.active_connections.keys()):
            await self.broadcast_to_user(user_id, message)

    async def send_to_connection(self, websocket: WebSocket, message: dict):
        """Send a message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Failed to send message: {e}")

    def get_user_connection_count(self, user_id: str) -> int:
        """Get number of active connections for a user."""
        return len(self.active_connections.get(user_id, set()))


# Global connection manager instance
ws_manager = ConnectionManager()
