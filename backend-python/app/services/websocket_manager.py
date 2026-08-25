"""
Real-time WebSocket Manager for Live Monitoring
Advanced WebSocket implementation for real-time security monitoring
"""

import asyncio
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

from app.core.database import record_audit_event, record_metric
from app.core.logging import logger


class MessageType(Enum):
    """WebSocket message types"""

    ALERT = "alert"
    SYSTEM_STATUS = "system_status"
    USER_ACTIVITY = "user_activity"
    PLATFORM_STATS = "platform_stats"
    RISK_TREND = "risk_trend"
    CONNECTION_STATUS = "connection_status"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


@dataclass
class WebSocketMessage:
    """WebSocket message structure"""

    type: MessageType
    data: Dict[str, Any]
    timestamp: float
    message_id: str


class ConnectionType(Enum):
    """WebSocket connection types"""

    DASHBOARD = "dashboard"
    ANALYST = "analyst"
    ADMIN = "admin"
    SYSTEM = "system"


class WebSocketConnection:
    """Individual WebSocket connection wrapper"""

    def __init__(
        self, websocket: WebSocket, connection_id: str, connection_type: ConnectionType
    ):
        self.websocket = websocket
        self.connection_id = connection_id
        self.connection_type = connection_type
        self.connected_at = time.time()
        self.last_ping = time.time()
        self.last_pong = time.time()
        self.is_alive = True
        self.subscriptions: Set[str] = set()
        self.user_id: Optional[str] = None
        self.metadata: Dict[str, Any] = {}

    async def send_message(self, message: WebSocketMessage):
        """Send message to WebSocket connection"""
        try:
            if self.is_alive:
                await self.websocket.send_text(
                    json.dumps(
                        {
                            "type": message.type.value,
                            "data": message.data,
                            "timestamp": message.timestamp,
                            "message_id": message.message_id,
                        }
                    )
                )
        except Exception as e:
            logger.error(f"Failed to send WebSocket message: {str(e)}")
            self.is_alive = False

    async def send_json(self, data: Dict[str, Any]):
        """Send JSON data directly"""
        try:
            if self.is_alive:
                await self.websocket.send_json(data)
        except Exception as e:
            logger.error(f"Failed to send WebSocket JSON: {str(e)}")
            self.is_alive = False

    def update_last_pong(self):
        """Update last pong timestamp"""
        self.last_pong = time.time()
        self.is_alive = True

    def is_connection_stale(self, timeout: int = 60) -> bool:
        """Check if connection is stale (no pong received)"""
        return time.time() - self.last_pong > timeout


class WebSocketManager:
    """Advanced WebSocket connection manager"""

    def __init__(self):
        # connection_id -> heartbeat task, so disconnect can cancel cleanly
        self._heartbeat_tasks: Dict[str, asyncio.Task] = {}
        self.connections: Dict[str, WebSocketConnection] = {}
        self.subscriptions: Dict[str, Set[str]] = {}  # topic -> connection_ids
        self.connection_stats: Dict[str, int] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.is_running = False

        # Statistics
        self.total_connections = 0
        self.total_messages_sent = 0
        self.total_broadcasts = 0

    async def connect(
        self,
        websocket: WebSocket,
        connection_type: ConnectionType = ConnectionType.DASHBOARD,
    ) -> str:
        """Accept new WebSocket connection"""
        try:
            await websocket.accept()

            # Generate unique connection ID
            connection_id = (
                f"{connection_type.value}_{int(time.time())}_{len(self.connections)}"
            )

            # Create connection wrapper
            connection = WebSocketConnection(websocket, connection_id, connection_type)
            self.connections[connection_id] = connection

            # Update statistics
            self.total_connections += 1
            self.connection_stats[connection_type.value] = (
                self.connection_stats.get(connection_type.value, 0) + 1
            )

            # Send welcome message
            await connection.send_json(
                {
                    "type": "connection_established",
                    "connection_id": connection_id,
                    "server_time": time.time(),
                    "available_subscriptions": [
                        "security_alerts",
                        "system_status",
                        "user_activity",
                        "platform_stats",
                        "risk_trends",
                    ],
                }
            )

            # Record connection metric
            await record_metric(
                "websocket_connections_total",
                1,
                {"connection_type": connection_type.value},
            )

            # Audit log
            await record_audit_event(
                event_type="websocket_connected",
                event_category="system",
                description=f"WebSocket connection established: {connection_type.value}",
                event_data={"connection_id": connection_id},
            )

            logger.info(f"WebSocket connected: {connection_id} ({connection_type.value})")

            # Start heartbeat for this connection. The handle is kept so
            # `disconnect` can cancel it: an orphaned heartbeat would hold a
            # reference to a dead socket for the lifetime of the process.
            self._heartbeat_tasks[connection_id] = asyncio.create_task(
                self._connection_heartbeat(connection)
            )

            return connection_id

        except Exception as e:
            logger.error(f"WebSocket connection failed: {str(e)}")
            raise

    def disconnect(self, connection_id: str):
        """Handle WebSocket disconnection"""
        try:
            heartbeat = self._heartbeat_tasks.pop(connection_id, None)
            if heartbeat is not None:
                heartbeat.cancel()

            if connection_id in self.connections:
                connection = self.connections[connection_id]

                # Remove from all subscriptions
                for topic in list(connection.subscriptions):
                    self.unsubscribe(connection_id, topic)

                # Update statistics
                self.connection_stats[connection.connection_type.value] = max(
                    0,
                    self.connection_stats.get(connection.connection_type.value, 1) - 1,
                )

                # Remove connection
                del self.connections[connection_id]

                logger.info(f"WebSocket disconnected: {connection_id}")

                # Record disconnection
                asyncio.create_task(
                    record_audit_event(
                        event_type="websocket_disconnected",
                        event_category="system",
                        description=f"WebSocket connection closed: {connection.connection_type.value}",
                        event_data={"connection_id": connection_id},
                    )
                )

        except Exception as e:
            logger.error(f"WebSocket disconnection error: {str(e)}")

    async def subscribe(
        self, connection_id: str, topic: str, filters: Dict[str, Any] = None
    ):
        """Subscribe connection to a topic"""
        try:
            if connection_id not in self.connections:
                return False

            connection = self.connections[connection_id]

            # Add to topic subscriptions
            if topic not in self.subscriptions:
                self.subscriptions[topic] = set()

            self.subscriptions[topic].add(connection_id)
            connection.subscriptions.add(topic)

            # Store filters in metadata
            if filters:
                connection.metadata[f"{topic}_filters"] = filters

            # Send subscription confirmation
            await connection.send_json(
                {
                    "type": "subscription_confirmed",
                    "topic": topic,
                    "filters": filters,
                    "timestamp": time.time(),
                }
            )

            logger.debug(f"WebSocket {connection_id} subscribed to {topic}")
            return True

        except Exception as e:
            logger.error(f"WebSocket subscription failed: {str(e)}")
            return False

    def unsubscribe(self, connection_id: str, topic: str):
        """Unsubscribe connection from a topic"""
        try:
            if connection_id in self.connections:
                connection = self.connections[connection_id]
                connection.subscriptions.discard(topic)

                # Remove filters
                filter_key = f"{topic}_filters"
                if filter_key in connection.metadata:
                    del connection.metadata[filter_key]

            if topic in self.subscriptions:
                self.subscriptions[topic].discard(connection_id)

                # Clean empty topics
                if not self.subscriptions[topic]:
                    del self.subscriptions[topic]

            logger.debug(f"WebSocket {connection_id} unsubscribed from {topic}")

        except Exception as e:
            logger.error(f"WebSocket unsubscription failed: {str(e)}")

    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        """Broadcast security alert to subscribed connections"""
        try:
            message = WebSocketMessage(
                type=MessageType.ALERT,
                data=alert_data,
                timestamp=time.time(),
                message_id=f"alert_{int(time.time())}",
            )

            await self._broadcast_to_topic("security_alerts", message, alert_data)
            self.total_broadcasts += 1

            # Record broadcast metric
            await record_metric(
                "websocket_alerts_broadcast",
                1,
                {"severity": alert_data.get("severity", "unknown")},
            )

        except Exception as e:
            logger.error(f"Alert broadcast failed: {str(e)}")

    async def broadcast_alert_update(self, update_data: Dict[str, Any]):
        """Broadcast a status/assignment change on an existing alert.

        Subscribers to `security_alerts` receive these so open dashboards stay
        in sync when another analyst triages an alert.
        """
        try:
            message = WebSocketMessage(
                type=MessageType.ALERT,
                data={"event": "alert_updated", **update_data},
                timestamp=time.time(),
                message_id=f"alert_update_{int(time.time() * 1000)}",
            )

            await self._broadcast_to_topic("security_alerts", message, update_data)
            self.total_broadcasts += 1

        except Exception as e:
            logger.error(f"Alert update broadcast failed: {str(e)}")

    async def broadcast_bulk_alert_update(self, update_data: Dict[str, Any]):
        """Broadcast the result of a bulk action across many alerts."""
        try:
            message = WebSocketMessage(
                type=MessageType.ALERT,
                data={"event": "alerts_bulk_updated", **update_data},
                timestamp=time.time(),
                message_id=f"alert_bulk_{int(time.time() * 1000)}",
            )

            await self._broadcast_to_topic("security_alerts", message)
            self.total_broadcasts += 1

        except Exception as e:
            logger.error(f"Bulk alert update broadcast failed: {str(e)}")

    async def broadcast_system_status(self, status_data: Dict[str, Any]):
        """Broadcast system status update"""
        try:
            message = WebSocketMessage(
                type=MessageType.SYSTEM_STATUS,
                data=status_data,
                timestamp=time.time(),
                message_id=f"status_{int(time.time())}",
            )

            await self._broadcast_to_topic("system_status", message)

        except Exception as e:
            logger.error(f"System status broadcast failed: {str(e)}")

    async def broadcast_user_activity(self, activity_data: Dict[str, Any]):
        """Broadcast user activity update"""
        try:
            message = WebSocketMessage(
                type=MessageType.USER_ACTIVITY,
                data=activity_data,
                timestamp=time.time(),
                message_id=f"activity_{int(time.time())}",
            )

            await self._broadcast_to_topic("user_activity", message, activity_data)

        except Exception as e:
            logger.error(f"User activity broadcast failed: {str(e)}")

    async def broadcast_platform_stats(self, stats_data: Dict[str, Any]):
        """Broadcast platform statistics"""
        try:
            message = WebSocketMessage(
                type=MessageType.PLATFORM_STATS,
                data=stats_data,
                timestamp=time.time(),
                message_id=f"stats_{int(time.time())}",
            )

            await self._broadcast_to_topic("platform_stats", message)

        except Exception as e:
            logger.error(f"Platform stats broadcast failed: {str(e)}")

    async def broadcast_risk_trend(self, trend_data: Dict[str, Any]):
        """Broadcast risk trend update"""
        try:
            message = WebSocketMessage(
                type=MessageType.RISK_TREND,
                data=trend_data,
                timestamp=time.time(),
                message_id=f"trend_{int(time.time())}",
            )

            await self._broadcast_to_topic("risk_trends", message)

        except Exception as e:
            logger.error(f"Risk trend broadcast failed: {str(e)}")

    async def broadcast_system_alert(self, alert_data: Dict[str, Any]):
        """Broadcast system-level alerts (health, errors, etc.)"""
        try:
            message = WebSocketMessage(
                type=(
                    MessageType.ERROR
                    if alert_data.get("type") == "error"
                    else MessageType.SYSTEM_STATUS
                ),
                data=alert_data,
                timestamp=time.time(),
                message_id=f"sys_alert_{int(time.time())}",
            )

            # Broadcast to all admin connections
            admin_connections = [
                conn
                for conn in self.connections.values()
                if conn.connection_type in [ConnectionType.ADMIN, ConnectionType.SYSTEM]
            ]

            for connection in admin_connections:
                await connection.send_message(message)

            self.total_messages_sent += len(admin_connections)

        except Exception as e:
            logger.error(f"System alert broadcast failed: {str(e)}")

    async def _broadcast_to_topic(
        self, topic: str, message: WebSocketMessage, filter_data: Dict[str, Any] = None
    ):
        """Broadcast message to all subscribers of a topic"""
        if topic not in self.subscriptions:
            return

        connection_ids = list(self.subscriptions[topic])
        sent_count = 0

        for connection_id in connection_ids:
            if connection_id not in self.connections:
                # Clean up stale subscription
                self.subscriptions[topic].discard(connection_id)
                continue

            connection = self.connections[connection_id]

            # Apply filters if specified
            if filter_data and not self._passes_filters(connection, topic, filter_data):
                continue

            await connection.send_message(message)
            sent_count += 1

        self.total_messages_sent += sent_count

        # Clean up empty topic
        if not self.subscriptions[topic]:
            del self.subscriptions[topic]

    def _passes_filters(
        self, connection: WebSocketConnection, topic: str, data: Dict[str, Any]
    ) -> bool:
        """Check if message passes connection's filters"""
        filter_key = f"{topic}_filters"
        filters = connection.metadata.get(filter_key)

        if not filters:
            return True

        # Apply severity filter for alerts
        if "min_severity" in filters:
            severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            message_severity = data.get("severity", "low")
            min_severity = filters["min_severity"]

            if severity_levels.get(message_severity, 1) < severity_levels.get(
                min_severity, 1
            ):
                return False

        # Apply platform filter
        if "platforms" in filters:
            message_platform = data.get("platform")
            if message_platform and message_platform not in filters["platforms"]:
                return False

        # Apply user filter
        if "user_ids" in filters:
            message_user = data.get("user_id")
            if message_user and message_user not in filters["user_ids"]:
                return False

        return True

    async def _connection_heartbeat(self, connection: WebSocketConnection):
        """Maintain connection heartbeat"""
        try:
            while connection.is_alive and connection.connection_id in self.connections:
                await asyncio.sleep(30)  # Send ping every 30 seconds

                try:
                    # Send ping
                    await connection.send_json({"type": "ping", "timestamp": time.time()})

                    connection.last_ping = time.time()

                    # Check if connection is stale
                    if connection.is_connection_stale():
                        logger.warning(
                            f"WebSocket connection stale: {connection.connection_id}"
                        )
                        self.disconnect(connection.connection_id)
                        break

                except WebSocketDisconnect:
                    self.disconnect(connection.connection_id)
                    break
                except Exception as e:
                    logger.error(
                        f"Heartbeat error for {connection.connection_id}: {str(e)}"
                    )
                    self.disconnect(connection.connection_id)
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Connection heartbeat failed: {str(e)}")

    async def handle_client_message(self, connection_id: str, message: Dict[str, Any]):
        """Handle incoming message from client"""
        try:
            if connection_id not in self.connections:
                return

            connection = self.connections[connection_id]
            message_type = message.get("type")

            if message_type == "pong":
                connection.update_last_pong()

            elif message_type == "subscribe":
                topic = message.get("topic")
                filters = message.get("filters", {})
                if topic:
                    await self.subscribe(connection_id, topic, filters)

            elif message_type == "unsubscribe":
                topic = message.get("topic")
                if topic:
                    self.unsubscribe(connection_id, topic)

            elif message_type == "get_stats":
                stats = self.get_connection_stats()
                await connection.send_json(
                    {"type": "stats_response", "data": stats, "timestamp": time.time()}
                )

            elif message_type == "authenticate":
                # The identity comes from the signed token, never from a
                # client-supplied `user_id` - trusting that field would let any
                # connection claim to be any user.
                token = message.get("token")

                try:
                    from app.core.security import decode_access_token

                    claims = decode_access_token(token or "")
                    connection.user_id = claims.get("sub")
                    connection.role = claims.get("role", "viewer")

                    await connection.send_json(
                        {
                            "type": "authenticated",
                            "user_id": connection.user_id,
                            "role": connection.role,
                        }
                    )
                    logger.info(
                        f"WebSocket {connection_id} authenticated as {connection.user_id}"
                    )

                except Exception as auth_error:
                    logger.warning(
                        f"WebSocket authentication rejected for {connection_id}: {auth_error}"
                    )
                    await connection.send_json(
                        {
                            "type": "authentication_failed",
                            "error": "Invalid or expired token",
                        }
                    )

            else:
                logger.warning(f"Unknown WebSocket message type: {message_type}")

        except Exception as e:
            logger.error(f"Client message handling failed: {str(e)}")

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        return {
            "total_connections": len(self.connections),
            "connections_by_type": self.connection_stats.copy(),
            "total_lifetime_connections": self.total_connections,
            "total_messages_sent": self.total_messages_sent,
            "total_broadcasts": self.total_broadcasts,
            "active_subscriptions": len(self.subscriptions),
            "subscriptions_by_topic": {
                topic: len(connections)
                for topic, connections in self.subscriptions.items()
            },
        }

    async def cleanup_stale_connections(self):
        """Clean up stale connections (background task)"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                stale_connections = []

                for connection_id, connection in self.connections.items():
                    if connection.is_connection_stale():
                        stale_connections.append(connection_id)

                for connection_id in stale_connections:
                    self.disconnect(connection_id)
                    logger.info(f"Cleaned up stale connection: {connection_id}")

                if stale_connections:
                    await record_metric(
                        "websocket_stale_connections_cleaned", len(stale_connections)
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stale connection cleanup failed: {str(e)}")
                await asyncio.sleep(60)

    async def start_background_tasks(self):
        """Start background maintenance tasks"""
        if not self.is_running:
            self.is_running = True
            asyncio.create_task(self.cleanup_stale_connections())
            logger.info("WebSocket manager background tasks started")

    async def shutdown(self):
        """Graceful shutdown of WebSocket manager"""
        try:
            self.is_running = False

            # Close all connections
            for connection_id in list(self.connections.keys()):
                connection = self.connections[connection_id]
                try:
                    await connection.send_json(
                        {
                            "type": "server_shutdown",
                            "message": "Server is shutting down",
                            "timestamp": time.time(),
                        }
                    )
                    await connection.websocket.close()
                except Exception:
                    # The peer may already be gone; the disconnect below still runs.
                    pass
                finally:
                    self.disconnect(connection_id)

            logger.info("WebSocket manager shutdown completed")

        except Exception as e:
            logger.error(f"WebSocket manager shutdown error: {str(e)}")


# Global WebSocket manager instance
websocket_manager = WebSocketManager()
