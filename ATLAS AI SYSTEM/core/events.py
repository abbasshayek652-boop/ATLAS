"""Real-Time Event Hub for Dashboard WebSocket (/api/v1/events)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from fastapi import WebSocket


class EventHub:
    """Thread-safe / async-compatible event broadcaster and recent event ring buffer."""

    def __init__(self, max_history: int = 200) -> None:
        self._connections: Set[WebSocket] = set()
        self._history: List[Dict[str, Any]] = []
        self._max_history = max_history

    def publish_sync(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        severity: str = "info",
    ) -> Dict[str, Any]:
        """Record an event synchronously and schedule broadcast if an event loop is running."""
        event = {
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "payload": payload,
        }
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(event))
        except RuntimeError:
            pass
        return event

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    async def broadcast(self, event: Dict[str, Any]) -> None:
        dead: List[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._history[-limit:]))


EVENT_HUB = EventHub()
