"""FastAPI Application Entry Point for Atlas AI Control Plane."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from api.routes import health_check, router as v1_router
from core.agent_registry import REGISTRY
from core.charter import ensure_active_charter
from core.config import load_settings
from core.events import EVENT_HUB
from core.kill_switch import ensure_system_state
from core.model_router import ModelRouter
from core.security import authenticate_bearer_token
from db.database import get_db, init_db, session_scope


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Validate security rules, initialize DB, seed catalog/charter, and verify Gemini models."""
    settings = load_settings()
    settings.validate_security_constraints()
    init_db(settings.database_url)
    with session_scope() as session:
        ensure_system_state(session)
        REGISTRY.sync_to_db(session)
        ensure_active_charter(session)

    router_svc = ModelRouter(settings=settings)
    router_svc.verify_startup_models()
    yield


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(
        title="Atlas AI Personal Multi-Agent Operating System API",
        description=(
            "Single-owner governed control plane for Atlas AI, including Tiered Decision Engine, "
            "Emergency Kill Switch, Append-Only Hash-Chained Audit Log, Cost Agent Enforcement, "
            "and Advisory Board of Directors."
        ),
        version=settings.version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Idempotency-Key"],
    )

    @app.exception_handler(NotImplementedError)
    async def not_implemented_exception_handler(_request: Request, exc: NotImplementedError):
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={
                "detail": str(exc),
                "error_type": "NotImplementedError",
                "status_doc": "See STATUS.md under 'Not implemented'",
            },
        )

    @app.get("/health", tags=["health"], summary="Root container health probe")
    def root_health(session: Session = Depends(get_db)) -> Dict[str, Any]:
        return health_check(session)

    async def _ws_events_handler(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token", "").strip()
        if not token:
            auth_header = websocket.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()

        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        with session_scope() as session:
            try:
                principal = authenticate_bearer_token(token, session)
            except Exception:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

        await EVENT_HUB.connect(websocket)
        try:
            await websocket.send_json(
                {
                    "event_type": "ws.connected",
                    "severity": "info",
                    "payload": {
                        "actor": principal.actor,
                        "recent_events": EVENT_HUB.recent_events(limit=20),
                    },
                }
            )
            while True:
                msg = await websocket.receive_text()
                if msg.strip().lower() == "ping":
                    await websocket.send_json({"event_type": "ws.pong", "severity": "info", "payload": {}})
        except WebSocketDisconnect:
            EVENT_HUB.disconnect(websocket)
        except Exception:
            EVENT_HUB.disconnect(websocket)

    @app.websocket("/api/v1/events")
    async def ws_v1_events(websocket: WebSocket) -> None:
        await _ws_events_handler(websocket)

    @app.websocket("/events")
    async def ws_root_events(websocket: WebSocket) -> None:
        await _ws_events_handler(websocket)

    app.include_router(v1_router)
    return app


app = create_app()
