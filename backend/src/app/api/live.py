"""WebSocket stream of live changes (new alerts, triage updates, ingest volume).

Browsers send cookies on WebSocket upgrades from any site, so the Origin header is
checked against the UI origin (cross-site WebSocket hijacking), and the session
cookie is validated exactly like an HTTP request.
"""

import asyncio
import contextlib
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import Session
from starlette.concurrency import run_in_threadpool

from app.core.config import get_settings
from app.live import hub
from app.services import auth as auth_service
from app.storage.db import get_engine

router = APIRouter()

PING_SECONDS = 25


def _origin_ok(origin: str | None, host: str | None, allowed: str) -> bool:
    if origin is None:
        return False
    if origin == allowed:
        return True
    o = urlparse(origin)
    return bool(host) and o.netloc == host  # same-origin (served behind the same host)


def _authenticate(token: str | None) -> bool:
    if not token:
        return False
    with Session(get_engine()) as db:
        return auth_service.resolve(db, token) is not None


@router.websocket("/ws")
async def stream(ws: WebSocket) -> None:
    settings = ws.app.state.settings if hasattr(ws.app.state, "settings") else get_settings()
    if not _origin_ok(ws.headers.get("origin"), ws.headers.get("host"), settings.frontend_origin):
        await ws.close(code=1008)
        return
    if not await run_in_threadpool(_authenticate, ws.cookies.get(settings.cookie_name)):
        await ws.close(code=1008)
        return
    await ws.accept()
    q = hub.subscribe()
    try:
        await ws.send_json({"type": "hello"})
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=PING_SECONDS)
            except TimeoutError:
                msg = {"type": "ping"}
            await ws.send_json(msg)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(q)
        with contextlib.suppress(RuntimeError):
            await ws.close()
