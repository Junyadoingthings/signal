"""FastAPI application factory."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app import __version__
from app.api import (
    alerts,
    audit,
    auth,
    entities,
    events,
    hunt,
    incidents,
    ingest,
    live,
    rules,
    system,
    users,
)
from app.core.config import Settings, get_settings
from app.core.errors import install_error_handlers
from app.core.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.core.ratelimit import limiter
from app.correlation.correlator import Correlator
from app.detection.engine import Engine
from app.detection.loader import load_rules, sync_rules
from app.ingest import pipeline
from app.ingest.service import (
    IngestWorker,
    clear_spool,
    fail_interrupted_batches,
    spool_dir,
)
from app.live import hub
from app.services.bootstrap import ensure_admin
from app.storage.db import get_engine
from app.storage.migrate import upgrade_to_head
from app.storage.models import utcnow
from app.storage.repositories import SqlSessionRepository

log = logging.getLogger("signal")

UPLOAD_PATH = "/api/ingest/upload"
LIVE_PATH = "/api/ingest/events"
MULTIPART_OVERHEAD = 1024 * 1024


def create_app(settings: Settings | None = None, *, run_migrations: bool = True) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    worker = IngestWorker()
    # Rule files are validated at startup: a broken rule stops the app instead of
    # silently not detecting anything.
    rule_files = load_rules()
    engine = Engine(spec for spec, _ in rule_files)

    correlator = Correlator(engine)

    def correlate(db: Session, alert_ids: list[int]) -> None:
        incident_ids = correlator.on_alerts(db, alert_ids)
        hub.publish({"type": "alerts", "ids": alert_ids, "incidents": incident_ids})

    engine.alert_hooks.append(correlate)

    def detect(db: Session, event_ids: list[int]) -> None:
        hub.publish({"type": "events", "count": len(event_ids), "at": utcnow().isoformat()})
        engine.on_ingest(db, event_ids)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if run_migrations:
            upgrade_to_head()
        with Session(get_engine()) as db:
            ensure_admin(db, settings)
            SqlSessionRepository(db).purge_expired()
            fail_interrupted_batches(db)
            sync_rules(db, rule_files)
        clear_spool(spool_dir(settings))
        pipeline.post_ingest_hooks.append(detect)
        worker.start()
        if not settings.cookie_secure:
            log.warning("SIGNAL_COOKIE_SECURE is off: session cookies will be sent over plain HTTP")
        try:
            yield
        finally:
            worker.stop()
            pipeline.post_ingest_hooks.remove(detect)

    app = FastAPI(
        title="SIGNAL API",
        version=__version__,
        description="Lightweight SIEM & detection console.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.limiter = limiter
    app.state.settings = settings
    app.state.ingest_worker = worker
    app.state.engine = engine

    def body_limit(path: str) -> int:
        if path == UPLOAD_PATH:
            return settings.max_upload_bytes + MULTIPART_OVERHEAD
        if path == LIVE_PATH:
            return settings.max_live_batch_bytes
        return settings.max_request_bytes

    install_error_handlers(app)

    # Starlette runs the last-added middleware first.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Content-Type", settings.csrf_header_name],
    )
    app.add_middleware(
        BodySizeLimitMiddleware,
        limit_for=body_limit,
    )
    app.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.cookie_secure and settings.env == "prod"
    )

    for r in (
        system.router,
        auth.router,
        users.router,
        audit.router,
        ingest.router,
        events.router,
        rules.router,
        alerts.router,
        incidents.router,
        live.router,
        hunt.router,
        entities.router,
    ):
        app.include_router(r)
    return app
