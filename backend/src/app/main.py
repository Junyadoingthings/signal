"""FastAPI application factory."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app import __version__
from app.api import audit, auth, system, users
from app.core.config import Settings, get_settings
from app.core.errors import install_error_handlers
from app.core.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.core.ratelimit import limiter
from app.services.bootstrap import ensure_admin
from app.storage.db import get_engine
from app.storage.migrate import upgrade_to_head
from app.storage.repositories import SqlSessionRepository

log = logging.getLogger("signal")

UPLOAD_PATH_PREFIX = "/api/ingest/upload"


def create_app(settings: Settings | None = None, *, run_migrations: bool = True) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if run_migrations:
            upgrade_to_head()
        with Session(get_engine()) as db:
            ensure_admin(db, settings)
            SqlSessionRepository(db).purge_expired()
        if not settings.cookie_secure:
            log.warning("SIGNAL_COOKIE_SECURE is off: session cookies will be sent over plain HTTP")
        yield

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
        limit_for=lambda path: (
            settings.max_upload_bytes
            if path.startswith(UPLOAD_PATH_PREFIX)
            else settings.max_request_bytes
        ),
    )
    app.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.cookie_secure and settings.env == "prod"
    )

    for r in (system.router, auth.router, users.router, audit.router):
        app.include_router(r)
    return app
