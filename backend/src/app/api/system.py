from datetime import timedelta

from fastapi import APIRouter
from sqlalchemy import func
from sqlmodel import col, select

from app import __version__
from app.api.deps import DB, CurrentUser
from app.api.schemas import Health, SystemStatus
from app.storage.models import (
    Alert,
    Event,
    Incident,
    IngestBatch,
    Rule,
    Status,
    UnparsedEvent,
    utcnow,
)

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health", response_model=Health)
def health() -> Health:
    return Health(status="ok", version=__version__)


@router.get("/system/status", response_model=SystemStatus)
def status(_: CurrentUser, db: DB) -> SystemStatus:
    def count(stmt: object) -> int:
        return int(db.exec(stmt).one())  # type: ignore[call-overload]

    since = utcnow() - timedelta(hours=24)
    return SystemStatus(
        events_total=count(select(func.count()).select_from(Event)),
        events_last_24h=count(
            select(func.count()).select_from(Event).where(col(Event.timestamp) >= since)
        ),
        unparsed_total=count(select(func.count()).select_from(UnparsedEvent)),
        alerts_open=count(
            select(func.count()).select_from(Alert).where(col(Alert.status) != Status.closed)
        ),
        incidents_open=count(
            select(func.count()).select_from(Incident).where(col(Incident.status) != Status.closed)
        ),
        rules_enabled=count(select(func.count()).select_from(Rule).where(col(Rule.enabled))),
        last_event_at=db.exec(select(func.max(Event.timestamp))).one(),
        last_ingest_at=db.exec(select(func.max(IngestBatch.created_at))).one(),
    )
