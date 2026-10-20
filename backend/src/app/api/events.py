from typing import Annotated

from fastapi import APIRouter, Query
from sqlmodel import col, select

from app.api.deps import DB, CurrentUser
from app.api.schemas import EventOut, EventPage
from app.core.errors import APIError
from app.storage.models import Event

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=EventPage)
def list_events(
    _: CurrentUser,
    db: DB,
    batch_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> EventPage:
    """Newest-first by storage order. Full search and filtering arrive with the hunt view."""
    stmt = select(Event)
    if batch_id:
        stmt = stmt.where(Event.batch_id == batch_id)
    if before_id:
        stmt = stmt.where(col(Event.id) < before_id)
    rows = db.exec(stmt.order_by(col(Event.id).desc()).limit(limit)).all()
    items = [EventOut.model_validate(r) for r in rows]
    return EventPage(items=items, next_before_id=items[-1].id if len(items) == limit else None)


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, _: CurrentUser, db: DB) -> Event:
    ev = db.get(Event, event_id)
    if ev is None:
        raise APIError(404, "not_found", "Event not found")
    return ev
