"""Incidents: list, detail with storyline, triage, notes and history."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from sqlalchemy import func
from sqlmodel import col, select

from app.api.alerts import _triage_kwargs, add_note, alert_rows, history_for, notes_for
from app.api.deps import DB, CurrentUser, client_ip
from app.api.schemas import (
    HistoryEntry,
    IncidentDetail,
    IncidentList,
    IncidentRow,
    IncidentUpdate,
    NoteCreate,
    NoteOut,
    StoryStep,
)
from app.core.errors import APIError
from app.correlation.correlator import storyline
from app.live import hub
from app.services import triage
from app.storage.models import Alert, Incident, Rule

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _get(db: DB, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise APIError(404, "not_found", "Incident not found")
    return inc


@router.get("", response_model=IncidentList)
def list_incidents(
    _: CurrentUser,
    db: DB,
    status: Annotated[list[Literal["new", "investigating", "closed"]] | None, Query()] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> IncidentList:
    stmt = select(Incident)
    if status:
        stmt = stmt.where(col(Incident.status).in_(status))
    total = db.exec(select(func.count()).select_from(stmt.subquery())).one()
    rows = db.exec(
        stmt.order_by(col(Incident.score).desc(), col(Incident.last_event_at).desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return IncidentList(items=[IncidentRow.model_validate(r) for r in rows], total=total)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, _: CurrentUser, db: DB) -> IncidentDetail:
    inc = _get(db, incident_id)
    alerts = db.exec(
        select(Alert)
        .where(Alert.incident_id == incident_id)
        .order_by(col(Alert.first_event_at), col(Alert.id))
    ).all()
    rules = {
        r.id: r for r in db.exec(select(Rule).where(col(Rule.id).in_({a.rule_id for a in alerts})))
    }
    return IncidentDetail(
        incident=IncidentRow.model_validate(inc),
        alerts=alert_rows(db, alerts),
        storyline=[StoryStep(**s) for s in storyline(alerts, rules)],
    )


@router.patch("/{incident_id}", response_model=IncidentRow)
def update_incident(
    incident_id: int, body: IncidentUpdate, request: Request, user: CurrentUser, db: DB
) -> IncidentRow:
    inc = _get(db, incident_id)
    try:
        closed = triage.update_incident(
            db,
            inc,
            user,
            close_alerts=body.close_alerts,
            ip=client_ip(request),
            **_triage_kwargs(body),  # type: ignore[arg-type]
        )
    except triage.TriageError as e:
        db.rollback()
        raise APIError(409, "invalid_transition", str(e)) from e
    db.commit()
    hub.publish({"type": "incidents_updated", "ids": [incident_id]})
    if closed:
        hub.publish({"type": "alerts_updated", "ids": closed})
    return IncidentRow.model_validate(inc)


@router.get("/{incident_id}/notes", response_model=list[NoteOut])
def list_notes(incident_id: int, _: CurrentUser, db: DB) -> list[NoteOut]:
    _get(db, incident_id)
    return notes_for(db, "incident", incident_id)


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def create_note(
    incident_id: int, body: NoteCreate, request: Request, user: CurrentUser, db: DB
) -> NoteOut:
    _get(db, incident_id)
    return add_note(db, "incident", incident_id, body, user, client_ip(request))


@router.get("/{incident_id}/history", response_model=list[HistoryEntry])
def incident_history(incident_id: int, _: CurrentUser, db: DB) -> list[HistoryEntry]:
    _get(db, incident_id)
    return history_for(db, "incident", incident_id)
