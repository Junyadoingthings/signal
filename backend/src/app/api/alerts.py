"""Alert queue, detail, triage, bulk triage, notes and history."""

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Literal

import yaml
from fastapi import APIRouter, Query, Request
from sqlalchemy import case, func, or_
from sqlmodel import Session, col, select

from app import attack
from app.api.deps import DB, CurrentUser, client_ip
from app.api.schemas import (
    AlertDetail,
    AlertList,
    AlertRow,
    AlertRuleInfo,
    BulkResult,
    BulkTriage,
    EventOut,
    HistoryEntry,
    NoteCreate,
    NoteOut,
    TechniqueRef,
    TriageUpdate,
)
from app.core.errors import APIError
from app.live import hub
from app.services import audit, triage
from app.storage.models import (
    Alert,
    AlertEvent,
    AuditLog,
    Event,
    Note,
    Rule,
    Status,
    User,
    Verdict,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SortKey = Literal["created_at", "last_event_at", "first_event_at", "severity", "event_count"]


def alert_rows(db: Session, alerts: Sequence[Alert]) -> list[AlertRow]:
    rule_ids = {a.rule_id for a in alerts}
    rules = (
        {r.id: r for r in db.exec(select(Rule).where(col(Rule.id).in_(rule_ids)))}
        if rule_ids
        else {}
    )
    user_ids = {a.assignee_id for a in alerts if a.assignee_id}
    users = (
        {u.id: u for u in db.exec(select(User).where(col(User.id).in_(user_ids)))}
        if user_ids
        else {}
    )
    out = []
    for a in alerts:
        r = rules.get(a.rule_id)
        u = users.get(a.assignee_id) if a.assignee_id else None
        out.append(
            AlertRow(
                **{k: getattr(a, k) for k in AlertRow.model_fields if hasattr(a, k)},
                rule_title=r.title if r else a.rule_id,
                tactic=r.primary_tactic if r else None,
                assignee_name=u.display_name if u else None,
            )
        )
    return out


@router.get("", response_model=AlertList)
def list_alerts(
    _: CurrentUser,
    db: DB,
    status: Annotated[list[Literal["new", "investigating", "closed"]] | None, Query()] = None,
    severity: Annotated[list[Literal["low", "medium", "high", "critical"]] | None, Query()] = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    incident_id: Annotated[int | None, Query(ge=1)] = None,
    assignee_id: Annotated[int | None, Query(ge=1)] = None,
    entity: Annotated[str | None, Query(max_length=255)] = None,
    q: Annotated[str | None, Query(max_length=255)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: SortKey = "created_at",
    order: Literal["asc", "desc"] = "desc",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AlertList:
    stmt = select(Alert)
    if status:
        stmt = stmt.where(col(Alert.status).in_(status))
    if severity:
        stmt = stmt.where(col(Alert.severity).in_(severity))
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if incident_id:
        stmt = stmt.where(Alert.incident_id == incident_id)
    if assignee_id:
        stmt = stmt.where(Alert.assignee_id == assignee_id)
    if entity:
        stmt = stmt.where(
            or_(col(Alert.host) == entity, col(Alert.user) == entity, col(Alert.src_ip) == entity)
        )
    if q:
        # Bound parameter with LIKE wildcards escaped: user text is never SQL.
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rule_match = select(Rule.id).where(col(Rule.title).ilike(like, escape="\\"))
        stmt = stmt.where(
            or_(
                col(Alert.host).ilike(like, escape="\\"),
                col(Alert.user).ilike(like, escape="\\"),
                col(Alert.src_ip).ilike(like, escape="\\"),
                col(Alert.rule_id).ilike(like, escape="\\"),
                col(Alert.rule_id).in_(rule_match),
            )
        )
    if since:
        stmt = stmt.where(col(Alert.last_event_at) >= since)
    if until:
        stmt = stmt.where(col(Alert.first_event_at) <= until)

    total = db.exec(select(func.count()).select_from(stmt.subquery())).one()
    key = case(SEV_RANK, value=Alert.severity) if sort == "severity" else getattr(Alert, sort)
    stmt = stmt.order_by(key.desc() if order == "desc" else key.asc(), col(Alert.id).desc())
    rows = db.exec(stmt.offset(offset).limit(limit)).all()
    return AlertList(items=alert_rows(db, rows), total=total, offset=offset, limit=limit)


def _get_alert(db: Session, alert_id: int) -> Alert:
    a = db.get(Alert, alert_id)
    if a is None:
        raise APIError(404, "not_found", "Alert not found")
    return a


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(
    alert_id: int,
    request: Request,
    _: CurrentUser,
    db: DB,
    events_limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> AlertDetail:
    a = _get_alert(db, alert_id)
    rule = db.get(Rule, a.rule_id)
    spec = yaml.safe_load(rule.yaml) if rule else {}
    engine = request.app.state.engine
    compiled = engine.rules.get(a.rule_id)
    techniques = []
    for tid in rule.techniques if rule else []:
        t = attack.technique(tid)
        techniques.append(
            TechniqueRef(id=tid, name=t.name if t else None, url=t.url if t else None)
        )
    event_ids = select(AlertEvent.event_id).where(AlertEvent.alert_id == a.id)
    events = db.exec(
        select(Event)
        .where(col(Event.id).in_(event_ids))
        .order_by(col(Event.timestamp), col(Event.id))
        .limit(events_limit)
    ).all()
    total = db.exec(
        select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == a.id)
    ).one()
    return AlertDetail(
        alert=alert_rows(db, [a])[0],
        rule=AlertRuleInfo(
            id=a.rule_id,
            title=rule.title if rule else a.rule_id,
            description=str(spec.get("description", "")).strip(),
            severity=rule.severity if rule else a.severity,
            logic_type=compiled.spec.logic.type if compiled else "unknown",
            primary_tactic=rule.primary_tactic if rule else None,
            techniques=techniques,
            false_positives=[str(x) for x in spec.get("false_positives", [])],
        ),
        events=[EventOut.model_validate(e) for e in events],
        events_total=total,
    )


def _triage_kwargs(body: TriageUpdate) -> dict[str, object]:
    return {
        "status": Status(body.status) if body.status else None,
        "verdict": Verdict(body.verdict) if body.verdict else None,
        "assignee_id": None if body.unassign else body.assignee_id,
        "set_assignee": body.unassign or body.assignee_id is not None,
    }


@router.patch("/{alert_id}", response_model=AlertRow)
def update_alert(
    alert_id: int, body: TriageUpdate, request: Request, user: CurrentUser, db: DB
) -> AlertRow:
    a = _get_alert(db, alert_id)
    try:
        changed = triage.update_alert(db, a, user, ip=client_ip(request), **_triage_kwargs(body))  # type: ignore[arg-type]
    except triage.TriageError as e:
        db.rollback()
        raise APIError(409, "invalid_transition", str(e)) from e
    db.commit()
    if changed:
        hub.publish({"type": "alerts_updated", "ids": [alert_id]})
    return alert_rows(db, [a])[0]


@router.post("/bulk", response_model=BulkResult)
def bulk_update(body: BulkTriage, request: Request, user: CurrentUser, db: DB) -> BulkResult:
    updated, errors = [], {}
    kwargs = _triage_kwargs(body)
    for aid in dict.fromkeys(body.ids):
        a = db.get(Alert, aid)
        if a is None:
            errors[aid] = "not found"
            continue
        try:
            if triage.update_alert(db, a, user, ip=client_ip(request), **kwargs):  # type: ignore[arg-type]
                updated.append(aid)
        except triage.TriageError as e:
            errors[aid] = str(e)
    db.commit()
    if updated:
        hub.publish({"type": "alerts_updated", "ids": updated})
    return BulkResult(updated=updated, errors=errors)


# --------------------------------------------------------------------------- notes & history


def notes_for(db: Session, target_type: str, target_id: int) -> list[NoteOut]:
    rows = db.exec(
        select(Note, User)
        .join(User, col(User.id) == Note.author_id)
        .where(Note.target_type == target_type, Note.target_id == target_id)
        .order_by(col(Note.created_at))
    ).all()
    return [
        NoteOut(
            id=n.id or 0,
            author_id=n.author_id,
            author_name=u.display_name,
            markdown=n.markdown,
            created_at=n.created_at,
        )
        for n, u in rows
    ]


def add_note(
    db: Session, target_type: str, target_id: int, body: NoteCreate, user: User, ip: str | None
) -> NoteOut:
    n = Note(
        target_type=target_type, target_id=target_id, author_id=user.id or 0, markdown=body.markdown
    )
    db.add(n)
    db.flush()
    audit.record_nocommit(
        db,
        f"{target_type}.note",
        actor=user,
        target_type=target_type,
        target_id=target_id,
        after={"note_id": n.id, "chars": len(body.markdown)},
        ip=ip,
    )
    db.commit()
    return NoteOut(
        id=n.id or 0,
        author_id=n.author_id,
        author_name=user.display_name,
        markdown=n.markdown,
        created_at=n.created_at,
    )


def history_for(db: Session, target_type: str, target_id: int) -> list[HistoryEntry]:
    entries = [
        HistoryEntry(
            kind="audit",
            ts=e.ts,
            actor=e.actor_email,
            action=e.action,
            before=e.before,
            after=e.after,
        )
        for e in db.exec(
            select(AuditLog).where(
                AuditLog.target_type == target_type,
                AuditLog.target_id == str(target_id),
                col(AuditLog.action).not_like("%.note"),
            )
        ).all()
    ]
    entries += [
        HistoryEntry(kind="note", ts=n.created_at, actor=n.author_name, note=n)
        for n in notes_for(db, target_type, target_id)
    ]
    return sorted(entries, key=lambda e: e.ts)


@router.get("/{alert_id}/notes", response_model=list[NoteOut])
def list_notes(alert_id: int, _: CurrentUser, db: DB) -> list[NoteOut]:
    _get_alert(db, alert_id)
    return notes_for(db, "alert", alert_id)


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=201)
def create_note(
    alert_id: int, body: NoteCreate, request: Request, user: CurrentUser, db: DB
) -> NoteOut:
    _get_alert(db, alert_id)
    note = add_note(db, "alert", alert_id, body, user, client_ip(request))
    hub.publish({"type": "alerts_updated", "ids": [alert_id]})
    return note


@router.get("/{alert_id}/history", response_model=list[HistoryEntry])
def alert_history(alert_id: int, _: CurrentUser, db: DB) -> list[HistoryEntry]:
    _get_alert(db, alert_id)
    return history_for(db, "alert", alert_id)
