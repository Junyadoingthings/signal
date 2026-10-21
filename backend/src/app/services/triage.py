"""Triage state machine for alerts and incidents, with an audit entry for every change.

Status: new → investigating → closed (and closed → investigating to reopen).
Closing requires a verdict; reopening clears it. Leaving `new` stamps acknowledged_at,
which (with closed_at) feeds the MTTR stat.
"""

from typing import Any

from sqlmodel import Session, select

from app.services import audit
from app.storage.models import Alert, Incident, Status, User, Verdict, utcnow

TRANSITIONS: dict[Status, set[Status]] = {
    Status.new: {Status.investigating, Status.closed},
    Status.investigating: {Status.closed, Status.new},
    Status.closed: {Status.investigating},
}


class TriageError(ValueError):
    pass


def _check_assignee(db: Session, assignee_id: int | None) -> None:
    if assignee_id is None:
        return
    u = db.get(User, assignee_id)
    if u is None or not u.is_active:
        raise TriageError("assignee must be an active user")


def _snapshot(obj: Alert | Incident) -> dict[str, Any]:
    return {
        "status": str(obj.status),
        "verdict": str(obj.verdict) if obj.verdict else None,
        "assignee_id": obj.assignee_id,
    }


def _apply(
    obj: Alert | Incident,
    *,
    status: Status | None,
    verdict: Verdict | None,
    assignee_id: int | None,
    set_assignee: bool,
) -> None:
    now = utcnow()
    if status is not None and status != obj.status:
        if status not in TRANSITIONS[obj.status]:
            raise TriageError(f"cannot move from {obj.status} to {status}")
        if status == Status.closed:
            if (verdict or obj.verdict) is None:
                raise TriageError("closing requires a verdict")
            obj.closed_at = now
        if obj.status == Status.closed:  # reopening
            obj.closed_at = None
            obj.verdict = None
        obj.status = status
    if verdict is not None:
        if (status or obj.status) != Status.closed:
            raise TriageError("a verdict can only be set when closing")
        obj.verdict = verdict
    if set_assignee:
        obj.assignee_id = assignee_id
    if isinstance(obj, Alert) and obj.status != Status.new and obj.acknowledged_at is None:
        obj.acknowledged_at = now
    if isinstance(obj, Incident):
        obj.updated_at = now


def update_alert(
    db: Session,
    alert: Alert,
    actor: User,
    *,
    status: Status | None = None,
    verdict: Verdict | None = None,
    assignee_id: int | None = None,
    set_assignee: bool = False,
    ip: str | None = None,
) -> bool:
    """Returns True when something changed. Does not commit."""
    if set_assignee:
        _check_assignee(db, assignee_id)
    before = _snapshot(alert)
    _apply(
        alert, status=status, verdict=verdict, assignee_id=assignee_id, set_assignee=set_assignee
    )
    after = _snapshot(alert)
    if before == after:
        return False
    db.add(alert)
    audit.record_nocommit(
        db,
        "alert.update",
        actor=actor,
        target_type="alert",
        target_id=alert.id,
        before=before,
        after=after,
        ip=ip,
    )
    return True


def update_incident(
    db: Session,
    incident: Incident,
    actor: User,
    *,
    status: Status | None = None,
    verdict: Verdict | None = None,
    assignee_id: int | None = None,
    set_assignee: bool = False,
    close_alerts: bool = False,
    ip: str | None = None,
) -> list[int]:
    """Returns ids of alerts that were closed alongside. Does not commit."""
    if set_assignee:
        _check_assignee(db, assignee_id)
    before = _snapshot(incident)
    _apply(
        incident, status=status, verdict=verdict, assignee_id=assignee_id, set_assignee=set_assignee
    )
    after = _snapshot(incident)
    closed: list[int] = []
    if before != after:
        db.add(incident)
        audit.record_nocommit(
            db,
            "incident.update",
            actor=actor,
            target_type="incident",
            target_id=incident.id,
            before=before,
            after=after,
            ip=ip,
        )
    if close_alerts and incident.status == Status.closed and incident.verdict is not None:
        for a in db.exec(select(Alert).where(Alert.incident_id == incident.id)).all():
            if a.status != Status.closed and update_alert(
                db, a, actor, status=Status.closed, verdict=incident.verdict, ip=ip
            ):
                closed.append(a.id or 0)
    return closed
