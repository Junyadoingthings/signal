"""Create or extend alerts.

A rule hitting the same group key again within its window extends the existing open
alert (more events, later last_event_at) instead of opening a new one. That keeps a
brute force of 5,000 attempts as one alert, and makes re-running a rule over the same
data (retro-hunt) idempotent.
"""

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, col, select

from app.detection.conditions import Hit
from app.storage.models import Alert, AlertEvent, Rule, Severity, Status, utcnow

MAX_LINKED_EVENTS = 1000


def _mode(values: Iterable[Any]) -> Any:
    counts = Counter(v for v in values if v)
    return counts.most_common(1)[0][0] if counts else None


def upsert_alert(
    db: Session,
    rule: Rule,
    *,
    group_key: str,
    events: Sequence[Mapping[str, Any]],
    hits: Sequence[Hit],
    window: timedelta,
    context: dict[str, Any],
    severity: Severity | None = None,
    primary: Mapping[str, Any] | None = None,
) -> tuple[Alert, bool]:
    """Returns (alert, created)."""
    if not events:
        raise ValueError("an alert needs at least one event")
    first: datetime = min(e["timestamp"] for e in events)
    last: datetime = max(e["timestamp"] for e in events)

    alert = db.exec(
        select(Alert)
        .where(
            Alert.rule_id == rule.id,
            Alert.group_key == group_key,
            col(Alert.status) != Status.closed,
            col(Alert.last_event_at) >= first - window,
            col(Alert.first_event_at) <= last + window,
        )
        .order_by(col(Alert.last_event_at).desc())
    ).first()

    def entity(field: str) -> Any:
        # The event that completed the detection names the entity when there is one
        # (e.g. the account that logged in after a brute force, not the guessed ones).
        if primary is not None and primary.get(field):
            return primary.get(field)
        return _mode(e.get(field) for e in events)

    created = alert is None
    if alert is None:
        alert = Alert(
            rule_id=rule.id,
            severity=severity or rule.severity,
            group_key=group_key,
            host=entity("host"),
            user=entity("user"),
            src_ip=entity("src_ip"),
            first_event_at=first,
            last_event_at=last,
            match_context={},
        )
    else:
        alert.first_event_at = min(alert.first_event_at, first)
        alert.last_event_at = max(alert.last_event_at, last)
        alert.host = alert.host or entity("host")
        alert.user = alert.user or entity("user")
        alert.src_ip = alert.src_ip or entity("src_ip")

    alert.match_context = {
        **context,
        "matched": [h.as_dict() for h in hits],
    }
    db.add(alert)
    db.flush()
    if alert.id is None:
        raise RuntimeError("alert was not assigned an id")

    linked = set(db.exec(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)).all())
    room = MAX_LINKED_EVENTS - len(linked)
    for e in events:
        if room <= 0:
            break
        if e["id"] not in linked:
            db.add(AlertEvent(alert_id=alert.id, event_id=e["id"]))
            linked.add(e["id"])
            room -= 1
    db.flush()
    alert.event_count = db.exec(
        select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert.id)
    ).one()

    now = utcnow()
    if created:
        rule.hit_count += 1
    rule.last_fired_at = now
    db.add(alert)
    db.add(rule)
    return alert, created


def events_already_alerted(db: Session, rule_id: str, event_ids: Sequence[int]) -> set[int]:
    if not event_ids:
        return set()
    rows = db.exec(
        select(AlertEvent.event_id)
        .join(Alert, col(Alert.id) == AlertEvent.alert_id)
        .where(Alert.rule_id == rule_id, col(AlertEvent.event_id).in_(list(event_ids)))
    ).all()
    return set(rows)
