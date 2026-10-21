"""Dashboard numbers. Everything here is computed from stored events, alerts and
incidents; nothing is cached or precomputed."""

from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from sqlalchemy import Integer, case, func
from sqlmodel import col, select

from app.api.deps import DB, CurrentUser
from app.api.hunt import _epoch
from app.api.schemas import (
    AlertMarker,
    Bucket,
    EntityCount,
    Overview,
    RuleCount,
    SeverityCounts,
)
from app.storage.models import Alert, Event, Incident, Outcome, Rule, Status, utcnow

router = APIRouter(prefix="/api", tags=["overview"])

RANGES = {"15m": 900, "1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _bucket_for(seconds: int) -> int:
    for size in (5, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 86400):
        if seconds / size <= 90:
            return size
    return 86400


@router.get("/overview", response_model=Overview)
def overview(
    _: CurrentUser,
    db: DB,
    window: Annotated[Literal["15m", "1h", "24h", "7d", "30d"], Query(alias="range")] = "24h",
    end: datetime | None = None,
) -> Overview:
    end_t = end or utcnow()
    span = RANGES[window]
    start_t = end_t - timedelta(seconds=span)
    size = _bucket_for(span)
    first = int(start_t.timestamp()) // size * size

    idx = ((_epoch(db, Event.timestamp) - first) / size).cast(Integer)
    rows = db.exec(
        select(
            idx.label("i"),
            func.count(),
            func.sum(case((col(Event.outcome) == Outcome.failure, 1), else_=0)),
        )
        .where(col(Event.timestamp) >= start_t, col(Event.timestamp) <= end_t)
        .group_by("i")
    ).all()
    n = int((end_t.timestamp() - first) // size) + 1
    counts, fails = [0] * n, [0] * n
    for i, c, f in rows:
        if 0 <= i < n:
            counts[i], fails[i] = int(c), int(f or 0)

    in_range = (col(Alert.last_event_at) >= start_t) & (col(Alert.first_event_at) <= end_t)
    rule_titles = {r.id: (r.title, r.primary_tactic) for r in db.exec(select(Rule)).all()}

    alerts = db.exec(
        select(Alert).where(in_range).order_by(col(Alert.first_event_at).desc()).limit(500)
    ).all()
    markers = [
        AlertMarker(
            id=a.id or 0,
            ts=a.first_event_at,
            severity=a.severity,
            title=rule_titles.get(a.rule_id, (a.rule_id, None))[0],
        )
        for a in alerts
    ]

    def sev_counts(model: type[Alert] | type[Incident]) -> SeverityCounts:
        out = SeverityCounts()
        for sev, c in db.exec(
            select(model.severity, func.count())
            .where(col(model.status) != Status.closed)
            .group_by(model.severity)
        ).all():
            setattr(out, str(sev), int(c))
        return out

    noisy = db.exec(
        select(Alert.rule_id, func.count(), func.max(Alert.severity))
        .where(in_range)
        .group_by(Alert.rule_id)
        .order_by(func.count().desc())
        .limit(6)
    ).all()
    noisy_rules = [
        RuleCount(
            rule_id=rid,
            title=rule_titles.get(rid, (rid, None))[0],
            severity=next((a.severity for a in alerts if a.rule_id == rid), "low"),
            count=int(c),
        )
        for rid, c, _ in noisy
    ]

    # Top entities by alert count (hosts, users, IPs together), worst severity shown.
    ent: dict[tuple[str, str], list[object]] = {}
    for a in db.exec(select(Alert).where(in_range)).all():
        for etype, v in (("host", a.host), ("user", a.user), ("ip", a.src_ip)):
            if v:
                cur = ent.setdefault((etype, v), [0, "low"])
                cur[0] = int(str(cur[0])) + 1
                if SEV_RANK[str(a.severity)] > SEV_RANK[str(cur[1])]:
                    cur[1] = str(a.severity)
    top_entities = [
        EntityCount(type=t, value=v, count=int(str(c)), top_severity=str(s))
        for (t, v), (c, s) in sorted(ent.items(), key=lambda kv: -int(str(kv[1][0])))[:6]
    ]

    fired: dict[str, int] = {}
    for a in alerts:
        tac = rule_titles.get(a.rule_id, ("", None))[1]
        if tac:
            fired[tac] = fired.get(tac, 0) + 1

    closed = db.exec(
        select(Alert).where(
            col(Alert.closed_at) >= start_t,
            col(Alert.closed_at) <= end_t,
            col(Alert.closed_at).is_not(None),
        )
    ).all()
    durations = [(a.closed_at - a.created_at).total_seconds() for a in closed if a.closed_at]
    verdicts: dict[str, int] = {}
    for a in closed:
        if a.verdict:
            verdicts[str(a.verdict)] = verdicts.get(str(a.verdict), 0) + 1

    return Overview(
        start=start_t,
        end=end_t,
        bucket_seconds=size,
        buckets=[
            Bucket(
                start=datetime.fromtimestamp(first + k * size, start_t.tzinfo),
                count=counts[k],
                failures=fails[k],
            )
            for k in range(n)
        ],
        events_total=sum(counts),
        markers=markers,
        open_incidents=sev_counts(Incident),
        open_alerts=sev_counts(Alert),
        noisy_rules=noisy_rules,
        top_entities=top_entities,
        fired_tactics=fired,
        mttr_seconds=sum(durations) / len(durations) if durations else None,
        closed_count=len(closed),
        verdicts=verdicts,
    )
