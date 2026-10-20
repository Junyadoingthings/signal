"""Detection engine: evaluates enabled rules over newly stored events (on ingest) or a
historical range (retro-hunt). Same code path for both.

Windows are measured in event time, not ingest time, so uploading last week's logs
after this week's gives the same alerts as streaming them in order.
"""

import logging
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, col, select

from app.detection import alerts as alert_store
from app.detection.conditions import (
    BusinessHours,
    EvalContext,
    Hit,
    Predicate,
    compile_condition,
    pushdown,
    resolve,
)
from app.detection.schema import (
    FirstSeenLogic,
    MatchLogic,
    RuleSpec,
    SequenceLogic,
    ThresholdLogic,
)
from app.services import settings as settings_service
from app.storage.models import Entity, EntityType, Event, FirstSeenValue, Rule

log = logging.getLogger("signal.detection")

EventDict = dict[str, Any]
EVENT_COLUMNS = [c.name for c in Event.__table__.columns]  # type: ignore[attr-defined]
# Columns usable for SQL equality on group keys (computed/extra fields are filtered in Python).
GROUPABLE = frozenset(EVENT_COLUMNS)
ENTITY_TYPE_FOR = {
    "host": EntityType.host,
    "user": EntityType.user,
    "src_ip": EntityType.ip,
    "dst_ip": EntityType.ip,
    "process_name": EntityType.process,
}

AlertHook = Callable[[Session, list[int]], None]


@dataclass
class CompiledRule:
    spec: RuleSpec
    predicate: Predicate | None  # match / threshold / first_seen
    steps: list[Predicate]  # sequence
    pushdown: dict[str, list[Any]]


def compile_rule(spec: RuleSpec) -> CompiledRule:
    logic = spec.logic
    if isinstance(logic, SequenceLogic):
        return CompiledRule(spec, None, [compile_condition(s.condition) for s in logic.steps], {})
    return CompiledRule(spec, compile_condition(logic.condition), [], pushdown(logic.condition))


def to_dict(ev: Event) -> EventDict:
    return {c: getattr(ev, c) for c in EVENT_COLUMNS}


def _key(event: Mapping[str, Any], fields: Sequence[str]) -> tuple[Any, ...] | None:
    vals = tuple(resolve(event, f) for f in fields)
    return None if any(v is None or v == "" for v in vals) else vals


def _key_str(fields: Sequence[str], values: Sequence[Any]) -> str:
    return "|".join(f"{f}={v}" for f, v in zip(fields, values, strict=True))[:512]


def _fmt_window(td: timedelta) -> str:
    s = int(td.total_seconds())
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s % n == 0 and s >= n:
            return f"{s // n}{unit}"
    return f"{s}s"


class Engine:
    def __init__(self, specs: Iterable[RuleSpec]) -> None:
        self.rules: dict[str, CompiledRule] = {s.id: compile_rule(s) for s in specs}
        self.alert_hooks: list[AlertHook] = []

    # ------------------------------------------------------------------ entry points

    def context(self, db: Session) -> EvalContext:
        d = settings_service.get_detection(db)
        start, end = d.hours()
        from zoneinfo import ZoneInfo

        return EvalContext(
            BusinessHours(start, end, frozenset(d.business_days), ZoneInfo(d.business_timezone))
        )

    def enabled_rules(
        self, db: Session, only: str | None = None
    ) -> list[tuple[Rule, CompiledRule]]:
        stmt = select(Rule).where(col(Rule.enabled))
        if only:
            stmt = select(Rule).where(Rule.id == only)
        out = []
        for row in db.exec(stmt):
            compiled = self.rules.get(row.id)
            if compiled is not None:
                out.append((row, compiled))
        return out

    def on_ingest(self, db: Session, event_ids: list[int]) -> list[int]:
        events = self._load(db, event_ids)
        return self.evaluate(db, events)

    def evaluate(
        self, db: Session, events: list[EventDict], *, only_rule: str | None = None
    ) -> list[int]:
        """Run rules over `events` (already stored). Returns ids of alerts created or
        extended. Commits once at the end."""
        if not events:
            return []
        events.sort(key=lambda e: (e["timestamp"], e["id"]))
        ctx = self.context(db)
        touched: set[int] = set()
        for rule, compiled in self.enabled_rules(db, only_rule):
            try:
                touched.update(self._run(db, rule, compiled, events, ctx))
            except Exception:
                log.exception("rule %s failed", rule.id)
                db.rollback()
        db.commit()
        ids = sorted(touched)
        if ids:
            for hook in self.alert_hooks:
                try:
                    hook(db, ids)
                except Exception:
                    log.exception("alert hook %r failed", hook)
                    db.rollback()
        return ids

    def retro_hunt(
        self,
        db: Session,
        rule_id: str,
        start: datetime,
        end: datetime,
        chunk: int = 5000,
    ) -> dict[str, int]:
        """Re-run one rule over stored events in [start, end]. Idempotent: hits that are
        already alerted extend or skip the existing alert."""
        scanned, alerts = 0, set()
        last_id = 0
        while True:
            rows = db.exec(
                select(Event)
                .where(
                    col(Event.timestamp) >= start,
                    col(Event.timestamp) <= end,
                    col(Event.id) > last_id,
                )
                .order_by(col(Event.id))
                .limit(chunk)
            ).all()
            if not rows:
                break
            last_id = rows[-1].id or last_id
            batch = [to_dict(r) for r in rows]
            scanned += len(batch)
            alerts.update(self.evaluate(db, batch, only_rule=rule_id))
        return {"events_scanned": scanned, "alerts": len(alerts)}

    # ------------------------------------------------------------------ internals

    def _load(self, db: Session, ids: Sequence[int]) -> list[EventDict]:
        out: list[EventDict] = []
        for i in range(0, len(ids), 500):
            rows = db.exec(select(Event).where(col(Event.id).in_(list(ids[i : i + 500])))).all()
            out.extend(to_dict(r) for r in rows)
        return out

    def _run(
        self, db: Session, rule: Rule, c: CompiledRule, events: list[EventDict], ctx: EvalContext
    ) -> set[int]:
        logic = c.spec.logic
        if isinstance(logic, MatchLogic):
            return self._match(db, rule, c, logic, events, ctx)
        if isinstance(logic, ThresholdLogic):
            return self._threshold(db, rule, c, logic, events, ctx)
        if isinstance(logic, SequenceLogic):
            return self._sequence(db, rule, c, logic, events, ctx)
        if isinstance(logic, FirstSeenLogic):
            return self._first_seen(db, rule, c, logic, events, ctx)
        raise TypeError(f"unknown logic {type(logic).__name__}")

    def _window_query(
        self,
        db: Session,
        fields: Sequence[str],
        values: Sequence[Any],
        start: datetime,
        end: datetime,
        push: Mapping[str, list[Any]],
    ) -> list[EventDict]:
        stmt = select(Event).where(col(Event.timestamp) >= start, col(Event.timestamp) <= end)
        for f, v in zip(fields, values, strict=True):
            if f in GROUPABLE:
                stmt = stmt.where(getattr(Event, f) == v)
        for f, vals in push.items():
            stmt = stmt.where(col(getattr(Event, f)).in_(vals))
        rows = db.exec(stmt.order_by(col(Event.timestamp), col(Event.id)).limit(50_000)).all()
        out = [to_dict(r) for r in rows]
        # Group fields that aren't plain columns (computed / extra.*) are checked here.
        return [e for e in out if _key(e, fields) == tuple(values)]

    # -- match

    def _match(
        self,
        db: Session,
        rule: Rule,
        c: CompiledRule,
        logic: MatchLogic,
        events: list[EventDict],
        ctx: EvalContext,
    ) -> set[int]:
        if c.predicate is None:
            return set()
        done = alert_store.events_already_alerted(db, rule.id, [e["id"] for e in events])
        touched: set[int] = set()
        for e in events:
            if e["id"] in done:
                continue
            hits = c.predicate(e, ctx)
            if hits is None:
                continue
            key_vals = tuple(resolve(e, f) for f in logic.suppress.by)
            alert, _ = alert_store.upsert_alert(
                db,
                rule,
                group_key=_key_str(logic.suppress.by, key_vals),
                events=[e],
                hits=hits,
                window=logic.suppress.window,
                context={"type": "match"},
                severity=_dynamic_severity(c.spec, e),
            )
            touched.add(alert.id or 0)
        return touched

    # -- threshold

    def _threshold(
        self,
        db: Session,
        rule: Rule,
        c: CompiledRule,
        logic: ThresholdLogic,
        events: list[EventDict],
        ctx: EvalContext,
    ) -> set[int]:
        if c.predicate is None:
            return set()
        keys: dict[tuple[Any, ...], list[datetime]] = defaultdict(list)
        for e in events:
            k = _key(e, logic.group_by)
            if k is not None and c.predicate(e, ctx) is not None:
                keys[k].append(e["timestamp"])

        touched: set[int] = set()
        for k, times in keys.items():
            window_events = self._window_query(
                db,
                logic.group_by,
                k,
                min(times) - logic.window,
                max(times) + logic.window,
                c.pushdown,
            )
            matched: list[tuple[EventDict, list[Hit]]] = []
            for e in window_events:
                hits = c.predicate(e, ctx)
                if hits is not None:
                    matched.append((e, hits))
            for burst in _bursts(matched, logic.window, logic.threshold, logic.distinct):
                distinct = (
                    len({resolve(e, logic.distinct) for e, _ in burst}) if logic.distinct else None
                )
                alert, _ = alert_store.upsert_alert(
                    db,
                    rule,
                    group_key=_key_str(logic.group_by, k),
                    events=[e for e, _ in burst],
                    hits=burst[-1][1],
                    window=logic.window,
                    context={
                        "type": "threshold",
                        "group": dict(zip(logic.group_by, k, strict=True)),
                        "count": len(burst),
                        "distinct_field": logic.distinct,
                        "distinct": distinct,
                        "threshold": logic.threshold,
                        "window": _fmt_window(logic.window),
                    },
                )
                touched.add(alert.id or 0)
        return touched

    # -- sequence

    def _sequence(
        self,
        db: Session,
        rule: Rule,
        c: CompiledRule,
        logic: SequenceLogic,
        events: list[EventDict],
        ctx: EvalContext,
    ) -> set[int]:
        keys: dict[tuple[Any, ...], list[datetime]] = defaultdict(list)
        for e in events:
            k = _key(e, logic.by)
            if k is not None and any(p(e, ctx) is not None for p in c.steps):
                keys[k].append(e["timestamp"])

        touched: set[int] = set()
        n = len(c.steps)
        for k, times in keys.items():
            window_events = self._window_query(
                db, logic.by, k, min(times) - logic.within, max(times) + logic.within, {}
            )
            per_step: list[list[tuple[EventDict, list[Hit]]]] = [[] for _ in range(n)]
            for e in window_events:
                for i, p in enumerate(c.steps):
                    hits = p(e, ctx)
                    if hits is not None:
                        per_step[i].append((e, hits))

            for final_event, final_hits in per_step[-1]:
                chain = _complete_chain(per_step, logic, final_event)
                if chain is None:
                    continue
                involved = [e for step in chain for e, _ in step] + [final_event]
                alert, _ = alert_store.upsert_alert(
                    db,
                    rule,
                    group_key=_key_str(logic.by, k),
                    events=involved,
                    hits=[h for step in chain for _, hs in step[-1:] for h in hs] + final_hits,
                    window=logic.within,
                    context={
                        "type": "sequence",
                        "group": dict(zip(logic.by, k, strict=True)),
                        "within": _fmt_window(logic.within),
                        "steps": [
                            {"name": s.name, "count": len(chain[i]) if i < n - 1 else 1}
                            for i, s in enumerate(logic.steps)
                        ],
                    },
                )
                touched.add(alert.id or 0)
        return touched

    # -- first seen

    def _first_seen(
        self,
        db: Session,
        rule: Rule,
        c: CompiledRule,
        logic: FirstSeenLogic,
        events: list[EventDict],
        ctx: EvalContext,
    ) -> set[int]:
        if c.predicate is None:
            return set()
        touched: set[int] = set()
        etype = ENTITY_TYPE_FOR.get(logic.entity)
        for e in events:
            ek, val = resolve(e, logic.entity), resolve(e, logic.value)
            if not ek or not val:
                continue
            hits = c.predicate(e, ctx)
            if hits is None:
                continue
            ek_s, val_s = str(ek)[:512], str(val)[:1024]
            seen = db.exec(
                select(FirstSeenValue).where(
                    FirstSeenValue.rule_id == rule.id,
                    FirstSeenValue.entity_key == ek_s,
                    FirstSeenValue.value == val_s,
                )
            ).first()
            if seen is not None:
                if seen.first_seen_at > e["timestamp"]:
                    seen.first_seen_at = e["timestamp"]
                    db.add(seen)
                continue
            db.add(
                FirstSeenValue(
                    rule_id=rule.id, entity_key=ek_s, value=val_s, first_seen_at=e["timestamp"]
                )
            )
            db.flush()

            # Learning period: no alerts until the entity has enough history.
            history_start = None
            if etype is not None:
                history_start = db.exec(
                    select(func.min(Entity.first_seen)).where(
                        Entity.type == etype, Entity.value == ek_s
                    )
                ).one()
            if history_start is None or e["timestamp"] - history_start < logic.min_history:
                continue
            alert, _ = alert_store.upsert_alert(
                db,
                rule,
                group_key=_key_str([logic.entity, logic.value], [ek_s, val_s]),
                events=[e],
                hits=[*hits, Hit(logic.value, "first_seen", f"new for {logic.entity}", val_s)],
                window=timedelta(0),
                context={
                    "type": "first_seen",
                    "entity": {logic.entity: ek_s},
                    "value": {logic.value: val_s},
                    "history_since": history_start.isoformat(),
                },
            )
            touched.add(alert.id or 0)
        return touched


def _dynamic_severity(spec: RuleSpec, event: Mapping[str, Any]) -> Any:
    if "severity_from_wazuh" in spec.tags:
        sev = resolve(event, "extra.wazuh.severity")
        if sev in ("low", "medium", "high", "critical"):
            return sev
    return None


def _bursts(
    matched: list[tuple[EventDict, list[Hit]]],
    window: timedelta,
    threshold: int,
    distinct: str | None,
) -> list[list[tuple[EventDict, list[Hit]]]]:
    """Sliding window over time-ordered matches. Every window that reaches the threshold
    marks its events; overlapping marked windows merge into one burst."""
    marked = [False] * len(matched)
    left = 0
    counts: dict[Any, int] = defaultdict(int)
    for right, (e, _) in enumerate(matched):
        if distinct:
            counts[resolve(e, distinct)] += 1
        while matched[right][0]["timestamp"] - matched[left][0]["timestamp"] > window:
            if distinct:
                v = resolve(matched[left][0], distinct)
                counts[v] -= 1
                if counts[v] == 0:
                    del counts[v]
            left += 1
        size = len([v for v in counts if v is not None]) if distinct else right - left + 1
        if size >= threshold:
            for i in range(left, right + 1):
                marked[i] = True

    bursts: list[list[tuple[EventDict, list[Hit]]]] = []
    current: list[tuple[EventDict, list[Hit]]] = []
    for i, m in enumerate(matched):
        if marked[i]:
            if current and m[0]["timestamp"] - current[-1][0]["timestamp"] > window:
                bursts.append(current)
                current = []
            current.append(m)
        elif current:
            bursts.append(current)
            current = []
    if current:
        bursts.append(current)
    return bursts


def _complete_chain(
    per_step: list[list[tuple[EventDict, list[Hit]]]],
    logic: SequenceLogic,
    final: EventDict,
) -> list[list[tuple[EventDict, list[Hit]]]] | None:
    """Walk backwards from the final step: each earlier step needs `min_count` hits that
    happen before the next step's first hit, all within `within` of the final event."""
    lower = final["timestamp"] - logic.within
    upper = final["timestamp"]
    upper_id = final["id"]
    chain: list[list[tuple[EventDict, list[Hit]]]] = []
    for i in range(len(logic.steps) - 2, -1, -1):
        cands = [
            (e, h)
            for e, h in per_step[i]
            if lower <= e["timestamp"] <= upper and (e["timestamp"], e["id"]) < (upper, upper_id)
        ]
        need = logic.steps[i].min_count
        if len(cands) < need:
            return None
        # Keep every qualifying hit as evidence (capped), but only require the earlier
        # step to precede the point where this step reached its minimum count.
        chain.insert(0, cands[-200:])
        pivot = cands[-need][0]
        upper, upper_id = pivot["timestamp"], pivot["id"]
    return chain
