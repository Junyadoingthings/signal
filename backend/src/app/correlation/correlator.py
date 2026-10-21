"""Group related alerts into incidents and score them.

Two open alerts are related when they share an entity (host, user or source IP, as
allowed by each rule's `correlate_on`) and their event times are within the
correlation window. Related alerts land in one incident; if an alert bridges two
existing incidents, they are merged into the older one.

Score (0-100) = worst alert severity
              + a little for each additional alert
              + breadth: distinct ATT&CK tactics involved
              + progression: how many steps follow kill-chain order in time
"""

import logging
from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import or_
from sqlmodel import Session, col, select

from app import attack
from app.detection.engine import Engine
from app.services import audit
from app.services import settings as settings_service
from app.storage.models import Alert, Incident, Rule, Severity, Status, utcnow

log = logging.getLogger("signal.correlation")

SEV_WEIGHT = {"low": 10, "medium": 25, "high": 45, "critical": 70}
SEV_ORDER = ["low", "medium", "high", "critical"]
ALWAYS_EXCLUDED = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",  # noqa: S104 - an entity value to ignore, not a bind address
    "localhost",
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "-",
}


def _excluded(value: str | None, exclusions: set[str]) -> bool:
    if not value:
        return True
    v = value.lower()
    return v in ALWAYS_EXCLUDED or v in exclusions or v.endswith("$")


class Correlator:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def link_keys(self, alert: Alert, exclusions: set[str]) -> list[tuple[str, str]]:
        compiled = self.engine.rules.get(alert.rule_id)
        fields = compiled.spec.correlate_on if compiled else ["host", "user", "src_ip"]
        out = []
        for f in fields:
            v = getattr(alert, f)
            if not _excluded(v, exclusions):
                out.append((f, v))
        return out

    # ------------------------------------------------------------------ entry point

    def on_alerts(self, db: Session, alert_ids: Sequence[int]) -> list[int]:
        """Called after detection. Returns ids of incidents created or changed."""
        settings = settings_service.get_detection(db)
        window = timedelta(minutes=settings.correlation_window_minutes)
        exclusions = {x.lower() for x in settings.correlation_exclusions}
        touched: set[int] = set()

        for aid in alert_ids:
            alert = db.get(Alert, aid)
            if alert is None or alert.status == Status.closed:
                continue
            keys = self.link_keys(alert, exclusions)
            if not keys:
                continue
            related = self._related(db, alert, keys, window, exclusions)
            if not related and alert.incident_id is None:
                continue
            group = [alert, *related]
            incident_ids = sorted({a.incident_id for a in group if a.incident_id is not None})
            if incident_ids:
                incident = db.get(Incident, incident_ids[0])
                if incident is None:
                    continue
                for other_id in incident_ids[1:]:
                    self._merge(db, other_id, incident)
            else:
                incident = Incident(
                    title="",
                    severity=Severity.low,
                    first_event_at=alert.first_event_at,
                    last_event_at=alert.last_event_at,
                )
                db.add(incident)
                db.flush()
                audit.record_nocommit(
                    db, "incident.create", target_type="incident", target_id=incident.id
                )
            for a in group:
                if a.incident_id != incident.id:
                    a.incident_id = incident.id
                    db.add(a)
            db.flush()
            self.rescore(db, incident)
            touched.add(incident.id or 0)
        db.commit()
        return sorted(touched)

    # ------------------------------------------------------------------ internals

    def _related(
        self,
        db: Session,
        alert: Alert,
        keys: list[tuple[str, str]],
        window: timedelta,
        exclusions: set[str],
    ) -> list[Alert]:
        clauses = [getattr(Alert, f) == v for f, v in keys]
        candidates = db.exec(
            select(Alert).where(
                col(Alert.id) != alert.id,
                col(Alert.status) != Status.closed,
                or_(*clauses),
                col(Alert.first_event_at) <= alert.last_event_at + window,
                col(Alert.last_event_at) >= alert.first_event_at - window,
            )
        ).all()
        mine = set(keys)
        # The link must be allowed by the other rule's correlate_on too.
        return [c for c in candidates if mine & set(self.link_keys(c, exclusions))]

    def _merge(self, db: Session, source_id: int, target: Incident) -> None:
        source = db.get(Incident, source_id)
        if source is None or source.id == target.id:
            return
        for a in db.exec(select(Alert).where(Alert.incident_id == source_id)).all():
            a.incident_id = target.id
            db.add(a)
        audit.record_nocommit(
            db,
            "incident.merge",
            target_type="incident",
            target_id=target.id,
            after={"merged_from": source_id},
        )
        db.flush()
        db.delete(source)

    def rescore(self, db: Session, incident: Incident) -> None:
        alerts = list(
            db.exec(
                select(Alert)
                .where(Alert.incident_id == incident.id)
                .order_by(col(Alert.first_event_at), col(Alert.id))
            ).all()
        )
        if not alerts:
            return
        rules = {
            r.id: r
            for r in db.exec(select(Rule).where(col(Rule.id).in_({a.rule_id for a in alerts})))
        }
        story = storyline(alerts, rules)
        tactics = ordered_unique(s["tactic"] for s in story if s["tactic"])
        score, sev = score_incident([a.severity for a in alerts], [s["tactic"] for s in story])

        incident.tactics = tactics
        incident.score = score
        incident.severity = Severity(sev)
        incident.alert_count = len(alerts)
        incident.first_event_at = min(a.first_event_at for a in alerts)
        incident.last_event_at = max(a.last_event_at for a in alerts)
        incident.entities = {
            f: sorted({getattr(a, f) for a in alerts if getattr(a, f)})
            for f in ("host", "user", "src_ip")
        }
        incident.title = make_title(incident.entities, tactics)
        incident.updated_at = utcnow()
        db.add(incident)


def ordered_unique(items: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen)


def story_time(a: Alert) -> Any:
    """When this stage of the attack happened. A sequence alert ("success after brute
    force") happens at its final step, not when its first precursor event occurred."""
    return a.last_event_at if a.match_context.get("type") == "sequence" else a.first_event_at


def storyline(alerts: Sequence[Alert], rules: dict[str, Rule]) -> list[dict[str, Any]]:
    """Alerts in story order with the tactic each one represents."""
    out = []
    for a in sorted(alerts, key=lambda x: (story_time(x), x.id or 0)):
        r = rules.get(a.rule_id)
        out.append(
            {
                "alert_id": a.id,
                "rule_id": a.rule_id,
                "title": r.title if r else a.rule_id,
                "tactic": r.primary_tactic if r else None,
                "techniques": list(r.techniques) if r else [],
                "severity": a.severity,
                "time": story_time(a),
                "status": a.status,
            }
        )
    return out


def _longest_nondecreasing(seq: Sequence[int]) -> int:
    best: list[int] = []  # patience sorting, non-strict
    import bisect

    for x in seq:
        i = bisect.bisect_right(best, x)
        if i == len(best):
            best.append(x)
        else:
            best[i] = x
    return len(best)


def score_incident(
    severities: Sequence[str], tactics_in_time_order: Sequence[str | None]
) -> tuple[int, str]:
    weights = sorted((SEV_WEIGHT[str(s)] for s in severities), reverse=True)
    base = weights[0] + 0.1 * sum(weights[1:])
    order = attack.tactic_order()
    known = [order[t] for t in tactics_in_time_order if t and t in order]
    distinct = len(set(known))
    breadth = 8 * max(0, distinct - 1)
    progression = 6 * max(0, _longest_nondecreasing(known) - 1) if known else 0
    score = min(100, round(base + breadth + progression))

    worst = max(severities, key=lambda s: SEV_ORDER.index(str(s)))
    by_score = (
        "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 30 else "low"
    )
    sev = max(str(worst), by_score, key=SEV_ORDER.index)
    return score, sev


def make_title(entities: dict[str, list[str]], tactics: list[str]) -> str:
    names = {t.shortname: t.name for t in attack.tactics()}
    subject = (
        entities.get("host") or entities.get("user") or entities.get("src_ip") or ["unknown"]
    )[0]
    more = sum(len(v) for v in entities.values()) - 1
    chain = " → ".join(names.get(t, t) for t in tactics) or "Related alerts"
    title = f"{subject}{f' +{more}' if more > 0 else ''} · {chain}"
    return title[:300]
