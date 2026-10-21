from datetime import timedelta

import yaml
from fastapi import APIRouter, Request
from sqlmodel import col, select

from app import attack
from app.api.deps import DB, AdminUser, CurrentUser, client_ip
from app.api.schemas import (
    AttackOut,
    RetroHuntRequest,
    RetroHuntResult,
    RuleDetail,
    RuleOut,
    RuleUpdate,
    TacticOut,
    TechniqueRef,
)
from app.core.errors import APIError
from app.core.ratelimit import limiter
from app.detection.engine import Engine
from app.services import audit
from app.services import settings as settings_service
from app.storage.models import Rule

router = APIRouter(prefix="/api", tags=["detection"])

MAX_RETRO_RANGE = timedelta(days=90)


def _engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def _techniques(ids: list[str]) -> list[TechniqueRef]:
    out = []
    for tid in ids:
        t = attack.technique(tid)
        out.append(TechniqueRef(id=tid, name=t.name if t else None, url=t.url if t else None))
    return out


def _rule_out(row: Rule, engine: Engine) -> RuleOut:
    compiled = engine.rules.get(row.id)
    return RuleOut(
        id=row.id,
        title=row.title,
        severity=row.severity,
        enabled=row.enabled,
        logic_type=compiled.spec.logic.type if compiled else "unknown",
        primary_tactic=row.primary_tactic,
        techniques=_techniques(row.techniques),
        hit_count=row.hit_count,
        last_fired_at=row.last_fired_at,
        tags=list(compiled.spec.tags) if compiled else [],
    )


@router.get("/rules", response_model=list[RuleOut])
def list_rules(request: Request, _: CurrentUser, db: DB) -> list[RuleOut]:
    engine = _engine(request)
    rows = db.exec(select(Rule).order_by(col(Rule.id))).all()
    return [_rule_out(r, engine) for r in rows]


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str, request: Request, _: CurrentUser, db: DB) -> RuleDetail:
    row = db.get(Rule, rule_id)
    if row is None:
        raise APIError(404, "not_found", "Rule not found")
    data = yaml.safe_load(row.yaml)
    return RuleDetail(
        **_rule_out(row, _engine(request)).model_dump(),
        description=str(data.get("description", "")).strip(),
        false_positives=[str(x) for x in data.get("false_positives", [])],
        references=[str(x) for x in data.get("references", [])],
        yaml=row.yaml,
        updated_at=row.updated_at,
    )


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: str, body: RuleUpdate, request: Request, admin: AdminUser, db: DB
) -> RuleOut:
    row = db.get(Rule, rule_id)
    if row is None:
        raise APIError(404, "not_found", "Rule not found")
    before = {"enabled": row.enabled}
    row.enabled = body.enabled
    db.add(row)
    db.commit()
    audit.record(
        db,
        "rule.update",
        actor=admin,
        target_type="rule",
        target_id=rule_id,
        before=before,
        after={"enabled": row.enabled},
        ip=client_ip(request),
    )
    return _rule_out(row, _engine(request))


@router.post("/rules/{rule_id}/retro-hunt", response_model=RetroHuntResult)
@limiter.limit("10/minute")
def retro_hunt(
    rule_id: str, body: RetroHuntRequest, request: Request, user: CurrentUser, db: DB
) -> RetroHuntResult:
    if db.get(Rule, rule_id) is None or rule_id not in _engine(request).rules:
        raise APIError(404, "not_found", "Rule not found")
    if body.end <= body.start or body.end - body.start > MAX_RETRO_RANGE:
        raise APIError(422, "validation_error", "Range must be positive and at most 90 days")
    result = _engine(request).retro_hunt(db, rule_id, body.start, body.end)
    audit.record(
        db,
        "rule.retro_hunt",
        actor=user,
        target_type="rule",
        target_id=rule_id,
        after={"start": body.start.isoformat(), "end": body.end.isoformat(), **result},
        ip=client_ip(request),
    )
    return RetroHuntResult(rule_id=rule_id, **result)


@router.get("/settings/detection", response_model=settings_service.DetectionSettings)
def get_detection_settings(_: CurrentUser, db: DB) -> settings_service.DetectionSettings:
    return settings_service.get_detection(db)


@router.put("/settings/detection", response_model=settings_service.DetectionSettings)
def put_detection_settings(
    body: settings_service.DetectionSettings, request: Request, admin: AdminUser, db: DB
) -> settings_service.DetectionSettings:
    before = settings_service.get_detection(db).model_dump()
    settings_service.put_detection(db, body)
    audit.record(
        db,
        "settings.detection",
        actor=admin,
        target_type="settings",
        target_id="detection",
        before=before,
        after=body.model_dump(),
        ip=client_ip(request),
    )
    return body


@router.get("/attack", response_model=AttackOut)
def attack_matrix(_: CurrentUser, db: DB) -> AttackOut:
    """Tactics in kill-chain order with how many enabled rules cover each."""
    counts: dict[str, int] = {}
    for row in db.exec(select(Rule).where(col(Rule.enabled))).all():
        tactics: set[str] = set()
        for tid in row.techniques:
            t = attack.technique(tid)
            if t:
                tactics.update(t.tactics)
        for tac in tactics:
            counts[tac] = counts.get(tac, 0) + 1
    return AttackOut(
        version=attack.version(),
        tactics=[
            TacticOut(
                id=t.id,
                shortname=t.shortname,
                name=t.name,
                url=t.url,
                rule_count=counts.get(t.shortname, 0),
            )
            for t in attack.tactics()
        ],
    )
