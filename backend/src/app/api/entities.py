"""Entity pages: summary, timeline, related alerts and a 2-hop relationship graph."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query
from sqlalchemy import func, or_
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

from app.api.alerts import alert_rows
from app.api.deps import DB, CurrentUser
from app.api.schemas import EntityDetail, EntityOut, EventOut, GraphEdge, GraphNode
from app.core.errors import APIError
from app.search.compiler import _like
from app.storage.models import Alert, Entity, EntityEdge, EntityType, Event

router = APIRouter(prefix="/api/entities", tags=["entities"])

MAX_NODES = 60
HOP1_LIMIT = 24
HOP2_PER_NODE = 6


def _alert_filter(etype: EntityType, value: str) -> ColumnElement[bool] | None:
    if etype == EntityType.host:
        return col(Alert.host) == value
    if etype == EntityType.user:
        return col(Alert.user) == value
    if etype == EntityType.ip:
        return col(Alert.src_ip) == value
    return None


def _event_filter(etype: EntityType, value: str) -> ColumnElement[bool]:
    if etype == EntityType.host:
        return col(Event.host) == value
    if etype == EntityType.user:
        return col(Event.user) == value
    if etype == EntityType.ip:
        return or_(col(Event.src_ip) == value, col(Event.dst_ip) == value)
    if etype == EntityType.process:
        return col(Event.process_name) == value
    pattern, _ = _like(value)
    return or_(
        col(Event.dns_query) == value, col(Event.dns_query).like(f"%.{pattern}", escape="\\")
    )


@router.get("", response_model=list[EntityOut])
def search_entities(
    _: CurrentUser,
    db: DB,
    q: Annotated[str, Query(min_length=1, max_length=255)],
    type: Annotated[Literal["host", "user", "ip", "process", "domain"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 15,
) -> list[Entity]:
    pattern, _w = _like(q)
    stmt = select(Entity).where(col(Entity.value).ilike(f"%{pattern}%", escape="\\"))
    if type:
        stmt = stmt.where(Entity.type == EntityType(type))
    return list(db.exec(stmt.order_by(col(Entity.event_count).desc()).limit(limit)).all())


def _graph(db: Session, center: Entity) -> tuple[list[GraphNode], list[GraphEdge]]:
    center_id = center.id or 0
    nodes: dict[int, GraphNode] = {
        center_id: GraphNode(
            id=str(center.id),
            type=center.type,
            value=center.value,
            event_count=center.event_count,
            hop=0,
        )
    }
    edges: dict[tuple[int, int, str], GraphEdge] = {}

    def expand(entity_id: int, hop: int, limit: int) -> list[int]:
        rows = db.exec(
            select(EntityEdge)
            .where(
                or_(
                    col(EntityEdge.src_entity_id) == entity_id,
                    col(EntityEdge.dst_entity_id) == entity_id,
                )
            )
            .order_by(col(EntityEdge.count).desc())
            .limit(limit)
        ).all()
        found = []
        for e in rows:
            other = e.dst_entity_id if e.src_entity_id == entity_id else e.src_entity_id
            if other not in nodes:
                if len(nodes) >= MAX_NODES:
                    continue
                o = db.get(Entity, other)
                if o is None:
                    continue
                nodes[other] = GraphNode(
                    id=str(other), type=o.type, value=o.value, event_count=o.event_count, hop=hop
                )
                found.append(other)
            key = (e.src_entity_id, e.dst_entity_id, e.relation)
            edges[key] = GraphEdge(
                source=str(e.src_entity_id),
                target=str(e.dst_entity_id),
                relation=e.relation,
                count=e.count,
            )
        return found

    for nid in expand(center_id, 1, HOP1_LIMIT):
        expand(nid, 2, HOP2_PER_NODE)
    # keep only edges whose both ends made it into the graph
    kept = [e for e in edges.values() if int(e.source) in nodes and int(e.target) in nodes]
    return list(nodes.values()), kept


@router.get("/detail", response_model=EntityDetail)
def entity_detail(
    _: CurrentUser,
    db: DB,
    type: Literal["host", "user", "ip", "process", "domain"],
    value: Annotated[str, Query(min_length=1, max_length=512)],
    events_limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> EntityDetail:
    etype = EntityType(type)
    ent = db.exec(select(Entity).where(Entity.type == etype, Entity.value == value)).first()
    if ent is None:
        raise APIError(404, "not_found", "No such entity has been seen")

    ev_filter = _event_filter(etype, value)
    events = db.exec(
        select(Event)
        .where(ev_filter)
        .order_by(col(Event.timestamp).desc(), col(Event.id).desc())
        .limit(events_limit)
    ).all()
    action_rows = db.exec(
        select(Event.action, func.count()).where(ev_filter).group_by(Event.action)
    ).all()
    actions = {(a or "other"): int(c) for a, c in action_rows}

    alerts: list[Alert] = []
    af = _alert_filter(etype, value)
    if af is not None:
        alerts = list(
            db.exec(select(Alert).where(af).order_by(col(Alert.created_at).desc()).limit(100)).all()
        )
    nodes, edges = _graph(db, ent)
    return EntityDetail(
        entity=EntityOut.model_validate(ent, from_attributes=True),
        actions=dict(sorted(actions.items(), key=lambda kv: -kv[1])),
        alerts=alert_rows(db, alerts),
        incident_ids=sorted({a.incident_id for a in alerts if a.incident_id}),
        events=[EventOut.model_validate(e) for e in events],
        nodes=nodes,
        edges=edges,
    )
