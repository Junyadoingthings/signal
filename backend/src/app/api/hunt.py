"""Hunt: query-language search over events, histogram, saved searches."""

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from sqlalchemy import Integer, case, cast, func
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

from app.api.deps import DB, CurrentUser, client_ip
from app.api.schemas import (
    Bucket,
    EventOut,
    Histogram,
    HuntResult,
    SavedSearchIn,
    SavedSearchOut,
)
from app.core.config import get_settings
from app.core.errors import APIError
from app.core.ratelimit import limiter
from app.search.compiler import FIELD_NAMES, compile_node
from app.search.parser import SearchError, parse
from app.services import audit
from app.storage.models import Event, Outcome, SavedSearch, utcnow

router = APIRouter(prefix="/api", tags=["hunt"])

MAX_RANGE = timedelta(days=366)
TARGET_BUCKETS = 60
NICE = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400]


def _where(query: str, start: datetime, end: datetime) -> list[ColumnElement[bool]]:
    if end <= start or end - start > MAX_RANGE:
        raise APIError(422, "validation_error", "Time range must be positive and at most a year")
    try:
        node = parse(query)
        cond = compile_node(node) if node is not None else None
    except SearchError as e:
        raise APIError(
            422, "invalid_query", e.message, {"pos": e.pos, "fields": FIELD_NAMES}
        ) from e
    clauses = [col(Event.timestamp) >= start, col(Event.timestamp) <= end]
    if cond is not None:
        clauses.append(cond)
    return clauses


@router.get("/hunt", response_model=HuntResult)
@limiter.limit(lambda: get_settings().ingest_rate_limit)
def hunt(
    request: Request,
    _: CurrentUser,
    db: DB,
    start: datetime,
    end: datetime,
    q: Annotated[str, Query(max_length=1000)] = "",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> HuntResult:
    where = _where(q, start, end)
    total = db.exec(select(func.count()).select_from(Event).where(*where)).one()
    rows = db.exec(
        select(Event)
        .where(*where)
        .order_by(col(Event.timestamp).desc(), col(Event.id).desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return HuntResult(
        items=[EventOut.model_validate(r) for r in rows], total=total, offset=offset, limit=limit
    )


def bucket_size(span: timedelta) -> int:
    want = span.total_seconds() / TARGET_BUCKETS
    return next((n for n in NICE if n >= want), NICE[-1])


def _epoch(db: Session, column: Any) -> Any:
    if db.get_bind().dialect.name == "postgresql":
        return func.extract("epoch", column)
    return cast(func.strftime("%s", column), Integer)


@router.get("/hunt/histogram", response_model=Histogram)
def histogram(
    _: CurrentUser,
    db: DB,
    start: datetime,
    end: datetime,
    q: Annotated[str, Query(max_length=1000)] = "",
) -> Histogram:
    where = _where(q, start, end)
    size = bucket_size(end - start)
    first = int(start.timestamp()) // size * size
    idx = ((_epoch(db, Event.timestamp) - first) / size).cast(Integer)
    rows = db.exec(
        select(
            idx.label("i"),
            func.count(),
            func.sum(case((col(Event.outcome) == Outcome.failure, 1), else_=0)),
        )
        .where(*where)
        .group_by("i")
    ).all()
    n = int((end.timestamp() - first) // size) + 1
    counts = [0] * n
    fails = [0] * n
    for i, c, f in rows:
        if 0 <= i < n:
            counts[i], fails[i] = int(c), int(f or 0)
    return Histogram(
        start=start,
        end=end,
        bucket_seconds=size,
        total=sum(counts),
        buckets=[
            Bucket(
                start=datetime.fromtimestamp(first + k * size, start.tzinfo),
                count=counts[k],
                failures=fails[k],
            )
            for k in range(n)
        ],
    )


@router.get("/hunt/fields", response_model=list[str])
def fields(_: CurrentUser) -> list[str]:
    return FIELD_NAMES


# ------------------------------------------------------------------ saved searches


@router.get("/searches", response_model=list[SavedSearchOut])
def list_searches(user: CurrentUser, db: DB) -> list[SavedSearch]:
    return list(
        db.exec(
            select(SavedSearch)
            .where(SavedSearch.owner_id == user.id)
            .order_by(col(SavedSearch.name))
        ).all()
    )


@router.post("/searches", response_model=SavedSearchOut, status_code=201)
def save_search(body: SavedSearchIn, request: Request, user: CurrentUser, db: DB) -> SavedSearch:
    try:
        if node := parse(body.query):  # validate before saving
            compile_node(node)
    except SearchError as e:
        raise APIError(422, "invalid_query", e.message, {"pos": e.pos}) from e
    row = SavedSearch(
        owner_id=user.id or 0,
        name=body.name,
        query=body.query,
        time_range=body.time_range,
        created_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(
        db,
        "search.save",
        actor=user,
        target_type="search",
        target_id=row.id,
        after={"name": row.name},
        ip=client_ip(request),
    )
    return row


@router.delete("/searches/{search_id}", status_code=204)
def delete_search(search_id: int, user: CurrentUser, db: DB) -> None:
    row = db.get(SavedSearch, search_id)
    if row is None or row.owner_id != user.id:  # other people's searches look nonexistent
        raise APIError(404, "not_found", "Saved search not found")
    db.delete(row)
    db.commit()
