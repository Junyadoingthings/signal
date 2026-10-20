"""Parse → dedup → store, in chunks, with entity/edge upserts and post-ingest hooks.

Works the same for file uploads (run on the ingest worker thread) and live batches (run
inline in the request). Callers own the Session; each chunk commits on its own so a huge
upload shows progress and a failure mid-file keeps what was already stored.
"""

import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from itertools import islice
from typing import Any

from sqlalchemy import func, insert, select, tuple_
from sqlalchemy.dialects import postgresql, sqlite
from sqlmodel import Session, col

from app.ingest.dedup import DedupKeyer
from app.ingest.entities import EdgeKey, EntityKey, Seen, aggregate
from app.ingest.types import NormalizedEvent, Parsed, ParseResult, Unparsed
from app.storage.models import Entity, EntityEdge, Event, IngestBatch, UnparsedEvent, utcnow

log = logging.getLogger("signal.ingest")

CHUNK_SIZE = 1000

# Called with (session, ids of newly stored events) after every chunk commit. Detection
# registers itself here.
PostIngestHook = Callable[[Session, list[int]], None]
post_ingest_hooks: list[PostIngestHook] = []


@dataclass(slots=True)
class Counts:
    parsed: int = 0
    unparsed: int = 0
    duplicates: int = 0
    inserted_ids: list[int] = field(default_factory=list)

    def add(self, other: "Counts") -> None:
        self.parsed += other.parsed
        self.unparsed += other.unparsed
        self.duplicates += other.duplicates
        self.inserted_ids.extend(other.inserted_ids)


def _event_row(ev: NormalizedEvent, batch_id: int | None, key: str) -> dict[str, Any]:
    return {
        "timestamp": ev.timestamp,
        "ingested_at": utcnow(),
        "batch_id": batch_id,
        "dedup_hash": key,
        "source_type": ev.source_type,
        "host": ev.host,
        "user": ev.user,
        "src_ip": ev.src_ip,
        "dst_ip": ev.dst_ip,
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "process_name": ev.process_name,
        "process_cmdline": ev.process_cmdline,
        "parent_process": ev.parent_process,
        "event_code": ev.event_code,
        "action": ev.action,
        "outcome": ev.outcome,
        "dns_query": ev.dns_query,
        "url": ev.url,
        "http_status": ev.http_status,
        "user_agent": ev.user_agent,
        "raw": ev.raw,
        "tags": ev.tags,
        "extra": ev.extra,
    }


def _dialect_insert(db: Session, table: Any) -> Any:
    name = db.get_bind().dialect.name
    if name == "sqlite":
        return sqlite.insert(table)
    if name == "postgresql":
        return postgresql.insert(table)
    raise NotImplementedError(f"upsert not implemented for {name}")


def _least_greatest(db: Session) -> tuple[Any, Any]:
    if db.get_bind().dialect.name == "sqlite":
        return func.min, func.max  # SQLite's scalar min/max take several arguments
    return func.least, func.greatest


def _upsert_entities(db: Session, ents: dict[EntityKey, Seen]) -> dict[EntityKey, int]:
    if not ents:
        return {}
    least, greatest = _least_greatest(db)
    t = Entity.__table__  # type: ignore[attr-defined]
    stmt = _dialect_insert(db, t)
    stmt = stmt.on_conflict_do_update(
        index_elements=["type", "value"],
        set_={
            "first_seen": least(t.c.first_seen, stmt.excluded.first_seen),
            "last_seen": greatest(t.c.last_seen, stmt.excluded.last_seen),
            "event_count": t.c.event_count + stmt.excluded.event_count,
        },
    )
    db.execute(
        stmt,
        [
            {
                "type": k[0],
                "value": k[1][:512],
                "first_seen": s.first,
                "last_seen": s.last,
                "event_count": s.count,
            }
            for k, s in ents.items()
        ],
    )
    keys = [(k[0].name, k[1][:512]) for k in ents]
    ids: dict[EntityKey, int] = {}
    for i in range(0, len(keys), 400):
        part = keys[i : i + 400]
        rows = db.execute(
            select(t.c.id, t.c.type, t.c.value).where(tuple_(t.c.type, t.c.value).in_(part))
        ).all()
        for row in rows:
            ids[(row.type, row.value)] = row.id
    return ids


def _upsert_edges(db: Session, edges: dict[EdgeKey, Seen], ids: dict[EntityKey, int]) -> None:
    rows = []
    for (a, b, rel), s in edges.items():
        ia, ib = ids.get((a[0], a[1][:512])), ids.get((b[0], b[1][:512]))
        if ia is None or ib is None or ia == ib:
            continue
        rows.append(
            {
                "src_entity_id": ia,
                "dst_entity_id": ib,
                "relation": rel,
                "count": s.count,
                "first_seen": s.first,
                "last_seen": s.last,
            }
        )
    if not rows:
        return
    least, greatest = _least_greatest(db)
    t = EntityEdge.__table__  # type: ignore[attr-defined]
    stmt = _dialect_insert(db, t)
    stmt = stmt.on_conflict_do_update(
        index_elements=["src_entity_id", "dst_entity_id", "relation"],
        set_={
            "first_seen": least(t.c.first_seen, stmt.excluded.first_seen),
            "last_seen": greatest(t.c.last_seen, stmt.excluded.last_seen),
            "count": t.c.count + stmt.excluded.count,
        },
    )
    db.execute(stmt, rows)


def _existing(db: Session, column: Any, keys: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(keys), 500):
        stmt = select(column).where(column.in_(keys[i : i + 500]))
        found.update(db.execute(stmt).scalars())
    return found


def store_chunk(
    db: Session,
    batch_id: int | None,
    results: list[ParseResult],
    keyer: DedupKeyer,
    seqs: list[str | None] | None = None,
) -> Counts:
    counts = Counts()
    keyed: list[tuple[str, NormalizedEvent]] = []
    unparsed_rows: list[dict[str, Any]] = []

    for i, r in enumerate(results):
        seq = seqs[i] if seqs else None
        raw_key = r.raw if isinstance(r, Unparsed) else r.event.raw
        raw_key = raw_key if seq is None else f"{seq}\0{raw_key}"
        if isinstance(r, Parsed):
            keyed.append((keyer.key(r.event.source_type, raw_key), r.event))
        else:
            # Unparsed records are deduplicated the same way, so a re-sent file doesn't
            # fill the bucket with copies.
            unparsed_rows.append(
                {
                    "batch_id": batch_id,
                    "line_no": r.line_no,
                    "dedup_hash": keyer.key("unparsed", raw_key),
                    "raw": r.raw,
                    "reason": r.reason[:512],
                    "created_at": utcnow(),
                }
            )

    existing = _existing(db, col(Event.dedup_hash), [k for k, _ in keyed])
    fresh = [(k, ev) for k, ev in keyed if k not in existing]
    seen_unparsed = _existing(
        db, col(UnparsedEvent.dedup_hash), [u["dedup_hash"] for u in unparsed_rows]
    )
    new_unparsed = [u for u in unparsed_rows if u["dedup_hash"] not in seen_unparsed]
    counts.duplicates = len(keyed) - len(fresh) + len(unparsed_rows) - len(new_unparsed)
    counts.parsed = len(fresh)
    counts.unparsed = len(new_unparsed)

    if fresh:
        t = Event.__table__  # type: ignore[attr-defined]
        rows = [_event_row(ev, batch_id, k) for k, ev in fresh]
        counts.inserted_ids = list(db.execute(insert(t).returning(t.c.id), rows).scalars())
        ents, edges = aggregate(ev for _, ev in fresh)
        ids = _upsert_entities(db, ents)
        _upsert_edges(db, edges, ids)
    if new_unparsed:
        db.execute(insert(UnparsedEvent.__table__), new_unparsed)  # type: ignore[attr-defined]

    if batch_id is not None:
        batch = db.get(IngestBatch, batch_id)
        if batch is not None:
            batch.parsed_count += counts.parsed
            batch.unparsed_count += counts.unparsed
            batch.duplicate_count += counts.duplicates
            db.add(batch)
    db.commit()

    if counts.inserted_ids:
        for hook in post_ingest_hooks:
            try:
                hook(db, counts.inserted_ids)
            except Exception:
                log.exception("post-ingest hook %r failed", hook)
                db.rollback()
    return counts


def _chunks(it: Iterable[ParseResult], n: int) -> Iterator[list[ParseResult]]:
    iterator = iter(it)
    while chunk := list(islice(iterator, n)):
        yield chunk


def ingest(
    db: Session,
    batch_id: int | None,
    results: Iterable[ParseResult],
    keyer: DedupKeyer | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> Counts:
    keyer = keyer or DedupKeyer()
    total = Counts()
    for chunk in _chunks(results, chunk_size):
        part = store_chunk(db, batch_id, chunk, keyer)
        total.add(part)
        total.inserted_ids = total.inserted_ids[-10_000:]  # bounded: only recent ids kept
    return total
