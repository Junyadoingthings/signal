"""Upload and live ingest orchestration, plus the background worker for file batches."""

import logging
import queue
import shutil
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from sqlmodel import Session, col, select

from app.core.config import Settings
from app.ingest import pipeline
from app.ingest.dedup import DedupKeyer
from app.ingest.parsers import dispatch
from app.ingest.parsers.generic_jsonl import validate_mapping
from app.ingest.sniff import Format, SniffError, compatible, sniff
from app.ingest.types import ParseContext
from app.services import settings as settings_service
from app.storage.db import get_engine
from app.storage.models import IngestBatch, utcnow

log = logging.getLogger("signal.ingest")

SNIFF_BYTES = 64 * 1024


class IngestError(ValueError):
    pass


class MappingRequiredError(IngestError):
    pass


def _context(db: Session, *, host: str | None, mapping: dict[str, str] | None) -> ParseContext:
    s = settings_service.get_ingest(db)
    return ParseContext(
        syslog_tz=s.tz,
        syslog_year=s.syslog_year,
        now=utcnow(),
        field_mapping=mapping,
        default_host=host,
    )


def _check_mapping(fmt: Format, mapping: dict[str, str] | None) -> dict[str, str] | None:
    if fmt == "generic_jsonl":
        if not mapping:
            raise MappingRequiredError(
                "generic JSON Lines needs a field mapping (at least 'timestamp')"
            )
        try:
            return validate_mapping(mapping)
        except ValueError as e:
            raise MappingRequiredError(str(e)) from e
    return None


# --------------------------------------------------------------------------- uploads


def save_upload(src: IO[bytes], dest_dir: Path, max_bytes: int) -> tuple[Path, int, bytes]:
    """Copy an upload to our own spool file, enforcing the size limit while streaming.
    Returns (path, size, first bytes for sniffing)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{uuid.uuid4().hex}.upload"
    size = 0
    head = b""
    try:
        with path.open("wb") as out:
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise IngestError(f"file exceeds the {max_bytes // (1024 * 1024)} MB limit")
                if len(head) < SNIFF_BYTES:
                    head += chunk[: SNIFF_BYTES - len(head)]
                out.write(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path, size, head


def resolve_format(requested: str, head: bytes) -> Format:
    try:
        sniffed = sniff(head)
    except SniffError as e:
        raise IngestError(str(e)) from e
    if requested == "auto":
        return sniffed
    if requested not in dispatch.LIVE_FORMATS and requested != "evtx":
        raise IngestError(f"unknown format {requested!r}")
    req: Format = requested  # type: ignore[assignment]
    if not compatible(req, sniffed):
        raise IngestError(f"content looks like {sniffed}, not {requested}")
    return req


@dataclass(frozen=True, slots=True)
class FileJob:
    batch_id: int
    path: Path
    fmt: Format
    host: str | None
    mapping: dict[str, str] | None


def create_upload_batch(
    db: Session,
    *,
    path: Path,
    size: int,
    head: bytes,
    requested_format: str,
    filename: str | None,
    host: str | None,
    mapping: dict[str, str] | None,
    user_id: int | None,
) -> tuple[IngestBatch, FileJob]:
    fmt = resolve_format(requested_format, head)
    mapping = _check_mapping(fmt, mapping)
    s = settings_service.get_ingest(db)
    batch = IngestBatch(
        source_type=fmt,
        kind="upload",
        filename=Path(filename or "upload").name[:255],
        default_host=host,
        size_bytes=size,
        status="pending",
        tz_assumption=s.syslog_timezone if fmt == "linux_auth" else None,
        year_assumption=(s.syslog_year or utcnow().year) if fmt == "linux_auth" else None,
        created_by=user_id,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    if batch.id is None:
        raise RuntimeError("batch was not assigned an id")
    return batch, FileJob(batch.id, path, fmt, host, mapping)


def run_file_job(job: FileJob) -> None:
    with Session(get_engine(), expire_on_commit=False) as db:
        batch = db.get(IngestBatch, job.batch_id)
        if batch is None:
            job.path.unlink(missing_ok=True)
            return
        batch.status = "running"
        db.add(batch)
        db.commit()
        try:
            ctx = _context(db, host=job.host, mapping=job.mapping)
            pipeline.ingest(db, job.batch_id, dispatch.parse_file(job.fmt, job.path, ctx))
            status, error = "done", None
        except Exception as e:
            log.exception("ingest batch %s failed", job.batch_id)
            db.rollback()
            status, error = "failed", f"{type(e).__name__}: {e}"[:500]
        finally:
            job.path.unlink(missing_ok=True)
        final = db.get(IngestBatch, job.batch_id)
        if final is not None:
            final.status, final.error, final.finished_at = status, error, utcnow()
            db.add(final)
            db.commit()


class IngestWorker:
    """One background thread processing uploads in order. SQLite has a single writer,
    so serial processing is the right default."""

    def __init__(self) -> None:
        self._q: queue.Queue[FileJob | None] = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="ingest-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        if self._thread:
            self._q.put(None)
            self._thread.join(timeout)
            self._thread = None

    def submit(self, job: FileJob) -> None:
        self._q.put(job)

    def join(self) -> None:
        """Block until every submitted job has finished (tests)."""
        self._q.join()

    def _loop(self) -> None:
        while True:
            job = self._q.get()
            try:
                if job is None:
                    return
                run_file_job(job)
            except Exception:
                log.exception("ingest worker crashed on a job")
            finally:
                self._q.task_done()


def fail_interrupted_batches(db: Session) -> None:
    """Uploads that were pending/running when the server stopped lost their spool file."""
    stmt = select(IngestBatch).where(
        IngestBatch.kind == "upload", col(IngestBatch.status).in_(["pending", "running"])
    )
    for b in db.exec(stmt):
        b.status = "failed"
        b.error = "interrupted by a server restart; upload the file again"
        b.finished_at = utcnow()
        db.add(b)
    db.commit()


def clear_spool(spool: Path) -> None:
    if spool.exists():
        shutil.rmtree(spool, ignore_errors=True)


# --------------------------------------------------------------------------- live


def live_batch(db: Session, stream: str, fmt: Format, host: str | None) -> IngestBatch:
    stmt = select(IngestBatch).where(
        IngestBatch.kind == "live", IngestBatch.filename == stream, IngestBatch.source_type == fmt
    )
    batch = db.exec(stmt).first()
    if batch is None:
        s = settings_service.get_ingest(db)
        batch = IngestBatch(
            source_type=fmt,
            kind="live",
            filename=stream,
            default_host=host,
            status="live",
            tz_assumption=s.syslog_timezone if fmt == "linux_auth" else None,
        )
        db.add(batch)
        db.commit()
        db.refresh(batch)
    return batch


def ingest_live(
    db: Session,
    *,
    fmt: Format,
    stream: str,
    host: str | None,
    mapping: dict[str, str] | None,
    records: list[tuple[str, str | None]],
) -> tuple[IngestBatch, pipeline.Counts]:
    if fmt not in dispatch.LIVE_FORMATS:
        raise IngestError(f"format {fmt!r} cannot be streamed live")
    mapping = _check_mapping(fmt, mapping)
    batch = live_batch(db, stream, fmt, host)
    ctx = _context(db, host=host or batch.default_host, mapping=mapping)
    results = list(dispatch.parse_records(fmt, [r for r, _ in records], ctx))
    # Live records are deduped by (seq, raw) when the sender supplies a sequence id (the
    # tail CLI sends file offset), so identical lines sent in different POSTs survive.
    seqs = [s for _, s in records]
    counts = pipeline.store_chunk(db, batch.id, results, DedupKeyer(), seqs)
    db.refresh(batch)
    return batch, counts


def spool_dir(settings: Settings) -> Path:
    return Path(settings.data_dir) / "uploads"
