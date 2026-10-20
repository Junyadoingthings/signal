import json
from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, UploadFile
from sqlmodel import Session, col, select

from app.api.deps import DB, AdminUser, AppSettings, CurrentUser, client_ip, current_principal
from app.api.schemas import (
    BatchOut,
    BatchPage,
    IngestSettingsOut,
    LiveIngestRequest,
    LiveIngestResult,
    TokenCreate,
    TokenCreated,
    TokenOut,
    UnparsedOut,
    UnparsedPage,
)
from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.ratelimit import limiter
from app.core.security import hash_token, new_token
from app.ingest import service
from app.services import audit
from app.services import settings as settings_service
from app.storage.models import IngestBatch, IngestToken, UnparsedEvent, User, utcnow

router = APIRouter(prefix="/api/ingest", tags=["ingest"])
TOKEN_PREFIX = "sig_"  # noqa: S105 - public prefix, not a secret


def _parse_mapping(raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise APIError(422, "validation_error", "field_mapping must be a JSON object") from e
    if not isinstance(obj, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in obj.items()
    ):
        raise APIError(422, "validation_error", "field_mapping must map field names to paths")
    return obj


@router.post("/upload", status_code=202, response_model=BatchOut)
@limiter.limit(lambda: get_settings().ingest_rate_limit)
def upload(
    request: Request,
    file: UploadFile,
    user: CurrentUser,
    db: DB,
    settings: AppSettings,
    format: Annotated[str, Form(max_length=32)] = "auto",
    host: Annotated[str | None, Form(max_length=255, pattern=r"^[A-Za-z0-9._-]*$")] = None,
    field_mapping: Annotated[str | None, Form(max_length=8192)] = None,
) -> IngestBatch:
    mapping = _parse_mapping(field_mapping)
    try:
        path, size, head = service.save_upload(
            file.file, service.spool_dir(settings), settings.max_upload_bytes
        )
    except service.IngestError as e:
        raise APIError(413, "payload_too_large", str(e)) from e
    try:
        batch, job = service.create_upload_batch(
            db,
            path=path,
            size=size,
            head=head,
            requested_format=format,
            filename=file.filename,
            host=host or None,
            mapping=mapping,
            user_id=user.id,
        )
    except service.MappingRequiredError as e:
        path.unlink(missing_ok=True)
        raise APIError(422, "validation_error", str(e)) from e
    except service.IngestError as e:
        path.unlink(missing_ok=True)
        raise APIError(415, "unsupported_content", str(e)) from e

    audit.record(
        db,
        "ingest.upload",
        actor=user,
        target_type="batch",
        target_id=batch.id,
        after={"format": batch.source_type, "filename": batch.filename, "bytes": size},
        ip=client_ip(request),
    )
    request.app.state.ingest_worker.submit(job)
    return batch


# --------------------------------------------------------------------------- live


def _ingest_caller(request: Request, db: Session, settings: Settings) -> tuple[str, User | None]:
    """Bearer ingest token (machines) or a normal session with CSRF (the UI)."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        row = db.exec(
            select(IngestToken).where(IngestToken.token_hash == hash_token(token))
        ).first()
        if row is None or row.revoked_at is not None:
            raise APIError(401, "invalid_token", "Invalid or revoked ingest token")
        row.last_used_at = utcnow()
        db.add(row)
        db.commit()
        return f"token:{row.prefix}", None
    principal = current_principal(request, db, settings)
    return principal.user.email, principal.user


@router.post("/events", response_model=LiveIngestResult)
@limiter.limit(lambda: get_settings().ingest_rate_limit)
def ingest_events(
    request: Request, body: LiveIngestRequest, db: DB, settings: AppSettings
) -> LiveIngestResult:
    _ingest_caller(request, db, settings)
    if len(body.records) > settings.max_live_records:
        raise APIError(
            413, "payload_too_large", f"at most {settings.max_live_records} records per request"
        )
    try:
        batch, counts = service.ingest_live(
            db,
            fmt=body.format,
            stream=body.stream,
            host=body.host,
            mapping=body.field_mapping,
            records=[(r.raw, r.seq) for r in body.records],
        )
    except service.IngestError as e:
        raise APIError(422, "validation_error", str(e)) from e
    return LiveIngestResult(
        batch_id=batch.id or 0,
        accepted=len(body.records),
        parsed=counts.parsed,
        unparsed=counts.unparsed,
        duplicates=counts.duplicates,
    )


# --------------------------------------------------------------------------- read


@router.get("/batches", response_model=BatchPage)
def list_batches(
    _: CurrentUser,
    db: DB,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> BatchPage:
    stmt = select(IngestBatch)
    if before_id:
        stmt = stmt.where(col(IngestBatch.id) < before_id)
    rows = db.exec(stmt.order_by(col(IngestBatch.id).desc()).limit(limit)).all()
    items = [BatchOut.model_validate(r) for r in rows]
    return BatchPage(items=items, next_before_id=items[-1].id if len(items) == limit else None)


@router.get("/batches/{batch_id}", response_model=BatchOut)
def get_batch(batch_id: int, _: CurrentUser, db: DB) -> IngestBatch:
    batch = db.get(IngestBatch, batch_id)
    if batch is None:
        raise APIError(404, "not_found", "Batch not found")
    return batch


@router.get("/unparsed", response_model=UnparsedPage)
def list_unparsed(
    _: CurrentUser,
    db: DB,
    batch_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> UnparsedPage:
    stmt = select(UnparsedEvent)
    if batch_id:
        stmt = stmt.where(UnparsedEvent.batch_id == batch_id)
    if before_id:
        stmt = stmt.where(col(UnparsedEvent.id) < before_id)
    rows = db.exec(stmt.order_by(col(UnparsedEvent.id).desc()).limit(limit)).all()
    items = [UnparsedOut.model_validate(r) for r in rows]
    return UnparsedPage(items=items, next_before_id=items[-1].id if len(items) == limit else None)


@router.get("/settings", response_model=IngestSettingsOut)
def get_ingest_settings(_: CurrentUser, db: DB, settings: AppSettings) -> IngestSettingsOut:
    s = settings_service.get_ingest(db)
    return IngestSettingsOut(
        syslog_timezone=s.syslog_timezone,
        syslog_year=s.syslog_year,
        max_upload_bytes=settings.max_upload_bytes,
    )


@router.put("/settings", response_model=IngestSettingsOut)
def put_ingest_settings(
    body: settings_service.IngestSettings,
    request: Request,
    admin: AdminUser,
    db: DB,
    settings: AppSettings,
) -> IngestSettingsOut:
    before = settings_service.get_ingest(db).model_dump()
    settings_service.put_ingest(db, body)
    audit.record(
        db,
        "settings.ingest",
        actor=admin,
        target_type="settings",
        target_id="ingest",
        before=before,
        after=body.model_dump(),
        ip=client_ip(request),
    )
    return IngestSettingsOut(
        syslog_timezone=body.syslog_timezone,
        syslog_year=body.syslog_year,
        max_upload_bytes=settings.max_upload_bytes,
    )


# --------------------------------------------------------------------------- tokens


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(_: AdminUser, db: DB) -> list[IngestToken]:
    return list(db.exec(select(IngestToken).order_by(col(IngestToken.id).desc())).all())


@router.post("/tokens", response_model=TokenCreated, status_code=201)
def create_token(body: TokenCreate, request: Request, admin: AdminUser, db: DB) -> TokenCreated:
    secret = TOKEN_PREFIX + new_token()
    row = IngestToken(
        name=body.name,
        token_hash=hash_token(secret),
        prefix=secret[: len(TOKEN_PREFIX) + 6],
        created_by=admin.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(
        db,
        "ingest_token.create",
        actor=admin,
        target_type="ingest_token",
        target_id=row.id,
        after={"name": row.name, "prefix": row.prefix},
        ip=client_ip(request),
    )
    return TokenCreated(**TokenOut.model_validate(row).model_dump(), token=secret)


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, request: Request, admin: AdminUser, db: DB) -> None:
    row = db.get(IngestToken, token_id)
    if row is None:
        raise APIError(404, "not_found", "Token not found")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        db.add(row)
        db.commit()
        audit.record(
            db,
            "ingest_token.revoke",
            actor=admin,
            target_type="ingest_token",
            target_id=row.id,
            ip=client_ip(request),
        )
