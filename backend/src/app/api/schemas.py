"""Request/response models. Requests forbid unknown fields; strings are length-bounded."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.storage.models import Role

Email = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+$",
    ),
]
Password = Annotated[str, StringConstraints(min_length=1, max_length=256)]
NewPassword = Annotated[str, StringConstraints(min_length=12, max_length=256)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    email: Email
    password: Password


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class MeOut(BaseModel):
    user: UserOut
    csrf_token: str
    session_expires_at: datetime


class UserCreate(StrictModel):
    email: Email
    display_name: DisplayName
    role: Role = Role.analyst
    password: NewPassword


class UserUpdate(StrictModel):
    display_name: DisplayName | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: NewPassword | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor_id: int | None
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ip: str | None


class AuditPage(BaseModel):
    items: list[AuditOut]
    next_before_id: int | None


class SystemStatus(BaseModel):
    events_total: int
    events_last_24h: int
    unparsed_total: int
    alerts_open: int
    incidents_open: int
    rules_enabled: int
    last_event_at: datetime | None
    last_ingest_at: datetime | None


class Health(BaseModel):
    status: str = Field(examples=["ok"])
    version: str


# ---------------------------------------------------------------- ingestion

IngestFormat = Literal["evtx", "windows_json", "linux_auth", "web_access", "wazuh", "generic_jsonl"]
LiveFormat = Literal["windows_json", "linux_auth", "web_access", "wazuh", "generic_jsonl"]


class BatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_type: str
    kind: str
    filename: str | None
    default_host: str | None
    size_bytes: int
    status: str
    parsed_count: int
    unparsed_count: int
    duplicate_count: int
    tz_assumption: str | None
    year_assumption: int | None
    error: str | None
    created_at: datetime
    finished_at: datetime | None


class BatchPage(BaseModel):
    items: list[BatchOut]
    next_before_id: int | None


class UnparsedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_id: int | None
    line_no: int | None
    raw: str
    reason: str
    created_at: datetime


class UnparsedPage(BaseModel):
    items: list[UnparsedOut]
    next_before_id: int | None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    ingested_at: datetime
    batch_id: int | None
    source_type: str
    host: str | None
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    process_name: str | None
    process_cmdline: str | None
    parent_process: str | None
    event_code: str | None
    action: str | None
    outcome: str
    dns_query: str | None
    url: str | None
    http_status: int | None
    user_agent: str | None
    raw: str
    tags: list[str]
    extra: dict[str, Any]


class EventPage(BaseModel):
    items: list[EventOut]
    next_before_id: int | None


StreamName = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/@-]+$")
]
HostName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$"
    ),
]


class LiveRecord(StrictModel):
    raw: Annotated[str, StringConstraints(min_length=1, max_length=65536)]
    seq: Annotated[str, StringConstraints(max_length=128)] | None = None


class LiveIngestRequest(StrictModel):
    format: LiveFormat
    stream: StreamName
    host: HostName | None = None
    field_mapping: dict[str, str] | None = None
    records: list[LiveRecord] = Field(min_length=1)


class LiveIngestResult(BaseModel):
    batch_id: int
    accepted: int
    parsed: int
    unparsed: int
    duplicates: int


class TokenCreate(StrictModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]


class TokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class TokenCreated(TokenOut):
    token: str  # shown once


class IngestSettingsOut(BaseModel):
    syslog_timezone: str
    syslog_year: int | None
    max_upload_bytes: int
