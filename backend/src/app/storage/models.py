"""Database models. Every timestamp is stored as UTC and returned timezone-aware."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Index, Text, TypeDecorator, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """SQLite has no timezone type: store naive UTC, hand back aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to UTCDateTime")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


def ts_field(*, index: bool = False, nullable: bool = False, default_now: bool = True) -> Any:
    return Field(
        default_factory=utcnow if default_now else None,
        sa_column=Column(UTCDateTime(), index=index, nullable=nullable),
    )


def json_field(default: Any) -> Any:
    return Field(default_factory=lambda: default.copy(), sa_column=Column(JSON, nullable=False))


# ---------------------------------------------------------------- enums


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Status(StrEnum):
    new = "new"
    investigating = "investigating"
    closed = "closed"


class Verdict(StrEnum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign_true_positive = "benign_true_positive"


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    unknown = "unknown"


class EntityType(StrEnum):
    host = "host"
    user = "user"
    ip = "ip"
    process = "process"
    domain = "domain"


# ---------------------------------------------------------------- identity & audit


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=254)
    display_name: str = Field(max_length=120)
    role: Role = Field(default=Role.analyst)
    password_hash: str
    is_active: bool = True
    created_at: datetime = ts_field()
    last_login_at: datetime | None = ts_field(nullable=True, default_now=False)


class AuthSession(SQLModel, table=True):
    __tablename__ = "sessions"

    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    csrf_token: str
    user_id: int = Field(foreign_key="users.id", index=True)
    created_at: datetime = ts_field()
    expires_at: datetime = ts_field(index=True)
    ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=512)


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = ts_field(index=True)
    actor_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    actor_email: str | None = None  # denormalised so the trail survives user changes
    action: str = Field(index=True, max_length=64)
    target_type: str | None = Field(default=None, max_length=32)
    target_id: str | None = Field(default=None, max_length=64)
    before: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    after: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    ip: str | None = Field(default=None, max_length=64)


# ---------------------------------------------------------------- ingestion


class IngestBatch(SQLModel, table=True):
    __tablename__ = "ingest_batches"

    id: int | None = Field(default=None, primary_key=True)
    source_type: str = Field(index=True, max_length=32)
    filename: str | None = Field(default=None, max_length=255)
    size_bytes: int = 0
    status: str = Field(default="pending", max_length=16)  # pending|running|done|failed
    parsed_count: int = 0
    unparsed_count: int = 0
    duplicate_count: int = 0
    tz_assumption: str | None = Field(default=None, max_length=64)
    year_assumption: int | None = None
    error: str | None = None
    created_by: int | None = Field(default=None, foreign_key="users.id")
    created_at: datetime = ts_field(index=True)
    finished_at: datetime | None = ts_field(nullable=True, default_now=False)


class Event(SQLModel, table=True):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_host_ts", "host", "timestamp"),
        Index("ix_events_user_ts", "user", "timestamp"),
        Index("ix_events_src_ip_ts", "src_ip", "timestamp"),
        Index("ix_events_code_ts", "source_type", "event_code", "timestamp"),
    )

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = ts_field(index=True)
    ingested_at: datetime = ts_field()
    batch_id: int | None = Field(default=None, foreign_key="ingest_batches.id", index=True)
    dedup_hash: str = Field(unique=True, max_length=64)

    source_type: str = Field(max_length=32)
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=45)
    dst_ip: str | None = Field(default=None, max_length=45)
    src_port: int | None = None
    dst_port: int | None = None
    process_name: str | None = Field(default=None, max_length=512)
    process_cmdline: str | None = Field(default=None, sa_column=Column(Text))
    parent_process: str | None = Field(default=None, max_length=512)
    event_code: str | None = Field(default=None, max_length=32)
    action: str | None = Field(default=None, max_length=64)
    outcome: Outcome = Field(default=Outcome.unknown)
    dns_query: str | None = Field(default=None, max_length=1024)
    url: str | None = Field(default=None, sa_column=Column(Text))
    http_status: int | None = None
    user_agent: str | None = Field(default=None, sa_column=Column(Text))
    raw: str = Field(sa_column=Column(Text, nullable=False))
    tags: list[str] = json_field([])
    extra: dict[str, Any] = json_field({})  # source-specific fields kept for detection/display


class UnparsedEvent(SQLModel, table=True):
    __tablename__ = "unparsed_events"

    id: int | None = Field(default=None, primary_key=True)
    batch_id: int | None = Field(default=None, foreign_key="ingest_batches.id", index=True)
    line_no: int | None = None
    raw: str = Field(sa_column=Column(Text, nullable=False))
    reason: str = Field(max_length=512)
    created_at: datetime = ts_field(index=True)


# ---------------------------------------------------------------- entities


class Entity(SQLModel, table=True):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: int | None = Field(default=None, primary_key=True)
    type: EntityType = Field(index=True)
    value: str = Field(max_length=512, index=True)
    first_seen: datetime = ts_field()
    last_seen: datetime = ts_field(index=True)
    event_count: int = 0


class EntityEdge(SQLModel, table=True):
    __tablename__ = "entity_edges"
    __table_args__ = (UniqueConstraint("src_entity_id", "dst_entity_id", "relation"),)

    id: int | None = Field(default=None, primary_key=True)
    src_entity_id: int = Field(foreign_key="entities.id", index=True)
    dst_entity_id: int = Field(foreign_key="entities.id", index=True)
    relation: str = Field(max_length=32)  # e.g. logged_on, connected_to, ran, resolved
    count: int = 0
    first_seen: datetime = ts_field()
    last_seen: datetime = ts_field()


# ---------------------------------------------------------------- detection


class Rule(SQLModel, table=True):
    __tablename__ = "rules"

    id: str = Field(primary_key=True, max_length=64)
    title: str = Field(max_length=200)
    yaml: str = Field(sa_column=Column(Text, nullable=False))
    sha256: str = Field(max_length=64)
    enabled: bool = True
    severity: Severity
    primary_tactic: str | None = Field(default=None, max_length=64)
    techniques: list[str] = json_field([])
    hit_count: int = 0
    last_fired_at: datetime | None = ts_field(nullable=True, default_now=False)
    updated_at: datetime = ts_field()


class FirstSeenValue(SQLModel, table=True):
    __tablename__ = "first_seen_values"
    __table_args__ = (UniqueConstraint("rule_id", "entity_key", "value"),)

    id: int | None = Field(default=None, primary_key=True)
    rule_id: str = Field(foreign_key="rules.id", index=True)
    entity_key: str = Field(max_length=512)
    value: str = Field(max_length=1024)
    first_seen_at: datetime = ts_field()


class Incident(SQLModel, table=True):
    __tablename__ = "incidents"

    id: int | None = Field(default=None, primary_key=True)
    title: str = Field(max_length=300)
    score: int = 0
    severity: Severity
    status: Status = Field(default=Status.new, index=True)
    verdict: Verdict | None = None
    assignee_id: int | None = Field(default=None, foreign_key="users.id")
    tactics: list[str] = json_field([])
    first_event_at: datetime = ts_field(index=True)
    last_event_at: datetime = ts_field()
    created_at: datetime = ts_field(index=True)
    updated_at: datetime = ts_field()
    closed_at: datetime | None = ts_field(nullable=True, default_now=False)


class Alert(SQLModel, table=True):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_sev", "status", "severity"),)

    id: int | None = Field(default=None, primary_key=True)
    rule_id: str = Field(foreign_key="rules.id", index=True)
    severity: Severity = Field(index=True)
    status: Status = Field(default=Status.new, index=True)
    verdict: Verdict | None = None
    assignee_id: int | None = Field(default=None, foreign_key="users.id")
    host: str | None = Field(default=None, max_length=255, index=True)
    user: str | None = Field(default=None, max_length=255, index=True)
    src_ip: str | None = Field(default=None, max_length=45, index=True)
    first_event_at: datetime = ts_field(index=True)
    last_event_at: datetime = ts_field()
    match_context: dict[str, Any] = json_field({})
    incident_id: int | None = Field(default=None, foreign_key="incidents.id", index=True)
    created_at: datetime = ts_field(index=True)
    acknowledged_at: datetime | None = ts_field(nullable=True, default_now=False)
    closed_at: datetime | None = ts_field(nullable=True, default_now=False)


class AlertEvent(SQLModel, table=True):
    __tablename__ = "alert_events"

    alert_id: int = Field(foreign_key="alerts.id", primary_key=True)
    event_id: int = Field(foreign_key="events.id", primary_key=True, index=True)


# ---------------------------------------------------------------- analyst artefacts


class Note(SQLModel, table=True):
    __tablename__ = "notes"
    __table_args__ = (Index("ix_notes_target", "target_type", "target_id"),)

    id: int | None = Field(default=None, primary_key=True)
    target_type: str = Field(max_length=16)  # alert | incident
    target_id: int
    author_id: int = Field(foreign_key="users.id")
    markdown: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = ts_field()


class SavedSearch(SQLModel, table=True):
    __tablename__ = "saved_searches"

    id: int | None = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="users.id", index=True)
    name: str = Field(max_length=120)
    query: str = Field(sa_column=Column(Text, nullable=False))
    time_range: str = Field(default="24h", max_length=64)
    created_at: datetime = ts_field()


class Setting(SQLModel, table=True):
    """Key/value runtime settings that admins can change from the UI."""

    __tablename__ = "settings"

    key: str = Field(primary_key=True, max_length=64)
    value: Any = Field(sa_column=Column(JSON, nullable=False))
    updated_at: datetime = ts_field()
