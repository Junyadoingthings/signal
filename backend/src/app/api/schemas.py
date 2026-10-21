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


# ---------------------------------------------------------------- detection


class TechniqueRef(BaseModel):
    id: str
    name: str | None
    url: str | None


class RuleOut(BaseModel):
    id: str
    title: str
    severity: str
    enabled: bool
    logic_type: str
    primary_tactic: str | None
    techniques: list[TechniqueRef]
    hit_count: int
    last_fired_at: datetime | None
    tags: list[str]


class RuleDetail(RuleOut):
    description: str
    false_positives: list[str]
    references: list[str]
    yaml: str
    updated_at: datetime


class RuleUpdate(StrictModel):
    enabled: bool


class RetroHuntRequest(StrictModel):
    start: datetime
    end: datetime


class RetroHuntResult(BaseModel):
    rule_id: str
    events_scanned: int
    alerts: int


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    severity: str
    status: str
    verdict: str | None
    host: str | None
    user: str | None
    src_ip: str | None
    group_key: str
    event_count: int
    first_event_at: datetime
    last_event_at: datetime
    created_at: datetime
    match_context: dict[str, Any]
    incident_id: int | None


class AlertPage(BaseModel):
    items: list[AlertOut]
    next_before_id: int | None


class TacticOut(BaseModel):
    id: str
    shortname: str
    name: str
    url: str
    rule_count: int


class AttackOut(BaseModel):
    version: str
    tactics: list[TacticOut]


# ---------------------------------------------------------------- triage

StatusLiteral = Literal["new", "investigating", "closed"]
VerdictLiteral = Literal["true_positive", "false_positive", "benign_true_positive"]


class AlertRow(AlertOut):
    rule_title: str
    tactic: str | None
    assignee_id: int | None
    assignee_name: str | None
    acknowledged_at: datetime | None
    closed_at: datetime | None


class AlertList(BaseModel):
    items: list[AlertRow]
    total: int
    offset: int
    limit: int


class AlertRuleInfo(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    logic_type: str
    primary_tactic: str | None
    techniques: list[TechniqueRef]
    false_positives: list[str]


class AlertDetail(BaseModel):
    alert: AlertRow
    rule: AlertRuleInfo
    events: list[EventOut]
    events_total: int


class TriageUpdate(StrictModel):
    status: StatusLiteral | None = None
    verdict: VerdictLiteral | None = None
    assignee_id: int | None = None
    unassign: bool = False


class BulkTriage(TriageUpdate):
    ids: list[int] = Field(min_length=1, max_length=500)


class BulkResult(BaseModel):
    updated: list[int]
    errors: dict[int, str]


class IncidentUpdate(TriageUpdate):
    close_alerts: bool = False


class IncidentRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    score: int
    severity: str
    status: str
    verdict: str | None
    assignee_id: int | None
    tactics: list[str]
    entities: dict[str, Any]
    alert_count: int
    first_event_at: datetime
    last_event_at: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class IncidentList(BaseModel):
    items: list[IncidentRow]
    total: int


class StoryStep(BaseModel):
    alert_id: int
    rule_id: str
    title: str
    tactic: str | None
    techniques: list[str]
    severity: str
    time: datetime
    status: str


class IncidentDetail(BaseModel):
    incident: IncidentRow
    alerts: list[AlertRow]
    storyline: list[StoryStep]


NoteText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=20000)]


class NoteCreate(StrictModel):
    markdown: NoteText


class NoteOut(BaseModel):
    id: int
    author_id: int
    author_name: str
    markdown: str
    created_at: datetime


class HistoryEntry(BaseModel):
    kind: Literal["audit", "note"]
    ts: datetime
    actor: str | None
    action: str | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    note: NoteOut | None = None


class UserBrief(BaseModel):
    id: int
    display_name: str
    role: str
