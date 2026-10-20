"""Parser output types. Parsers yield one ParseResult per input record, in order."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.storage.models import Outcome

SOURCE_TYPES = (
    "linux_auth",
    "windows_security",
    "sysmon",
    "web_access",
    "wazuh",
    "generic_jsonl",
)


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime
    source_type: str
    raw: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    process_name: str | None = None
    process_cmdline: str | None = None
    parent_process: str | None = None
    event_code: str | None = None
    action: str | None = None
    outcome: Outcome = Outcome.unknown
    dns_query: str | None = None
    url: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class Unparsed:
    raw: str
    reason: str
    line_no: int | None = None


@dataclass(slots=True, frozen=True)
class Parsed:
    event: NormalizedEvent
    line_no: int | None = None


ParseResult = Parsed | Unparsed


@dataclass(slots=True, frozen=True)
class ParseContext:
    """Assumptions a parser may need. Syslog has no year or zone, so both are explicit."""

    syslog_tz: ZoneInfo
    syslog_year: int | None  # None = infer (current year, rolling back if in the future)
    now: datetime
    field_mapping: dict[str, str] | None = None  # generic JSONL only
    default_host: str | None = None  # web access logs don't name the server
