"""Generic JSON Lines with a user-supplied field mapping.

The mapping is {schema_field: "dotted.path.in.record"}; `timestamp` is required. Paths
are resolved by plain dict/list lookups (no expressions, no eval).
"""

from collections.abc import Iterable, Iterator
from typing import Any

from app.ingest.normalise import clean_int, clean_port, clean_str, finalise
from app.ingest.readers import JsonRecord
from app.ingest.timeparse import parse_any
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, ParseResult, Unparsed
from app.storage.models import Outcome

SOURCE = "generic_jsonl"

STRING_FIELDS = (
    "host",
    "user",
    "src_ip",
    "dst_ip",
    "process_name",
    "process_cmdline",
    "parent_process",
    "event_code",
    "action",
    "dns_query",
    "url",
    "user_agent",
)
INT_FIELDS = ("http_status",)
PORT_FIELDS = ("src_port", "dst_port")
MAPPABLE = frozenset(("timestamp", "outcome", *STRING_FIELDS, *INT_FIELDS, *PORT_FIELDS))

_SUCCESS = {"success", "succeeded", "ok", "allow", "allowed", "accept", "accepted", "true", "1"}
_FAILURE = {
    "failure",
    "failed",
    "fail",
    "deny",
    "denied",
    "reject",
    "rejected",
    "error",
    "false",
    "0",
}


class MappingError(ValueError):
    pass


def validate_mapping(mapping: dict[str, str]) -> dict[str, str]:
    unknown = set(mapping) - MAPPABLE
    if unknown:
        raise MappingError(f"unknown target fields: {', '.join(sorted(unknown))}")
    if "timestamp" not in mapping:
        raise MappingError("mapping must include 'timestamp'")
    for k, path in mapping.items():
        if not isinstance(path, str) or not path or len(path) > 256:
            raise MappingError(f"invalid path for {k!r}")
    return mapping


def lookup(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def map_record(obj: Any, raw: str, mapping: dict[str, str]) -> NormalizedEvent:
    ts_val = lookup(obj, mapping["timestamp"])
    if ts_val is None:
        raise ValueError(f"timestamp path {mapping['timestamp']!r} not found")
    ev = NormalizedEvent(timestamp=parse_any(ts_val), source_type=SOURCE, raw=raw)
    for f in STRING_FIELDS:
        if f in mapping:
            v = lookup(obj, mapping[f])
            setattr(ev, f, clean_str(v, 8192) if not isinstance(v, dict | list) else None)
    for f in INT_FIELDS:
        if f in mapping:
            setattr(ev, f, clean_int(lookup(obj, mapping[f])))
    for f in PORT_FIELDS:
        if f in mapping:
            setattr(ev, f, clean_port(lookup(obj, mapping[f])))
    if "outcome" in mapping:
        v = str(lookup(obj, mapping["outcome"])).strip().lower()
        ev.outcome = (
            Outcome.success
            if v in _SUCCESS
            else Outcome.failure
            if v in _FAILURE
            else Outcome.unknown
        )
    return finalise(ev)


def parse_json_records(records: Iterable[JsonRecord], ctx: ParseContext) -> Iterator[ParseResult]:
    mapping = validate_mapping(ctx.field_mapping or {})
    for rec in records:
        if rec.error:
            yield Unparsed(rec.raw, rec.error, rec.line_no)
            continue
        try:
            yield Parsed(map_record(rec.obj, rec.raw, mapping), rec.line_no)
        except (ValueError, TypeError) as e:
            yield Unparsed(rec.raw, f"mapping failed: {e}", rec.line_no)
