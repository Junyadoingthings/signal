"""AST → SQLAlchemy expression. Only allow-listed columns; every value is a bound
parameter and LIKE wildcards in user text are escaped, so a query can never alter the
shape of the SQL."""

from typing import Any

from sqlalchemy import String, and_, cast, func, not_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.search.parser import And, Node, Not, Or, SearchError, Term, Text
from app.storage.models import Event

STRING_FIELDS = {
    "user",
    "host",
    "process_name",
    "process_cmdline",
    "parent_process",
    "event_code",
    "action",
    "outcome",
    "dns_query",
    "url",
    "user_agent",
    "source_type",
}
EXACT_FIELDS = {"src_ip", "dst_ip"}  # wildcards allowed, compared case-sensitively
INT_FIELDS = {"src_port", "dst_port", "http_status"}
ALIASES = {
    "cmdline": "process_cmdline",
    "process": "process_name",
    "parent": "parent_process",
    "ip": "*ip",
    "dns": "dns_query",
    "ua": "user_agent",
    "code": "event_code",
    "status": "http_status",
    "src": "src_ip",
    "dst": "dst_ip",
    "type": "source_type",
    "tag": "*tag",
    "tags": "*tag",
}
FIELD_NAMES = sorted(STRING_FIELDS | EXACT_FIELDS | INT_FIELDS | {"ip", "tag"})
FREE_TEXT_COLUMNS = ("raw", "process_cmdline", "url", "dns_query", "user", "host", "user_agent")


def _like(value: str) -> tuple[str, bool]:
    """Returns (pattern, has_wildcard). `*` is the wildcard; %, _ and \\ are literals."""
    esc = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return esc.replace("*", "%"), "*" in value


def _string_match(col: Any, value: str, *, ci: bool) -> ColumnElement[bool]:
    pattern, wild = _like(value)
    if wild:
        like: ColumnElement[bool] = (
            col.ilike(pattern, escape="\\") if ci else col.like(pattern, escape="\\")
        )
        return like
    exact: ColumnElement[bool] = func.lower(col) == value.lower() if ci else col == value
    return exact


def _int_match(col: Any, term: Term) -> ColumnElement[bool]:
    try:
        n = int(term.value)
    except ValueError as e:
        raise SearchError(f"{term.field} expects a number, got {term.value!r}") from e
    cmp: dict[str, ColumnElement[bool]] = {
        "eq": col == n,
        "gte": col >= n,
        "gt": col > n,
        "lte": col <= n,
        "lt": col < n,
    }
    return cmp[term.op]


def _term(t: Term) -> ColumnElement[bool]:
    field = ALIASES.get(t.field, t.field)
    if field == "*ip":
        return or_(_term(Term("src_ip", t.op, t.value)), _term(Term("dst_ip", t.op, t.value)))
    if field == "*tag":
        pattern, _ = _like(t.value)
        return cast(Event.tags, String).like(f'%"{pattern.replace("*", "%")}"%', escape="\\")
    if t.op != "eq" and field not in INT_FIELDS:
        raise SearchError(f"{t.field} does not support comparison operators")
    col = (
        getattr(Event, field, None)
        if field in (STRING_FIELDS | EXACT_FIELDS | INT_FIELDS)
        else None
    )
    if col is None:
        raise SearchError(f"unknown field {t.field!r}. Fields: {', '.join(FIELD_NAMES)}")
    if field in INT_FIELDS:
        return _int_match(col, t)
    return _string_match(col, t.value, ci=field in STRING_FIELDS)


def compile_node(node: Node) -> ColumnElement[bool]:
    if isinstance(node, Term):
        return _term(node)
    if isinstance(node, Text):
        pattern, _ = _like(node.value)
        like = f"%{pattern}%"
        return or_(*(getattr(Event, c).like(like, escape="\\") for c in FREE_TEXT_COLUMNS))
    if isinstance(node, Not):
        return not_(compile_node(node.child))
    if isinstance(node, And):
        return and_(*(compile_node(c) for c in node.children))
    if isinstance(node, Or):
        return or_(*(compile_node(c) for c in node.children))
    raise TypeError(type(node).__name__)
