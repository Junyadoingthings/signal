"""Compile rule conditions into predicates that also explain themselves.

Each leaf records the field, modifier, expected and actual value when it matches, so an
alert can show exactly why it fired. Fields are resolved from a fixed allow-list
(normalised columns, extra.* paths and a few computed fields); unknown fields are a
load-time error, never a silent non-match.
"""

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Any
from zoneinfo import ZoneInfo

from app.ingest.entities import registered_domain

COLUMNS = frozenset(
    {
        "timestamp",
        "source_type",
        "host",
        "user",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "process_name",
        "process_cmdline",
        "parent_process",
        "event_code",
        "action",
        "outcome",
        "dns_query",
        "url",
        "http_status",
        "user_agent",
        "raw",
        "tags",
    }
)


def _dns_subdomain(q: str | None) -> str | None:
    if not q:
        return None
    reg = registered_domain(q)
    sub = q[: -len(reg)].rstrip(".") if q.endswith(reg) else ""
    return sub or None


COMPUTED: dict[str, Callable[[Mapping[str, Any]], Any]] = {
    "dns_domain": lambda e: registered_domain(e["dns_query"]) if e.get("dns_query") else None,
    "dns_subdomain": lambda e: _dns_subdomain(e.get("dns_query")),
    "dns_longest_label": lambda e: (
        max((len(x) for x in (e.get("dns_query") or "").split(".")), default=0)
        if e.get("dns_query")
        else None
    ),
}


class ConditionError(ValueError):
    pass


def check_field(name: str) -> None:
    if name in COLUMNS or name in COMPUTED:
        return
    if name.startswith("extra.") and len(name) > 6:
        return
    raise ConditionError(f"unknown field {name!r}")


def resolve(event: Mapping[str, Any], name: str) -> Any:
    if name in COMPUTED:
        return COMPUTED[name](event)
    if name.startswith("extra."):
        cur: Any = event.get("extra") or {}
        for part in name[6:].split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
    return event.get(name)


# ------------------------------------------------------------------ evaluation context


@dataclass(frozen=True, slots=True)
class BusinessHours:
    start: time = time(8, 0)
    end: time = time(18, 0)
    days: frozenset[int] = frozenset({0, 1, 2, 3, 4})  # Monday=0
    tz: ZoneInfo = field(default_factory=lambda: ZoneInfo("UTC"))

    def is_off_hours(self, ts: datetime) -> bool:
        local = ts.astimezone(self.tz)
        return local.weekday() not in self.days or not (self.start <= local.time() < self.end)


@dataclass(frozen=True, slots=True)
class EvalContext:
    business_hours: BusinessHours = BusinessHours()


@dataclass(frozen=True, slots=True)
class Hit:
    field: str
    op: str
    expected: Any
    actual: Any

    def as_dict(self) -> dict[str, Any]:
        def j(v: Any) -> Any:
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, str) and len(v) > 512:
                return v[:512] + "…"
            return v

        return {
            "field": self.field,
            "op": self.op,
            "expected": j(self.expected),
            "actual": j(self.actual),
        }


Predicate = Callable[[Mapping[str, Any], EvalContext], list[Hit] | None]
"""Returns the list of matching leaves (possibly empty for `not`) or None for no match."""


# ------------------------------------------------------------------ leaf operators


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _norm(v: Any, cs: bool) -> Any:
    return v if cs or not isinstance(v, str) else v.lower()


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int | float):
        return float(v)
    try:
        return float(str(v))
    except ValueError:
        return None


Op = Callable[[Any, Any, EvalContext], bool]


def _string_op(fn: Callable[[str, str], bool], cs: bool) -> Op:
    def op(actual: Any, expected: Any, _: EvalContext) -> bool:
        if actual is None:
            return False
        values = actual if isinstance(actual, list) else [actual]
        return any(fn(_norm(str(a), cs), _norm(str(expected), cs)) for a in values)

    return op


def _eq(cs: bool) -> Op:
    def op(actual: Any, expected: Any, _: EvalContext) -> bool:
        if actual is None:
            return expected is None
        if isinstance(actual, list):
            return any(_norm(a, cs) == _norm(expected, cs) for a in actual)
        if isinstance(expected, str) or isinstance(actual, str):
            return bool(_norm(str(actual), cs) == _norm(str(expected), cs))
        return bool(actual == expected)

    return op


def _cmp(fn: Callable[[float, float], bool]) -> Op:
    def op(actual: Any, expected: Any, _: EvalContext) -> bool:
        a, e = _num(actual), _num(expected)
        return a is not None and e is not None and fn(a, e)

    return op


def _cidr(actual: Any, expected: Any, _: EvalContext) -> bool:
    if not actual:
        return False
    try:
        return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
            str(expected), strict=False
        )
    except ValueError:
        return False


def _exists(actual: Any, expected: Any, _: EvalContext) -> bool:
    present = actual is not None and actual != "" and actual != []
    return present == bool(expected)


def _off_hours(actual: Any, expected: Any, ctx: EvalContext) -> bool:
    if not isinstance(actual, datetime):
        return False
    return ctx.business_hours.is_off_hours(actual) == bool(expected)


def _len_gte(actual: Any, expected: Any, _: EvalContext) -> bool:
    return actual is not None and len(str(actual)) >= int(expected)


def _entropy_gte(actual: Any, expected: Any, _: EvalContext) -> bool:
    return actual is not None and shannon_entropy(str(actual)) >= float(expected)


OPS: dict[str, Op] = {
    "equals": _eq(False),
    "equals_cs": _eq(True),
    "contains": _string_op(lambda a, e: e in a, False),
    "contains_cs": _string_op(lambda a, e: e in a, True),
    "startswith": _string_op(lambda a, e: a.startswith(e), False),
    "endswith": _string_op(lambda a, e: a.endswith(e), False),
    "gte": _cmp(lambda a, e: a >= e),
    "gt": _cmp(lambda a, e: a > e),
    "lte": _cmp(lambda a, e: a <= e),
    "lt": _cmp(lambda a, e: a < e),
    "cidr": _cidr,
    "exists": _exists,
    "off_hours": _off_hours,
    "len_gte": _len_gte,
    "entropy_gte": _entropy_gte,
}
ALIASES = {"in": "equals", "eq": "equals"}
LIST_ANY = {
    "equals",
    "equals_cs",
    "contains",
    "contains_cs",
    "startswith",
    "endswith",
    "cidr",
    "re",
}

MAX_REGEX_LEN = 2000


def _leaf(key: str, value: Any) -> Predicate:
    name, _, op_name = key.partition("|")
    op_name = ALIASES.get(op_name or "equals", op_name or "equals")
    check_field(name)

    if op_name == "re":
        patterns = value if isinstance(value, list) else [value]
        compiled = []
        for p in patterns:
            if not isinstance(p, str) or len(p) > MAX_REGEX_LEN:
                raise ConditionError(f"{key}: regex must be a string under {MAX_REGEX_LEN} chars")
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                raise ConditionError(f"{key}: invalid regex: {e}") from e

        def regex_pred(event: Mapping[str, Any], _: EvalContext) -> list[Hit] | None:
            actual = resolve(event, name)
            if actual is None:
                return None
            for a in actual if isinstance(actual, list) else [actual]:
                text = str(a)[:65536]
                for rx in compiled:
                    if m := rx.search(text):
                        return [Hit(name, "re", rx.pattern, m.group(0)[:256])]
            return None

        return regex_pred

    op = OPS.get(op_name)
    if op is None:
        raise ConditionError(f"{key}: unknown modifier {op_name!r}")
    if isinstance(value, list) and op_name not in LIST_ANY:
        raise ConditionError(f"{key}: a list is not allowed with |{op_name}")
    expected_values = value if isinstance(value, list) else [value]

    def pred(event: Mapping[str, Any], ctx: EvalContext) -> list[Hit] | None:
        actual = resolve(event, name)
        for exp in expected_values:
            if op(actual, exp, ctx):
                shown: Any = actual
                if op_name == "entropy_gte" and actual is not None:
                    shown = round(shannon_entropy(str(actual)), 2)
                elif op_name == "len_gte" and actual is not None:
                    shown = len(str(actual))
                return [Hit(name, op_name, exp, shown)]
        return None

    return pred


def compile_condition(node: Any) -> Predicate:
    if isinstance(node, list):
        return compile_condition({"all": node})
    if not isinstance(node, dict) or not node:
        raise ConditionError("a condition must be a non-empty mapping or list")

    if set(node) == {"all"} or set(node) == {"any"}:
        ((kind, children),) = node.items()
        if not isinstance(children, list) or not children:
            raise ConditionError(f"'{kind}' needs a non-empty list")
        preds = [compile_condition(c) for c in children]
        if kind == "all":

            def all_pred(event: Mapping[str, Any], ctx: EvalContext) -> list[Hit] | None:
                hits: list[Hit] = []
                for p in preds:
                    r = p(event, ctx)
                    if r is None:
                        return None
                    hits.extend(r)
                return hits

            return all_pred

        def any_pred(event: Mapping[str, Any], ctx: EvalContext) -> list[Hit] | None:
            for p in preds:
                r = p(event, ctx)
                if r is not None:
                    return r
            return None

        return any_pred

    if set(node) == {"not"}:
        inner = compile_condition(node["not"])

        def not_pred(event: Mapping[str, Any], ctx: EvalContext) -> list[Hit] | None:
            return [] if inner(event, ctx) is None else None

        return not_pred

    if any(k in ("all", "any", "not") for k in node):
        raise ConditionError("all/any/not must be the only key in their mapping")
    # Several leaves in one mapping are ANDed, as in Sigma selections.
    leaves = [_leaf(k, v) for k, v in node.items()]
    if len(leaves) == 1:
        return leaves[0]
    return compile_condition({"all": [{k: v} for k, v in node.items()]})


# ------------------------------------------------------------------ SQL pushdown


PUSHDOWN_COLUMNS = frozenset({"action", "outcome", "source_type", "event_code"})


def pushdown(node: Any) -> dict[str, list[Any]]:
    """Top-level AND-ed equality leaves on indexed columns, safe to apply in SQL as a
    pre-filter (the full predicate still runs afterwards). Case-insensitive matches
    are not pushed down, except on columns we always store lowercase."""
    if isinstance(node, list):
        node = {"all": node}
    if not isinstance(node, dict):
        return {}
    items: list[tuple[str, Any]] = []
    if set(node) == {"all"}:
        for child in node["all"]:
            if isinstance(child, dict) and not ({"all", "any", "not"} & set(child)):
                items.extend(child.items())
    elif not ({"all", "any", "not"} & set(node)):
        items.extend(node.items())
    out: dict[str, list[Any]] = {}
    for key, value in items:
        name, _, op = key.partition("|")
        if name in PUSHDOWN_COLUMNS and op in ("", "equals", "in", "eq"):
            values = value if isinstance(value, list) else [value]
            if all(isinstance(v, str) for v in values):
                out[name] = values
    return out
