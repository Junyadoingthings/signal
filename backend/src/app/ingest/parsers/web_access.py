"""nginx / Apache access logs in Common or Combined format.

Quoted fields may contain escaped quotes (Apache writes \\", nginx writes \\x22).
The log has no server name, so the host comes from the upload (ctx.default_host).
"""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from app.ingest.normalise import clean_int, clean_str, finalise
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, ParseResult, Unparsed
from app.storage.models import Outcome

SOURCE = "web_access"

_Q = r'"((?:[^"\\]|\\.)*)"'
LINE = re.compile(
    r"^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    + _Q.replace("(", "(?P<req>", 1)
    + r" (?P<status>\d{3}) (?P<size>\S+)"
    + r"(?: "
    + _Q.replace("(", "(?P<ref>", 1)
    + r" "
    + _Q.replace("(", "(?P<ua>", 1)
    + r")?"
)
REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<target>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\x22", '"').replace("\\\\", "\\")


def parse_line(line: str, ctx: ParseContext) -> NormalizedEvent | str:
    m = LINE.match(line)
    if not m:
        return "not a Common/Combined access log line"
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return f"bad timestamp {m['ts']!r}"

    status = int(m["status"])
    ev = NormalizedEvent(
        timestamp=ts,
        source_type=SOURCE,
        raw=line,
        host=ctx.default_host,
        src_ip=m["ip"],
        user=clean_str(m["user"]),
        http_status=status,
        action="http_request",
        outcome=Outcome.success if status < 400 else Outcome.failure,
        user_agent=clean_str(_unescape(m["ua"] or "")),
    )
    req = _unescape(m["req"])
    if rm := REQUEST.match(req):
        ev.url = rm["target"][:8192]
        ev.extra.update(method=rm["method"], protocol=rm["proto"])
    else:
        # Garbage request lines (TLS handshakes to port 80, scanners) are worth keeping.
        ev.url = None
        ev.extra["malformed_request"] = req[:2048]
        ev.tags.append("malformed_request")
    size = clean_int(m["size"])
    if size is not None:
        ev.extra["bytes"] = size
    if ref := clean_str(_unescape(m["ref"] or "")):
        ev.extra["referrer"] = ref
    return finalise(ev)


def parse_lines(lines: Iterable[tuple[int, str]], ctx: ParseContext) -> Iterator[ParseResult]:
    for line_no, line in lines:
        out = parse_line(line, ctx)
        if isinstance(out, str):
            yield Unparsed(raw=line, reason=out, line_no=line_no)
        else:
            yield Parsed(out, line_no)
