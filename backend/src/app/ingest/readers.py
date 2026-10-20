"""Streaming readers: bytes → text lines → JSON records, never the whole file in memory.

Encoding is decided by BOM (Windows PowerShell 5.1 writes UTF-16LE with a BOM when you
redirect with `>`), defaulting to UTF-8. Undecodable bytes are replaced rather than
dropping the record, so raw is always preserved.
"""

import codecs
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import IO, Any

MAX_LINE_CHARS = 64 * 1024
_CHUNK = 64 * 1024

_BOMS: list[tuple[bytes, str]] = [
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
]


def detect_encoding(head: bytes) -> str:
    for bom, enc in _BOMS:
        if head.startswith(bom):
            return enc
    return "utf-8"


def iter_text_chunks(stream: IO[bytes]) -> Iterator[str]:
    head = stream.read(4)
    decoder = codecs.getincrementaldecoder(detect_encoding(head))(errors="replace")
    data = head
    while True:
        if data:
            text = decoder.decode(data)
            if text:
                yield text
        data = stream.read(_CHUNK)
        if not data:
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail
            return


def iter_lines(stream: IO[bytes]) -> Iterator[tuple[int, str]]:
    """Yields (1-based line number, line without newline). Blank lines are skipped."""
    buf = ""
    line_no = 0
    for chunk in iter_text_chunks(stream):
        buf += chunk
        *lines, buf = buf.split("\n")
        for line in lines:
            line_no += 1
            line = line.rstrip("\r").replace("\x00", "")
            if line.strip():
                yield line_no, line
        if len(buf) > MAX_LINE_CHARS * 4:  # pathological: no newlines at all
            line_no += 1
            yield line_no, buf
            buf = ""
    if buf.strip():
        yield line_no + 1, buf.rstrip("\r").replace("\x00", "")


@dataclass(slots=True, frozen=True)
class JsonRecord:
    line_no: int | None
    raw: str
    obj: Any = None
    error: str | None = None


def _decode(raw: str, line_no: int | None) -> JsonRecord:
    if len(raw) > MAX_LINE_CHARS * 4:
        return JsonRecord(line_no, raw[: MAX_LINE_CHARS * 4], error="record too large")
    try:
        return JsonRecord(line_no, raw, json.loads(raw))
    except (json.JSONDecodeError, RecursionError) as e:
        return JsonRecord(line_no, raw, error=f"invalid JSON: {e.msg if hasattr(e, 'msg') else e}")


def iter_json_lines(lines: Iterable[tuple[int, str]]) -> Iterator[JsonRecord]:
    for line_no, line in lines:
        yield _decode(line.strip(), line_no)


def iter_json_array(chunks: Iterable[str]) -> Iterator[JsonRecord]:
    """Splits a top-level JSON array into element texts without parsing it all at once.
    Tracks depth and string/escape state; each element is then json.loads'ed alone."""
    depth = 0
    in_str = False
    esc = False
    started = False
    buf: list[str] = []
    index = 0

    def flush() -> JsonRecord | None:
        nonlocal buf, index
        text = "".join(buf).strip()
        buf = []
        if not text:
            return None
        index += 1
        return _decode(text, index)

    for chunk in chunks:
        for ch in chunk:
            if not started:
                if ch == "[":
                    started = True
                continue
            if in_str:
                buf.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if depth == 0 and ch in ",]":
                rec = flush()
                if rec is not None:
                    yield rec
                if ch == "]":
                    return
                continue
            buf.append(ch)
            if ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
    rec = flush()
    if rec is not None:
        yield JsonRecord(rec.line_no, rec.raw, error="truncated JSON array")


def iter_json_stream(stream: IO[bytes]) -> Iterator[JsonRecord]:
    """JSON Lines, or one big JSON array (PowerShell ConvertTo-Json output)."""
    chunks = iter_text_chunks(stream)
    first: str | None = None
    pending: list[str] = []
    for chunk in chunks:
        pending.append(chunk)
        stripped = chunk.lstrip()
        if stripped:
            first = stripped[0]
            break

    def replay() -> Iterator[str]:
        yield from pending
        yield from chunks

    if first == "[":
        yield from iter_json_array(replay())
        return

    def lines() -> Iterator[tuple[int, str]]:
        buf = ""
        n = 0
        for c in replay():
            buf += c
            *ls, buf = buf.split("\n")
            for line in ls:
                n += 1
                if line.strip():
                    yield n, line.rstrip("\r")
        if buf.strip():
            yield n + 1, buf

    yield from iter_json_lines(lines())
