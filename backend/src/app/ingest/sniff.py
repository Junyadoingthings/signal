"""Decide a file's format from its content, never its extension.

Formats are what we parse; source types are what events end up as. A Windows EVTX or
JSON export can yield both windows_security and sysmon events.
"""

import json
import re
from typing import Literal

from app.ingest.readers import MAX_LINE_CHARS, detect_encoding

Format = Literal["evtx", "windows_json", "linux_auth", "web_access", "wazuh", "generic_jsonl"]
FORMATS: tuple[Format, ...] = (
    "evtx",
    "windows_json",
    "linux_auth",
    "web_access",
    "wazuh",
    "generic_jsonl",
)

EVTX_MAGIC = b"ElfFile\x00"

# Binary types people commonly drop by mistake. Rejected outright.
_BINARY_MAGIC: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "zip archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"SQLite format 3", "SQLite database"),
    (b"7z\xbc\xaf", "7z archive"),
    (b"Rar!", "RAR archive"),
]

SYSLOG_CLASSIC = re.compile(
    r"^[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ [^\s:\[]+(?:\[\d+\])?: "
)
SYSLOG_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}) "
    r"\S+ [^\s:\[]+(?:\[\d+\])?: "
)
ACCESS_LOG = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} ')


class SniffError(ValueError):
    pass


def _json_kind(obj: object) -> Format:
    if not isinstance(obj, dict):
        return "generic_jsonl"
    rule = obj.get("rule")
    if isinstance(rule, dict) and "level" in rule and ("agent" in obj or "manager" in obj):
        return "wazuh"
    if isinstance(obj.get("Event"), dict) and "System" in obj["Event"]:
        return "windows_json"
    if "Id" in obj and ("ProviderName" in obj or "LogName" in obj):
        return "windows_json"
    return "generic_jsonl"


def _first_json_object(text: str) -> object | None:
    s = text.lstrip()
    if s.startswith("["):
        # Find the first element's text: decode greedily from after "[".
        dec = json.JSONDecoder()
        try:
            obj: object = dec.raw_decode(s[1:].lstrip())[0]
            return obj
        except json.JSONDecodeError:
            return None
    for line in s.splitlines():
        if line.strip():
            try:
                parsed: object = json.loads(line)
                return parsed
            except json.JSONDecodeError:
                return None
    return None


def sniff(head: bytes) -> Format:
    """`head` is the first ~64 KiB of the file."""
    if not head:
        raise SniffError("file is empty")
    if head.startswith(EVTX_MAGIC):
        return "evtx"
    for magic, name in _BINARY_MAGIC:
        if head.startswith(magic):
            raise SniffError(f"unsupported file type: {name}")

    enc = detect_encoding(head)
    text = head.decode(enc, errors="replace")
    if enc == "utf-8" and "\x00" in text:
        raise SniffError("binary content: not a text log, EVTX or JSON file")
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped:
        raise SniffError("file contains only whitespace")

    if stripped[0] in "{[":
        obj = _first_json_object(stripped)
        if obj is None and len(head) < MAX_LINE_CHARS:
            raise SniffError("looks like JSON but the first record does not parse")
        return _json_kind(obj) if obj is not None else "generic_jsonl"

    lines = [ln for ln in stripped.splitlines()[:-1] or stripped.splitlines() if ln.strip()][:50]
    syslog = sum(1 for ln in lines if SYSLOG_CLASSIC.match(ln) or SYSLOG_RFC3339.match(ln))
    access = sum(1 for ln in lines if ACCESS_LOG.match(ln))
    if lines and syslog / len(lines) >= 0.5 and syslog >= access:
        return "linux_auth"
    if lines and access / len(lines) >= 0.5:
        return "web_access"
    raise SniffError("unrecognised format: expected syslog auth log, web access log, EVTX, or JSON")


def compatible(requested: Format, sniffed: Format) -> bool:
    """An explicit choice must agree with the content. JSON content may be forced to the
    generic mapper; nothing else can be overridden."""
    if requested == sniffed:
        return True
    return requested == "generic_jsonl" and sniffed in ("wazuh", "windows_json")
