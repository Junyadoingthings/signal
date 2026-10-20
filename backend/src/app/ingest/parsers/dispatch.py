"""Format → parser wiring, for files (streamed from disk) and for live record batches."""

from collections.abc import Iterable, Iterator
from pathlib import Path

from app.ingest.parsers import generic_jsonl, linux_auth, wazuh, web_access, windows
from app.ingest.readers import iter_json_lines, iter_json_stream, iter_lines
from app.ingest.sniff import Format
from app.ingest.types import ParseContext, ParseResult

_TEXT = {"linux_auth": linux_auth.parse_lines, "web_access": web_access.parse_lines}
_JSON = {
    "windows_json": windows.parse_json_records,
    "wazuh": wazuh.parse_json_records,
    "generic_jsonl": generic_jsonl.parse_json_records,
}

LIVE_FORMATS: tuple[Format, ...] = (
    "linux_auth",
    "web_access",
    "windows_json",
    "wazuh",
    "generic_jsonl",
)


def parse_file(fmt: Format, path: Path, ctx: ParseContext) -> Iterator[ParseResult]:
    if fmt == "evtx":
        yield from windows.parse_evtx(path)
        return
    with path.open("rb") as fh:
        if fmt in _TEXT:
            yield from _TEXT[fmt](iter_lines(fh), ctx)
        else:
            yield from _JSON[fmt](iter_json_stream(fh), ctx)


def parse_records(fmt: Format, records: Iterable[str], ctx: ParseContext) -> Iterator[ParseResult]:
    """Live ingest: each record is one line of text or one JSON document."""
    numbered = ((i, r) for i, r in enumerate(records, 1))
    if fmt in _TEXT:
        yield from _TEXT[fmt](numbered, ctx)
    elif fmt in _JSON:
        yield from _JSON[fmt](iter_json_lines(numbered), ctx)
    else:
        raise ValueError(f"format {fmt!r} cannot be streamed live")
