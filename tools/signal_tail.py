#!/usr/bin/env python3
"""signal-tail: follow a log file and ship new lines to SIGNAL's live ingest endpoint.

Standard library only, so it runs on any box with Python 3.10+ (a lab VM, a jump host).

    export SIGNAL_INGEST_TOKEN=sig_...           # create one under Ingest → Tokens
    python3 signal_tail.py /var/log/auth.log --format linux_auth --url http://signal:8080

Behaviour
- Follows the file like `tail -F`: survives rotation (inode change) and truncation.
- Sends only complete lines, in batches (size or time based, whichever comes first).
- Each line carries seq "<inode>:<byte offset>", so retries never create duplicates and
  identical lines at different offsets are kept.
- Remembers its position in a state file, so a restart resumes instead of re-sending.
- Retries network errors, 429 and 5xx with exponential backoff; other 4xx stop it.
- The token comes from the environment or a file, never argv (argv shows up in `ps`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

FORMATS = ("linux_auth", "web_access", "wazuh", "windows_json", "generic_jsonl")
MAX_LINE = 64 * 1024

Post = Callable[[dict[str, object]], dict[str, object]]


class FatalError(RuntimeError):
    """A response that retrying will not fix (bad token, bad request)."""


class RetryableError(RuntimeError):
    pass


@dataclass
class Position:
    inode: int = 0
    offset: int = 0

    @classmethod
    def load(cls, path: Path | None) -> Position:
        if path is None or not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(int(data["inode"]), int(data["offset"]))
        except (ValueError, KeyError, OSError):
            return cls()

    def save(self, path: Path | None) -> None:
        if path is None:
            return
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": self.inode, "offset": self.offset}))
        tmp.replace(path)


@dataclass
class Follower:
    """Reads complete lines from a file that may grow, rotate or be truncated."""

    path: Path
    pos: Position
    from_start: bool = False
    _fh: object | None = None
    _partial: bytes = b""
    _pending: list[tuple[str, str, int]] = field(default_factory=list)

    def _open(self) -> bool:
        try:
            fh = self.path.open("rb")
        except FileNotFoundError:
            return False
        st = os.fstat(fh.fileno())
        if st.st_ino == self.pos.inode and self.pos.offset <= st.st_size:
            fh.seek(self.pos.offset)
        elif self.pos.inode == 0 and not self.from_start:
            fh.seek(0, os.SEEK_END)  # first run: only new lines, like `tail -f`
            self.pos = Position(st.st_ino, fh.tell())
        else:
            self.pos = Position(st.st_ino, 0)  # rotated, or explicitly from the start
        self._fh = fh
        self._partial = b""
        return True

    def _rotated(self) -> bool:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        return st.st_ino != self.pos.inode or st.st_size < self.pos.offset

    def read(self, limit: int) -> list[tuple[str, str, int]]:
        """Up to `limit` (line, seq, end_offset) tuples. Empty when there is nothing new."""
        if self._fh is None and not self._open():
            return []
        out: list[tuple[str, str, int]] = []
        fh = self._fh
        if fh is None:
            return []
        while len(out) < limit:
            chunk = fh.readline(MAX_LINE)  # type: ignore[attr-defined]
            if not chunk:
                break
            if not chunk.endswith(b"\n") and len(self._partial) + len(chunk) < MAX_LINE:
                self._partial += chunk  # incomplete line: wait for the rest
                continue
            data = self._partial + chunk
            line_start = self.pos.offset
            self._partial = b""
            end = line_start + len(data)
            text = data.decode("utf-8", errors="replace").rstrip("\r\n")
            self.pos = Position(self.pos.inode, end)
            if text.strip():
                out.append((text, f"{self.pos.inode}:{line_start}", end))
        if not out and self._rotated():
            fh.close()  # type: ignore[attr-defined]
            self._fh = None
            # Rotated or truncated: the new file is read from its first byte.
            self.pos = Position(0, 0)
            self.from_start = True
            return self.read(limit)
        return out


def http_poster(url: str, token: str, timeout: float = 15) -> Post:
    endpoint = url.rstrip("/") + "/api/ingest/events"

    def post(body: dict[str, object]) -> dict[str, object]:
        req = urllib.request.Request(  # noqa: S310 - scheme validated in main()
            endpoint,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "signal-tail/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                result: dict[str, object] = json.loads(resp.read() or b"{}")
                return result
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace")
            if e.code == 429 or e.code >= 500:
                raise RetryableError(f"HTTP {e.code}: {detail}") from e
            raise FatalError(f"HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise RetryableError(str(e)) from e

    return post


@dataclass
class Shipper:
    post: Post
    fmt: str
    stream: str
    host: str | None = None
    max_backoff: float = 60.0
    sleep: Callable[[float], None] = time.sleep

    def send(self, lines: list[tuple[str, str, int]]) -> dict[str, object]:
        body: dict[str, object] = {
            "format": self.fmt,
            "stream": self.stream,
            "records": [{"raw": text, "seq": seq} for text, seq, _ in lines],
        }
        if self.host:
            body["host"] = self.host
        delay = 1.0
        while True:
            try:
                return self.post(body)
            except RetryableError as e:
                print(f"signal-tail: {e}; retrying in {delay:.0f}s", file=sys.stderr)
                self.sleep(delay)
                delay = min(delay * 2, self.max_backoff)


def run(
    follower: Follower,
    shipper: Shipper,
    state: Path | None,
    *,
    batch_size: int,
    interval: float,
    once: bool = False,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Main loop. Returns the number of lines shipped (useful for --once and tests)."""
    shipped = 0
    buf: list[tuple[str, str, int]] = []
    last_flush = clock()
    while True:
        new = follower.read(batch_size - len(buf))
        buf.extend(new)
        due = buf and (len(buf) >= batch_size or clock() - last_flush >= interval or once)
        if due:
            result = shipper.send(buf)
            shipped += len(buf)
            # Persist the offset only after the server accepted the batch.
            Position(follower.pos.inode, buf[-1][2]).save(state)
            print(
                f"signal-tail: sent {len(buf)} "
                f"(parsed {result.get('parsed')}, unparsed {result.get('unparsed')}, "
                f"duplicates {result.get('duplicates')})",
                file=sys.stderr,
            )
            buf = []
            last_flush = clock()
            continue
        if once and not new:
            return shipped
        if not new:
            sleep(0.5)


def _token(args: argparse.Namespace) -> str:
    if args.token_file:
        return Path(args.token_file).read_text().strip()
    token = os.environ.get("SIGNAL_INGEST_TOKEN", "").strip()
    if not token:
        raise SystemExit("set SIGNAL_INGEST_TOKEN or pass --token-file")
    return token


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="signal-tail", description=__doc__.split("\n\n")[0])
    p.add_argument("file", type=Path)
    p.add_argument("--url", default="http://localhost:8080", help="SIGNAL base URL")
    p.add_argument("--format", required=True, choices=FORMATS)
    p.add_argument("--stream", help="stream name (default: <hostname>:<file path>)")
    p.add_argument("--host", help="host name for web access logs")
    p.add_argument("--token-file", help="read the ingest token from this file")
    p.add_argument("--state-file", type=Path, help="where to remember the read position")
    p.add_argument("--from-start", action="store_true", help="ship the existing contents too")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--interval", type=float, default=2.0, help="max seconds between sends")
    p.add_argument("--once", action="store_true", help="ship what is there now, then exit")
    p.add_argument("--insecure", action="store_true", help="allow http:// to non-local hosts")
    args = p.parse_args(argv)

    url = urlparse(args.url)
    if url.scheme not in ("http", "https"):
        raise SystemExit("--url must be http(s)")
    local = url.hostname in ("localhost", "127.0.0.1", "::1")
    if url.scheme == "http" and not local and not args.insecure:
        raise SystemExit("refusing to send a token over plain http; use https or --insecure")

    stream = args.stream or f"{socket.gethostname()}:{args.file.resolve()}"[:128]
    stream = "".join(c if c.isalnum() or c in "._:/@-" else "_" for c in stream)
    digest = hashlib.sha256(stream.encode()).hexdigest()[:12]
    state = args.state_file or Path(f".signal-tail-{digest}.json")
    follower = Follower(args.file, Position.load(state), from_start=args.from_start)
    shipper = Shipper(http_poster(args.url, _token(args)), args.format, stream, args.host)
    try:
        run(
            follower,
            shipper,
            state,
            batch_size=min(args.batch_size, 5000),
            interval=args.interval,
            once=args.once,
        )
    except FatalError as e:
        print(f"signal-tail: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
