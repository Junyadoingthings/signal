#!/usr/bin/env python3
"""Generate the sample data and upload it to a running SIGNAL (stdlib only).

    python3 tools/seed/load.py [--url http://localhost:5173] [--out sample-data]

Credentials come from SIGNAL_ADMIN_EMAIL / SIGNAL_ADMIN_PASSWORD (environment or .env).
"""

# ruff: noqa: E501, S310
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from http.cookiejar import CookieJar
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import generate

FILES = {
    "web01-auth.log": {},
    "db01-auth.log": {},
    "web01-access.log": {"host": "web01"},
    "windows-events.jsonl": {},
    "wazuh-alerts.json": {},
}


def env(root: Path) -> dict[str, str]:
    out = dict(os.environ)
    f = root / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out.setdefault(k.strip(), v.strip())
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://localhost:5173")
    ap.add_argument("--out", type=Path, default=Path("sample-data"))
    args = ap.parse_args()

    email = env(Path.cwd()).get("SIGNAL_ADMIN_EMAIL")
    password = env(Path.cwd()).get("SIGNAL_ADMIN_PASSWORD")
    if not email or not password:
        print("Set SIGNAL_ADMIN_EMAIL and SIGNAL_ADMIN_PASSWORD (or put them in .env).")
        return 1

    counts = generate.generate(args.out, generate.default_day())
    print(f"generated {sum(counts.values())} records in {args.out}/")

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def call(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        try:
            with opener.open(req, timeout=60) as r:
                return json.loads(r.read() or b"{}")  # type: ignore[no-any-return]
        except urllib.error.HTTPError as e:
            print(f"{req.full_url}: HTTP {e.code} {e.read()[:200].decode(errors='replace')}")
            raise SystemExit(1) from e
        except urllib.error.URLError as e:
            print(f"Can't reach {args.url}: {e.reason}. Is `make dev` running?")
            raise SystemExit(1) from e

    me = call(
        urllib.request.Request(
            f"{args.url}/api/auth/login",
            json.dumps({"email": email, "password": password}).encode(),
            {"Content-Type": "application/json"},
        )
    )
    csrf = me["csrf_token"]

    # The generated syslog has no year; tell SIGNAL which one it is.
    call(
        urllib.request.Request(
            f"{args.url}/api/ingest/settings",
            json.dumps(
                {"syslog_timezone": "UTC", "syslog_year": generate.default_day().year}
            ).encode(),
            {"Content-Type": "application/json", "X-CSRF-Token": csrf},
            method="PUT",
        )
    )

    for name, fields in FILES.items():
        boundary = uuid.uuid4().hex
        parts = []
        for k, v in fields.items():
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
            )
        body = (args.out / name).read_bytes()
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n".encode()
            + body
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        batch = call(
            urllib.request.Request(
                f"{args.url}/api/ingest/upload",
                b"".join(parts),
                {"Content-Type": f"multipart/form-data; boundary={boundary}", "X-CSRF-Token": csrf},
            )
        )
        print(f"uploaded {name} -> batch #{batch['id']} ({batch['source_type']})")

    time.sleep(1)
    for _ in range(60):
        items = call(urllib.request.Request(f"{args.url}/api/ingest/batches?limit=10"))["items"]
        if all(b["status"] in ("done", "failed") for b in items[: len(FILES)]):
            break
        time.sleep(1)
    incidents = call(urllib.request.Request(f"{args.url}/api/incidents"))
    print(f"\ndone: {incidents['total']} incidents. Open {args.url}/incidents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
