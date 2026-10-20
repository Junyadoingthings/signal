# signal

A self-hosted mini SIEM and detection console: ingest security logs, normalise them,
run ATT&CK-mapped detections, correlate alerts into incidents and triage them from a
keyboard-first console.

> **Status: Phase 2 of 7 (ingestion).** Auth, roles, audit trail, design system, and
> ingestion for every v1 source are in place. Detection lands next. This README is
> rewritten in full at the end (Phase 7).

## Ingest

Upload in the UI (drag and drop) or with the API. The format is detected from content.

| Source | Accepted as |
|---|---|
| Linux auth | `auth.log` / `secure`, classic or RFC 3339 syslog |
| Windows Security & Sysmon | `.evtx`, `evtx_dump` JSON, PowerShell `Get-WinEvent \| ConvertTo-Json` (UTF-8 or UTF-16) |
| Web server | nginx / Apache Common or Combined |
| Wazuh | `alerts.json`; Windows/Sysmon and sshd alerts are unpacked into the same schema |
| Anything else | JSON Lines with a field mapping |

Live: create an ingest token (Ingest → Live ingest tokens), then on the machine with the log:

```bash
export SIGNAL_INGEST_TOKEN=sig_...
python3 tools/signal_tail.py /var/log/auth.log --format linux_auth --url https://your-signal-host
```

`signal_tail.py` is standard-library only, follows rotation, resumes from a state file,
and is idempotent on retry.

## Run it

### Docker (one command)

```bash
cp .env.example .env   # set SIGNAL_ADMIN_EMAIL and a 12+ char SIGNAL_ADMIN_PASSWORD
docker compose up --build
```

Open <http://localhost:8080> and sign in with the admin from `.env`.

### Dev mode (no Docker)

Requires [uv](https://docs.astral.sh/uv/) and Node 22+.

```bash
cp .env.example .env
make install
make dev        # API on :8000, UI on http://localhost:5173 (proxied, same origin)
```

## Checks

```bash
make test       # pytest + vitest
make lint       # ruff, mypy --strict, eslint (strict type-checked), prettier, tsc
```

## Layout

```
backend/   FastAPI + SQLModel API (Python 3.12), Alembic migrations, pytest
frontend/  React 18 + TypeScript + Vite + Tailwind v4 console, Vitest
tools/     signal_tail.py live shipper
scripts/   dev runner
```
