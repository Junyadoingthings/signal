# signal

A self-hosted mini SIEM and detection console: ingest security logs, normalise them,
run ATT&CK-mapped detections, correlate alerts into incidents and triage them from a
keyboard-first console.

> **Status: Phase 1 of 7 (foundation).** Auth, roles, audit trail, database schema,
> design system and app shell are in place. Ingestion and detection land next. This
> README is rewritten in full at the end (Phase 7).

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
scripts/   dev runner
```
