#!/usr/bin/env bash
# Runs the API and the Vite dev server together; Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "No .env found. Copy .env.example to .env and set SIGNAL_ADMIN_EMAIL / SIGNAL_ADMIN_PASSWORD." >&2
  exit 1
fi

trap 'kill 0' EXIT INT TERM
(cd backend && uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000) &
(cd frontend && npm run dev) &
wait
