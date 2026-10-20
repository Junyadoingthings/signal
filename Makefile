.PHONY: help install dev backend frontend test test-backend test-frontend lint fmt migrate build up down

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install backend + frontend dependencies
	cd backend && uv sync
	cd frontend && npm ci

dev: ## Run API (:8000) and UI (:5173) with reload, no Docker
	./scripts/dev.sh

backend: ## Run only the API with reload
	cd backend && uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000

frontend: ## Run only the UI dev server
	cd frontend && npm run dev

test: test-backend test-frontend ## Run all tests

test-backend:
	cd backend && uv run pytest

test-frontend:
	cd frontend && npm test

lint: ## ruff + mypy + eslint + prettier + tsc
	cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
	cd frontend && npm run lint && npm run format:check && npm run typecheck

fmt: ## Auto-format everything
	cd backend && uv run ruff check --fix . && uv run ruff format .
	cd frontend && npm run format

migrate: ## Apply database migrations
	cd backend && uv run python -m app.storage.migrate

up: ## docker compose up (http://localhost:8080)
	docker compose up --build

down:
	docker compose down
