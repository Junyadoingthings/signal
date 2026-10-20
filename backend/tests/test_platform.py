"""Security headers, CORS, size limits, error format and first-run bootstrap."""

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session

from app.core.config import Settings
from app.services.bootstrap import BootstrapError, ensure_admin
from app.storage.repositories import SqlUserRepository


def test_security_headers(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    h = r.headers
    csp = h["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "'unsafe-inline'" not in csp
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert "server" not in h


def test_cors_only_allows_frontend_origin(client: TestClient) -> None:
    ok = client.options(
        "/api/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert ok.headers.get("access-control-allow-credentials") == "true"

    evil = client.options(
        "/api/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in evil.headers


def test_oversized_body_rejected(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login",
        content=b"x" * (65 * 1024),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_unhandled_errors_do_not_leak(settings: Settings, engine: Engine) -> None:
    from app.main import create_app

    app = create_app(settings, run_migrations=False)
    boom = APIRouter()

    @boom.get("/api/boom")
    def _boom() -> None:
        raise RuntimeError("secret internal detail /etc/passwd")

    app.include_router(boom)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/boom")
    assert r.status_code == 500
    assert r.json() == {
        "error": {"code": "internal_error", "message": "An internal error occurred"}
    }
    assert "secret" not in r.text
    assert "Traceback" not in r.text


def test_unknown_route_uses_error_format(client: TestClient) -> None:
    r = client.get("/api/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_openapi_docs_available(client: TestClient) -> None:
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/docs").status_code == 200


def test_bootstrap_creates_admin_once(client: TestClient, db: Session, settings: Settings) -> None:
    users = SqlUserRepository(db)
    assert users.count() == 1
    ensure_admin(db, settings)
    assert users.count() == 1


def test_bootstrap_refuses_without_env(engine: Engine) -> None:
    with Session(engine) as db, pytest.raises(BootstrapError):
        ensure_admin(db, Settings(env="test", admin_email=None, admin_password=None))


def test_weak_bootstrap_password_rejected() -> None:
    with pytest.raises(ValueError, match="at least 12 characters"):
        Settings(env="test", admin_email="a@b.c", admin_password="short")
