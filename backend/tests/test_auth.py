from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

from app.core.security import hash_password, hash_token, verify_password
from app.storage.models import AuditLog, AuthSession, utcnow


def test_passwords_are_argon2id() -> None:
    h = hash_password("a long enough password")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "a long enough password")
    assert not verify_password(h, "wrong")
    assert not verify_password(None, "anything")


def test_login_sets_hardened_cookie_and_returns_csrf(client: TestClient) -> None:
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["email"] == ADMIN_EMAIL
    assert body["user"]["role"] == "admin"
    assert len(body["csrf_token"]) > 30
    assert "password_hash" not in body["user"]

    cookie = r.headers["set-cookie"].lower()
    assert "signal_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_secure_flag_when_enabled(client: TestClient, settings: object) -> None:
    settings.cookie_secure = True  # type: ignore[attr-defined]
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()


def test_email_is_case_insensitive(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL.upper(), "password": ADMIN_PASSWORD}
    )
    assert r.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"email": ADMIN_EMAIL, "password": "wrong password"},
        {"email": "nobody@signal.test", "password": ADMIN_PASSWORD},
    ],
)
def test_bad_credentials_get_one_generic_error(client: TestClient, payload: dict[str, str]) -> None:
    r = client.post("/api/auth/login", json=payload)
    assert r.status_code == 401
    assert r.json() == {
        "error": {"code": "invalid_credentials", "message": "Invalid email or password"}
    }


def test_failed_and_successful_logins_are_audited(client: TestClient, db: Session) -> None:
    client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "nope nope nope"})
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    actions = [a.action for a in db.exec(select(AuditLog)).all()]
    assert "auth.login_failed" in actions
    assert "auth.login" in actions


def test_login_requires_json(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login",
        content=f'{{"email":"{ADMIN_EMAIL}","password":"{ADMIN_PASSWORD}"}}',
        headers={"content-type": "text/plain"},
    )
    assert r.status_code in (415, 422)


def test_login_rejects_unknown_fields(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "role": "admin"},
    )
    assert r.status_code == 422
    # Validation errors never echo the submitted input (it contains the password).
    assert ADMIN_PASSWORD not in r.text


def test_login_is_rate_limited(client: TestClient) -> None:
    codes = [
        client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "x"}).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5
    assert codes[-1] == 429
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.json()["error"]["code"] == "rate_limited"


def test_me_requires_session(client: TestClient) -> None:
    r = client.get("/api/auth/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthenticated"


def test_me_and_logout(client: TestClient) -> None:
    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert client.get("/api/auth/me").status_code == 200

    assert client.post("/api/auth/logout").status_code == 403  # no CSRF header
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_session_tokens_are_stored_hashed(client: TestClient, db: Session) -> None:
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    token = client.cookies.get("signal_session")
    assert token
    stored = db.exec(select(AuthSession)).one()
    assert stored.token_hash == hash_token(token)
    assert token not in stored.token_hash


def test_expired_session_is_rejected(client: TestClient, db: Session) -> None:
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    s = db.exec(select(AuthSession)).one()
    s.expires_at = utcnow() - timedelta(minutes=1)
    db.add(s)
    db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_forged_cookie_is_rejected(client: TestClient) -> None:
    client.cookies.set("signal_session", "forged-token-value")
    assert client.get("/api/auth/me").status_code == 401


def test_session_endpoint_is_null_when_signed_out(client: TestClient) -> None:
    r = client.get("/api/auth/session")
    assert r.status_code == 200
    assert r.json() is None
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert client.get("/api/auth/session").json()["user"]["email"] == ADMIN_EMAIL
