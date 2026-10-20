from fastapi.testclient import TestClient
from sqlmodel import Session, select
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ANALYST_EMAIL, ANALYST_PASSWORD, login

from app.storage.models import AuditLog, User

NEW_USER = {
    "email": "new.analyst@signal.test",
    "display_name": "New Analyst",
    "role": "analyst",
    "password": "a sufficiently long pw",
}


def test_analyst_cannot_use_admin_endpoints(client: TestClient, analyst: User) -> None:
    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    h = {"X-CSRF-Token": csrf}
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/users", json=NEW_USER, headers=h).status_code == 403
    assert (
        client.patch(f"/api/users/{analyst.id}", json={"role": "admin"}, headers=h).status_code
        == 403
    )


def test_analyst_can_read_status(client: TestClient, analyst: User) -> None:
    login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    r = client.get("/api/system/status")
    assert r.status_code == 200
    assert r.json()["events_total"] == 0


def test_admin_creates_user_with_csrf_and_audit(client: TestClient, db: Session) -> None:
    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert client.post("/api/users", json=NEW_USER).status_code == 403  # missing CSRF
    r = client.post("/api/users", json=NEW_USER, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201
    assert r.json()["role"] == "analyst"

    entry = db.exec(select(AuditLog).where(AuditLog.action == "user.create")).one()
    assert entry.actor_email == ADMIN_EMAIL
    assert entry.after is not None
    assert "password" not in entry.after

    dup = client.post("/api/users", json=NEW_USER, headers={"X-CSRF-Token": csrf})
    assert dup.status_code == 409


def test_weak_password_rejected(client: TestClient) -> None:
    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    r = client.post(
        "/api/users", json=NEW_USER | {"password": "short"}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 422


def test_cannot_remove_last_admin(client: TestClient) -> None:
    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    me = client.get("/api/auth/me").json()["user"]
    r = client.patch(
        f"/api/users/{me['id']}", json={"role": "analyst"}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "last_admin"


def test_role_change_revokes_sessions(client: TestClient, analyst: User) -> None:
    other = TestClient(client.app)
    login(other, ANALYST_EMAIL, ANALYST_PASSWORD)
    assert other.get("/api/auth/me").status_code == 200

    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    r = client.patch(
        f"/api/users/{analyst.id}", json={"is_active": False}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_audit_log_lists_and_paginates(client: TestClient) -> None:
    csrf = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    client.post("/api/users", json=NEW_USER, headers={"X-CSRF-Token": csrf})
    r = client.get("/api/audit", params={"limit": 2})
    assert r.status_code == 200
    page = r.json()
    assert len(page["items"]) == 2
    assert page["items"][0]["action"] == "user.create"  # newest first
    assert page["next_before_id"] is not None
