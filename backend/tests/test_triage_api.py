"""Alert queue, triage workflow, notes, history, incidents API and the live WebSocket,
driven end to end from an uploaded log file."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from tests.conftest import ANALYST_EMAIL, ANALYST_PASSWORD, admin_login, login
from tests.test_ingest_api import upload, wait

from app.storage.models import User

ATTACK_LOG = (
    "\n".join(
        [
            f"Oct 20 02:00:{i:02d} web01 sshd[{100 + i}]: Failed password for root from 203.0.113.50 port {40000 + i} ssh2"
            for i in range(12)
        ]
        + [
            "Oct 20 02:01:00 web01 sshd[200]: Accepted password for deploy from 203.0.113.50 port 41000 ssh2",
            "Oct 20 02:02:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m svc-backup",
            "Oct 20 02:02:01 web01 useradd[300]: new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup, shell=/bin/bash",
            "Oct 20 02:02:30 web01 usermod[301]: add 'svc-backup' to group 'sudo'",
            "Oct 20 11:00:00 db01 useradd[400]: new user: name=intern, UID=1003, GID=1003, home=/home/intern, shell=/bin/bash",
        ]
    )
    + "\n"
)


@pytest.fixture
def seeded(client: TestClient) -> dict[str, str]:
    h = admin_login(client)
    b = upload(client, h, "attack.log", content=ATTACK_LOG.encode())
    assert b["_status"] == 202
    wait(client)
    return h


def alerts(client: TestClient, **params: Any) -> dict[str, Any]:
    r = client.get("/api/alerts", params=params)
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def test_queue_lists_filters_and_sorts(client: TestClient, seeded: dict[str, str]) -> None:
    everything = alerts(client)
    rules = {a["rule_id"] for a in everything["items"]}
    assert {
        "sig-auth-brute-force",
        "sig-auth-success-after-brute-force",
        "sig-persist-new-account",
        "sig-persist-admin-group",
    } <= rules
    assert everything["total"] == len(everything["items"])
    row = everything["items"][0]
    assert row["rule_title"]
    assert "tactic" in row

    crit = alerts(client, severity=["critical"])
    assert {a["rule_id"] for a in crit["items"]} == {"sig-auth-success-after-brute-force"}

    by_entity = alerts(client, entity="db01")
    assert [a["user"] for a in by_entity["items"]] == ["intern"]

    by_search = alerts(client, q="brute")  # matches the rule title
    assert {a["rule_id"] for a in by_search["items"]} == {
        "sig-auth-brute-force",
        "sig-auth-success-after-brute-force",
    }

    sev_sorted = alerts(client, sort="severity", order="desc")["items"]
    assert sev_sorted[0]["severity"] == "critical"

    page = alerts(client, limit=2, offset=1)
    assert len(page["items"]) == 2
    assert page["total"] == everything["total"]


def test_search_input_is_not_sql(client: TestClient, seeded: dict[str, str]) -> None:
    for q in ["%", "_", "' OR 1=1 --", "\\"]:
        assert alerts(client, q=q)["total"] == 0


def test_alert_detail_explains_itself(client: TestClient, seeded: dict[str, str]) -> None:
    brute = alerts(client, rule_id="sig-auth-brute-force")["items"][0]
    d = client.get(f"/api/alerts/{brute['id']}").json()
    assert d["rule"]["false_positives"]
    assert d["rule"]["techniques"][0]["id"] == "T1110.001"
    assert d["rule"]["techniques"][0]["name"] == "Password Guessing"
    assert d["events_total"] == 12
    assert len(d["events"]) == 12
    assert d["events"][0]["raw"].startswith("Oct 20 02:00:00 web01 sshd")
    matched = d["alert"]["match_context"]["matched"]
    assert {m["field"] for m in matched} == {"action", "outcome"}


def test_triage_workflow_and_audit_trail(client: TestClient, seeded: dict[str, str]) -> None:
    h = seeded
    a = alerts(client, entity="db01")["items"][0]
    url = f"/api/alerts/{a['id']}"

    r = client.patch(url, json={"status": "closed"}, headers=h)
    assert r.status_code == 409
    assert "verdict" in r.json()["error"]["message"]

    me = client.get("/api/auth/me").json()["user"]
    r = client.patch(url, json={"status": "investigating", "assignee_id": me["id"]}, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "investigating"
    assert body["assignee_name"] == me["display_name"]
    assert body["acknowledged_at"] is not None

    r = client.post(
        f"{url}/notes",
        json={"markdown": "Onboarding ticket **HR-1042**. <script>x</script>"},
        headers=h,
    )
    assert r.status_code == 201

    r = client.patch(url, json={"status": "closed", "verdict": "benign_true_positive"}, headers=h)
    assert r.status_code == 200
    assert r.json()["closed_at"] is not None

    r = client.patch(url, json={"status": "investigating"}, headers=h)  # reopen
    assert r.json()["verdict"] is None
    assert r.json()["closed_at"] is None

    hist = client.get(f"{url}/history").json()
    kinds = [(e["kind"], e.get("action")) for e in hist]
    assert kinds.count(("audit", "alert.update")) == 3
    note = next(e for e in hist if e["kind"] == "note")
    # Stored verbatim; the UI renders markdown without raw HTML.
    assert note["note"]["markdown"].endswith("<script>x</script>")
    closing = next(e for e in hist if e.get("after", {}) and e["after"].get("status") == "closed")
    assert closing["before"]["status"] == "investigating"
    assert closing["actor"] == me["email"]


def test_invalid_assignee_and_verdict_rules(client: TestClient, seeded: dict[str, str]) -> None:
    a = alerts(client)["items"][0]
    r = client.patch(f"/api/alerts/{a['id']}", json={"assignee_id": 9999}, headers=seeded)
    assert r.status_code == 409
    r = client.patch(f"/api/alerts/{a['id']}", json={"verdict": "true_positive"}, headers=seeded)
    assert r.status_code == 409  # verdicts only when closing
    r = client.patch(f"/api/alerts/{a['id']}", json={"verdict": "maybe"}, headers=seeded)
    assert r.status_code == 422


def test_bulk_close(client: TestClient, seeded: dict[str, str]) -> None:
    ids = [a["id"] for a in alerts(client, rule_id="sig-persist-new-account")["items"]]
    r = client.post(
        "/api/alerts/bulk",
        json={"ids": [*ids, 424242], "status": "closed", "verdict": "false_positive"},
        headers=seeded,
    )
    out = r.json()
    assert sorted(out["updated"]) == sorted(ids)
    assert out["errors"] == {"424242": "not found"}
    assert alerts(client, rule_id="sig-persist-new-account", status=["closed"])["total"] == len(ids)


def test_analyst_can_triage(client: TestClient, seeded: dict[str, str], analyst: User) -> None:
    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    a = alerts(client)["items"][0]
    r = client.patch(
        f"/api/alerts/{a['id']}", json={"status": "investigating"}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 200
    assert client.patch(f"/api/alerts/{a['id']}", json={"status": "closed"}).status_code == 403


def test_incident_detail_and_close_with_alerts(client: TestClient, seeded: dict[str, str]) -> None:
    incs = client.get("/api/incidents").json()
    assert incs["total"] == 1
    inc = incs["items"][0]
    assert inc["severity"] == "critical"
    assert inc["title"].startswith("web01")

    d = client.get(f"/api/incidents/{inc['id']}").json()
    story = d["storyline"]
    assert [s["tactic"] for s in story][:2] == ["credential-access", "initial-access"]
    assert all(s["alert_id"] in {a["id"] for a in d["alerts"]} for s in story)
    assert "db01" not in inc["entities"]["host"]

    r = client.patch(
        f"/api/incidents/{inc['id']}",
        json={"status": "closed", "verdict": "true_positive", "close_alerts": True},
        headers=seeded,
    )
    assert r.status_code == 200
    still_open = alerts(client, incident_id=inc["id"], status=["new", "investigating"])
    assert still_open["total"] == 0
    hist = client.get(f"/api/incidents/{inc['id']}/history").json()
    assert any(e.get("action") == "incident.update" for e in hist)


def test_user_directory_for_any_user(client: TestClient, analyst: User) -> None:
    login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    names = {u["display_name"] for u in client.get("/api/users/directory").json()}
    assert "Ana Lyst" in names


# --------------------------------------------------------------------------- websocket


def test_websocket_requires_session_and_same_origin(client: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/ws", headers={"origin": "http://localhost:5173"}) as ws,
    ):
        ws.receive_json()

    admin_login(client)
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/ws", headers={"origin": "https://evil.example"}) as ws,
    ):
        ws.receive_json()


def test_websocket_streams_new_alerts(client: TestClient) -> None:
    h = admin_login(client)
    with client.websocket_connect("/ws", headers={"origin": "http://localhost:5173"}) as ws:
        assert ws.receive_json() == {"type": "hello"}
        upload(client, h, "attack.log", content=ATTACK_LOG.encode())
        wait(client)
        seen: list[dict[str, Any]] = []
        while not any(m["type"] == "alerts" for m in seen):
            seen.append(ws.receive_json())
        kinds = {m["type"] for m in seen}
        assert "events" in kinds
        alert_msg = next(m for m in seen if m["type"] == "alerts")
        assert alert_msg["ids"]
