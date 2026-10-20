"""End-to-end ingestion through the API: uploads, worker, dedup, unparsed, live, tokens."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, col, select
from tests.conftest import ANALYST_EMAIL, ANALYST_PASSWORD, admin_login, login

from app.core.config import Settings
from app.ingest import pipeline
from app.storage.models import Entity, EntityEdge, EntityType, Event, User

FIX = Path(__file__).parent / "fixtures" / "ingest"


def upload(
    client: TestClient,
    headers: dict[str, str],
    name: str,
    *,
    content: bytes | None = None,
    form: dict[str, str] | None = None,
    **fields: str,
) -> dict[str, object]:
    data = content if content is not None else (FIX / name).read_bytes()
    form = (form or {}) | fields
    r = client.post("/api/ingest/upload", files={"file": (name, data)}, data=form, headers=headers)
    body: dict[str, object] = r.json()
    body["_status"] = r.status_code
    return body


def wait(client: TestClient) -> None:
    client.app.state.ingest_worker.join()  # type: ignore[attr-defined]


def batch(client: TestClient, batch_id: object) -> dict[str, object]:
    r = client.get(f"/api/ingest/batches/{batch_id}")
    assert r.status_code == 200
    out: dict[str, object] = r.json()
    return out


def test_upload_auth_log_end_to_end(client: TestClient, db: Session) -> None:
    h = admin_login(client)
    b = upload(client, h, "auth.log")
    assert b["_status"] == 202, b
    assert b["source_type"] == "linux_auth"
    assert b["status"] == "pending"
    assert b["tz_assumption"] == "UTC"
    wait(client)

    done = batch(client, b["id"])
    assert done["status"] == "done"
    assert (done["parsed_count"], done["unparsed_count"], done["duplicate_count"]) == (15, 1, 0)

    events = client.get("/api/events", params={"batch_id": b["id"]}).json()["items"]
    assert len(events) == 15
    unparsed = client.get("/api/ingest/unparsed", params={"batch_id": b["id"]}).json()["items"]
    assert unparsed[0]["reason"] == "not a syslog line"
    assert unparsed[0]["raw"] == "this line is not syslog at all"

    # Entities and relationships were extracted.
    hosts = db.exec(select(Entity).where(Entity.type == EntityType.host)).all()
    assert [h.value for h in hosts] == ["web01"]
    assert hosts[0].event_count == 15
    ip = db.exec(select(Entity).where(Entity.value == "203.0.113.50")).one()
    edge = db.exec(
        select(EntityEdge).where(
            EntityEdge.src_entity_id == ip.id, EntityEdge.relation == "connected_to"
        )
    ).one()
    assert edge.count == 5

    # Same file again: everything is a duplicate, entity counts don't double.
    again = upload(client, h, "auth.log")
    wait(client)
    second = batch(client, again["id"])
    # 15 events + the 1 unparsed line are all recognised as already seen.
    assert (second["parsed_count"], second["unparsed_count"], second["duplicate_count"]) == (
        0,
        0,
        16,
    )
    db.expire_all()
    assert db.get(Entity, hosts[0].id).event_count == 15  # type: ignore[union-attr]


def test_upload_every_format(client: TestClient) -> None:
    h = admin_login(client)
    cases = {
        "access.log": ("web_access", {"host": "web01"}),
        "wazuh_alerts.json": ("wazuh", {}),
        "windows_evtx_dump.jsonl": ("windows_json", {}),
        "windows_powershell.json": ("windows_json", {}),
        "generic.jsonl": (
            "generic_jsonl",
            {"field_mapping": json.dumps({"timestamp": "ts", "host": "device.name"})},
        ),
    }
    ids = {}
    for name, (fmt, form) in cases.items():
        b = upload(client, h, name, form=form)
        assert b["_status"] == 202, (name, b)
        assert b["source_type"] == fmt
        ids[name] = b["id"]
    wait(client)
    for name, bid in ids.items():
        assert batch(client, bid)["status"] == "done", name
        assert int(str(batch(client, bid)["parsed_count"])) > 0, name


def test_analyst_can_upload(client: TestClient, analyst: User) -> None:
    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    b = upload(client, {"X-CSRF-Token": csrf}, "auth.log")
    assert b["_status"] == 202


def test_upload_requires_csrf(client: TestClient) -> None:
    admin_login(client)
    assert upload(client, {}, "auth.log")["_status"] == 403


@pytest.mark.parametrize(
    ("name", "content", "form", "status"),
    [
        ("auth.log", b"PK\x03\x04" + b"\x00" * 64, {}, 415),  # zip renamed to .log
        ("payload.log", b"MZ\x90\x00" + b"\x00" * 64, {}, 415),
        ("prose.txt", b"dear diary\ntoday was fine\n", {}, 415),
        ("auth.log", None, {"format": "wazuh"}, 415),  # explicit format contradicts content
        ("generic.jsonl", None, {"format": "generic_jsonl"}, 422),  # no mapping
        ("generic.jsonl", None, {"field_mapping": "not json"}, 422),
    ],
)
def test_upload_rejections(
    client: TestClient,
    settings: Settings,
    name: str,
    content: bytes | None,
    form: dict[str, str],
    status: int,
) -> None:
    h = admin_login(client)
    if name == "generic.jsonl" and "format" not in form:
        form = form | {"format": "generic_jsonl"}
    b = upload(client, h, name, content=content, form=form)
    assert b["_status"] == status, b
    # Nothing left behind in the spool.
    assert not list((Path(settings.data_dir) / "uploads").glob("*.upload"))


def test_upload_size_limit(client: TestClient, settings: Settings) -> None:
    settings.max_upload_bytes = 1024
    h = admin_login(client)
    big = (FIX / "auth.log").read_bytes() * 4
    b = upload(client, h, "auth.log", content=big)
    assert b["_status"] == 413


def test_filename_is_display_only(client: TestClient, settings: Settings) -> None:
    h = admin_login(client)
    b = upload(client, h, "../../../etc/evil.log", content=(FIX / "auth.log").read_bytes())
    assert b["_status"] == 202
    assert b["filename"] == "evil.log"
    wait(client)
    assert not Path("/etc/evil.log").exists()


def test_raw_html_is_stored_verbatim_for_safe_rendering(client: TestClient) -> None:
    h = admin_login(client)
    line = (
        '198.51.100.7 - - [20/Oct/2026:10:00:00 +0000] "GET /<script>alert(1)</script> '
        'HTTP/1.1" 404 0 "-" "<img src=x onerror=alert(1)>"\n'
    )
    b = upload(client, h, "xss.log", content=line.encode(), host="web01")
    wait(client)
    ev = client.get("/api/events", params={"batch_id": b["id"]}).json()["items"][0]
    assert ev["raw"] == line.rstrip("\n")
    assert ev["user_agent"] == "<img src=x onerror=alert(1)>"
    # JSON API: the browser receives it as data, never as markup.
    assert client.get(f"/api/events/{ev['id']}").headers["content-type"] == "application/json"


def test_syslog_settings_drive_parsing(client: TestClient) -> None:
    h = admin_login(client)
    r = client.put(
        "/api/ingest/settings",
        json={"syslog_timezone": "Mars/Olympus", "syslog_year": None},
        headers=h,
    )
    assert r.status_code == 422
    r = client.put(
        "/api/ingest/settings",
        json={"syslog_timezone": "Africa/Johannesburg", "syslog_year": 2025},
        headers=h,
    )
    assert r.status_code == 200
    b = upload(client, h, "auth.log")
    assert b["tz_assumption"] == "Africa/Johannesburg"
    assert b["year_assumption"] == 2025
    wait(client)
    ev = client.get("/api/events", params={"batch_id": b["id"]}).json()["items"][-1]
    assert ev["timestamp"].startswith("2025-10-20T01:14:07")


def test_analyst_cannot_change_settings(client: TestClient, analyst: User) -> None:
    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    r = client.put(
        "/api/ingest/settings",
        json={"syslog_timezone": "UTC", "syslog_year": None},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403


def test_post_ingest_hook_receives_new_event_ids(client: TestClient) -> None:
    seen: list[int] = []

    def hook(_: Session, ids: list[int]) -> None:
        seen.extend(ids)

    pipeline.post_ingest_hooks.append(hook)
    try:
        h = admin_login(client)
        upload(client, h, "auth.log")
        wait(client)
    finally:
        pipeline.post_ingest_hooks.remove(hook)
    assert len(seen) == 15


# --------------------------------------------------------------------------- live


def make_token(client: TestClient, h: dict[str, str]) -> str:
    r = client.post("/api/ingest/tokens", json={"name": "web01 tail"}, headers=h)
    assert r.status_code == 201
    token: str = r.json()["token"]
    assert token.startswith("sig_")
    return token


def live(client: TestClient, token: str | None, records: list[dict[str, str]], **kw: str) -> object:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    body = {"format": "linux_auth", "stream": "web01:/var/log/auth.log", "records": records} | kw
    return client.post("/api/ingest/events", json=body, headers=headers)


def test_live_ingest_with_token(client: TestClient, db: Session) -> None:
    h = admin_login(client)
    token = make_token(client, h)
    client.cookies.clear()  # machine client: token only

    line = (
        "Oct 20 03:14:09 web01 sshd[2213]: "
        "Failed password for root from 203.0.113.50 port 50130 ssh2"
    )
    r = live(
        client, token, [{"raw": line, "seq": "100"}, {"raw": line, "seq": "200"}, {"raw": "junk"}]
    )
    assert r.status_code == 200, r.text  # type: ignore[attr-defined]
    out = r.json()  # type: ignore[attr-defined]
    assert (out["parsed"], out["unparsed"], out["duplicates"]) == (2, 1, 0)

    # Retried POST (same seq) is idempotent.
    r2 = live(client, token, [{"raw": line, "seq": "100"}]).json()  # type: ignore[attr-defined]
    assert r2["duplicates"] == 1
    assert r2["batch_id"] == out["batch_id"]

    n = db.exec(select(Event).where(col(Event.batch_id) == out["batch_id"])).all()
    assert len(n) == 2


def test_live_ingest_auth(client: TestClient) -> None:
    rec = [{"raw": "x"}]
    assert live(client, None, rec).status_code == 401  # type: ignore[attr-defined]
    assert live(client, "sig_forged", rec).status_code == 401  # type: ignore[attr-defined]

    h = admin_login(client)
    # Session without CSRF is refused; with CSRF it's allowed (UI path).
    assert live(client, None, rec).status_code == 403  # type: ignore[attr-defined]
    r = client.post(
        "/api/ingest/events",
        json={"format": "linux_auth", "stream": "ui", "records": rec},
        headers=h,
    )
    assert r.status_code == 200

    token = make_token(client, h)
    tid = client.get("/api/ingest/tokens").json()[0]["id"]
    assert client.delete(f"/api/ingest/tokens/{tid}", headers=h).status_code == 204
    client.cookies.clear()
    assert live(client, token, rec).status_code == 401  # type: ignore[attr-defined]


def test_live_ingest_validation(client: TestClient) -> None:
    h = admin_login(client)
    token = make_token(client, h)
    bad_stream = live(client, token, [{"raw": "x"}], stream="<script>alert(1)</script>")
    assert bad_stream.status_code == 422  # type: ignore[attr-defined]
    evtx = live(client, token, [{"raw": "x"}], format="evtx")
    assert evtx.status_code == 422  # type: ignore[attr-defined]
    empty = live(client, token, [])
    assert empty.status_code == 422  # type: ignore[attr-defined]


def test_tokens_admin_only(client: TestClient, analyst: User) -> None:
    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    r = client.post("/api/ingest/tokens", json={"name": "x"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403
    assert client.get("/api/ingest/tokens").status_code == 403
