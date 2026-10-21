"""Hunt query language, hunt/histogram/saved-search API and entity pages."""

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from tests.conftest import ANALYST_EMAIL, ANALYST_PASSWORD, admin_login, login
from tests.test_ingest_api import upload, wait
from tests.test_triage_api import ATTACK_LOG

from app.search.compiler import compile_node
from app.search.parser import And, Not, Or, SearchError, Term, Text, parse
from app.storage.models import Event, Outcome, User

# ------------------------------------------------------------------ parser


def test_parse_precedence_and_shapes() -> None:
    assert parse("") is None
    assert parse("  ") is None
    assert parse("user:admin") == Term("user", "eq", "admin")
    assert parse("a b") == And((Text("a"), Text("b")))
    assert parse("a OR b c") == Or((Text("a"), And((Text("b"), Text("c")))))  # AND binds tighter
    assert parse("(a OR b) AND c") == And((Or((Text("a"), Text("b"))), Text("c")))
    assert parse("NOT a") == Not(Text("a"))
    assert parse("-host:web02") == Not(Term("host", "eq", "web02"))
    assert parse("http_status:>=400") == Term("http_status", "gte", "400")
    assert parse('cmdline:"a b"') == Term("cmdline", "eq", "a b")
    assert parse('"two words"') == Text("two words")


def test_parse_the_example_from_the_brief() -> None:
    node = parse("user:admin AND outcome:failure AND src_ip:10.0.*")
    assert node == And(
        (
            Term("user", "eq", "admin"),
            Term("outcome", "eq", "failure"),
            Term("src_ip", "eq", "10.0.*"),
        )
    )


@pytest.mark.parametrize(
    "bad",
    [
        "(a OR b",
        "a OR",
        "AND a",
        ")",
        "user:",
        'x:"unterminated',
        "(" * 30 + "a" + ")" * 30,
        " ".join(["t"] * 120),
        "a" * 1001,
        "http_status:>=",
    ],
)
def test_parse_errors(bad: str) -> None:
    with pytest.raises(SearchError):
        parse(bad)


# ------------------------------------------------------------------ compiler on real rows


@pytest.fixture
def populated(db: Session) -> Session:
    base = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)

    def add(i: int, **kw: Any) -> None:
        db.add(
            Event(
                timestamp=base + timedelta(minutes=i),
                ingested_at=base,
                dedup_hash=f"h{i}",
                source_type=kw.pop("source_type", "linux_auth"),
                raw=kw.pop("raw", f"raw line {i}"),
                **kw,
            )
        )

    add(
        0,
        user="admin",
        outcome=Outcome.failure,
        src_ip="10.0.0.5",
        host="web01",
        action="ssh_login",
    )
    add(
        1,
        user="admin",
        outcome=Outcome.success,
        src_ip="10.0.0.6",
        host="web01",
        action="ssh_login",
    )
    add(
        2,
        user="root",
        outcome=Outcome.failure,
        src_ip="203.0.113.9",
        host="web02",
        action="ssh_login",
    )
    add(
        3,
        source_type="web_access",
        http_status=404,
        url="/a_b%c",
        src_ip="198.51.100.1",
        raw='GET /a_b%c "x"',
        user_agent="sqlmap/1.8",
    )
    add(4, source_type="web_access", http_status=200, url="/ok", src_ip="198.51.100.1")
    add(
        5,
        source_type="sysmon",
        process_name="powershell.exe",
        process_cmdline="powershell -enc AAAA",
        host="ws-07",
        dst_ip="10.0.0.5",
        tags=["rdp"],
    )
    db.commit()
    return db


def ids(db: Session, q: str) -> list[int]:
    node = parse(q)
    stmt = select(Event.dedup_hash)
    if node is not None:
        stmt = stmt.where(compile_node(node))
    return sorted(int(h[1:]) for h in db.exec(stmt).all())


def test_compiled_queries(populated: Session) -> None:
    db = populated
    assert ids(db, "user:admin AND outcome:failure AND src_ip:10.0.*") == [0]
    assert ids(db, "USER:ADMIN") == [0, 1]  # string fields are case-insensitive
    assert ids(db, "user:admin OR user:root") == [0, 1, 2]
    assert ids(db, "outcome:failure NOT user:root") == [0]
    assert ids(db, "-host:web01 action:ssh_login") == [2]
    assert ids(db, "http_status:>=400") == [3]
    assert ids(db, "http_status:<400 type:web_access") == [4]
    assert ids(db, "ip:10.0.0.5") == [0, 5]  # matches src or dst
    assert ids(db, "cmdline:*-enc*") == [5]
    assert ids(db, "tag:rdp") == [5]
    assert ids(db, "sqlmap") == [3]  # free text also covers the user agent
    assert ids(db, '"Failed" OR sqlmap') == [3]
    assert ids(db, "") == [0, 1, 2, 3, 4, 5]


def test_like_metacharacters_are_literal(populated: Session) -> None:
    db = populated
    assert ids(db, 'url:"/a_b%c"') == [3]
    assert ids(db, 'url:"/a_b%"') == []  # % is not a wildcard
    assert ids(db, "url:/a_b%c*") == [3]  # * is
    assert ids(db, '"%"') == [3]  # only the line that really contains a percent sign
    assert ids(db, '"_"') == [3]


@pytest.mark.parametrize(
    "q",
    [
        "user:' OR 1=1 --",
        'host:"x"); DROP TABLE events;--',
        "'; DELETE FROM events; --",
        "user:admin' UNION SELECT raw FROM events--",
        "\\",
        "%%%",
        "user:\\*",
    ],
)
def test_injection_attempts_are_just_text(populated: Session, q: str) -> None:
    db = populated
    with contextlib.suppress(SearchError):
        ids(db, q)
    assert db.exec(select(Event)).all().__len__() == 6  # nothing dropped or altered


@pytest.mark.parametrize(
    "q", ["password:x", "raw:x", "tags:1 OR id:3", "http_status:abc", "user:>=3", "src_port:>=x"]
)
def test_unknown_fields_and_bad_operators_are_rejected(populated: Session, q: str) -> None:
    with pytest.raises(SearchError):
        ids(populated, q)


# ------------------------------------------------------------------ API


@pytest.fixture
def seeded(client: TestClient) -> dict[str, str]:
    h = admin_login(client)
    upload(client, h, "attack.log", content=ATTACK_LOG.encode())
    wait(client)
    return h


RANGE = {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}


def test_hunt_endpoint(client: TestClient, seeded: dict[str, str]) -> None:
    r = client.get("/api/hunt", params={**RANGE, "q": "src_ip:203.0.113.* AND outcome:failure"})
    body = r.json()
    assert r.status_code == 200
    assert body["total"] == 12
    assert len(body["items"]) == 12
    assert body["items"][0]["timestamp"] >= body["items"][-1]["timestamp"]  # newest first
    page = client.get(
        "/api/hunt", params={**RANGE, "q": "host:web01", "limit": 5, "offset": 5}
    ).json()
    assert len(page["items"]) == 5
    assert page["total"] == 16

    narrow = client.get(
        "/api/hunt", params={"start": "2020-01-01T00:00:00Z", "end": "2020-01-02T00:00:00Z"}
    ).json()
    assert narrow["total"] == 0


def test_hunt_validation(client: TestClient, seeded: dict[str, str]) -> None:
    r = client.get("/api/hunt", params={**RANGE, "q": "nosuchfield:x"})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "invalid_query"
    assert "unknown field" in err["message"]
    assert "src_ip" in err["details"]["fields"]
    r = client.get("/api/hunt", params={"start": RANGE["end"], "end": RANGE["start"]})
    assert r.status_code == 422
    r = client.get(
        "/api/hunt", params={"start": "2000-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}
    )
    assert r.status_code == 422  # > 1 year


def test_histogram(client: TestClient, seeded: dict[str, str]) -> None:
    p = {"start": "2026-10-20T00:00:00Z", "end": "2026-10-21T00:00:00Z"}
    h = client.get("/api/hunt/histogram", params=p).json()
    assert h["bucket_seconds"] == 1800
    assert h["total"] == 17
    assert sum(b["count"] for b in h["buckets"]) == 17
    assert sum(b["failures"] for b in h["buckets"]) == 12
    filtered = client.get("/api/hunt/histogram", params={**p, "q": "host:db01"}).json()
    assert filtered["total"] == 1


def test_saved_searches_are_private(
    client: TestClient, seeded: dict[str, str], analyst: User
) -> None:
    h = seeded
    r = client.post(
        "/api/searches",
        json={"name": "Brute force", "query": "outcome:failure", "time_range": "24h"},
        headers=h,
    )
    assert r.status_code == 201
    sid = r.json()["id"]
    assert (
        client.post(
            "/api/searches", json={"name": "bad", "query": "((", "time_range": "24h"}, headers=h
        ).status_code
        == 422
    )
    assert [s["name"] for s in client.get("/api/searches").json()] == ["Brute force"]

    csrf = login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    assert client.get("/api/searches").json() == []
    assert client.delete(f"/api/searches/{sid}", headers={"X-CSRF-Token": csrf}).status_code == 404


def test_entity_page(client: TestClient, seeded: dict[str, str]) -> None:
    r = client.get("/api/entities/detail", params={"type": "ip", "value": "203.0.113.50"})
    d = r.json()
    assert r.status_code == 200
    assert d["entity"]["event_count"] == 13
    assert d["actions"]["ssh_login"] == 13
    assert {a["rule_id"] for a in d["alerts"]} >= {"sig-auth-brute-force"}
    assert d["incident_ids"]
    assert len(d["events"]) == 13

    hosts = {n["value"] for n in d["nodes"] if n["type"] == "host"}
    assert "web01" in hosts
    center = next(n for n in d["nodes"] if n["hop"] == 0)
    assert center["value"] == "203.0.113.50"
    ids_ = {n["id"] for n in d["nodes"]}
    assert all(e["source"] in ids_ and e["target"] in ids_ for e in d["edges"])
    assert any(n["hop"] == 2 for n in d["nodes"])  # web01 → its users

    host = client.get("/api/entities/detail", params={"type": "host", "value": "web01"}).json()
    assert host["entity"]["first_seen"] <= host["entity"]["last_seen"]
    dom = client.get("/api/entities/detail", params={"type": "user", "value": "svc-backup"}).json()
    assert dom["entity"]["value"] == "svc-backup"

    assert (
        client.get("/api/entities/detail", params={"type": "host", "value": "nope"}).status_code
        == 404
    )
    found = client.get("/api/entities", params={"q": "web"}).json()
    assert found[0]["value"] == "web01"
    assert client.get("/api/entities", params={"q": "%"}).json() == []
