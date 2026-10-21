"""The planted attacks must come out of the real pipeline as the incidents documented in
docs/scenarios.md, and the false-positive bait must alert but stay out of the incidents."""

import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from tests.conftest import admin_login
from tests.test_ingest_api import upload, wait

_spec = importlib.util.spec_from_file_location(
    "seed_generate", Path(__file__).parents[2] / "tools" / "seed" / "generate.py"
)
assert _spec
assert _spec.loader
gen = importlib.util.module_from_spec(_spec)
sys.modules["seed_generate"] = gen
_spec.loader.exec_module(gen)


@pytest.fixture
def loaded(client: TestClient, tmp_path: Path) -> dict[str, list[dict]]:  # type: ignore[type-arg]
    day = gen.default_day()
    gen.generate(tmp_path, day)
    h = admin_login(client)
    client.put(
        "/api/ingest/settings", json={"syslog_timezone": "UTC", "syslog_year": day.year}, headers=h
    )
    for name, form in {
        "web01-auth.log": {},
        "db01-auth.log": {},
        "web01-access.log": {"host": "web01"},
        "windows-events.jsonl": {},
        "wazuh-alerts.json": {},
    }.items():
        b = upload(client, h, name, content=(tmp_path / name).read_bytes(), form=form)
        assert b["_status"] == 202, (name, b)
    wait(client)
    alerts = client.get("/api/alerts?limit=500&status=new").json()["items"]
    incidents = client.get("/api/incidents").json()["items"]
    return {"alerts": alerts, "incidents": incidents}


def rules_by_host(alerts: list[dict], host: str) -> set[str]:  # type: ignore[type-arg]
    return {a["rule_id"] for a in alerts if a["host"] == host}


def test_everything_parses(client: TestClient, loaded: dict) -> None:  # type: ignore[type-arg]
    batches = client.get("/api/ingest/batches").json()["items"]
    assert len(batches) == 5
    assert all(b["status"] == "done" for b in batches)
    assert sum(b["unparsed_count"] for b in batches) == 0
    assert sum(b["parsed_count"] for b in batches) > 1000


def test_three_attacks_become_three_incidents(loaded: dict) -> None:  # type: ignore[type-arg]
    incs = {tuple(i["entities"]["host"]): i for i in loaded["incidents"]}
    assert set(incs) == {("web01",), ("ws-04",), ("ws-02",)}

    s1 = incs[("web01",)]
    assert s1["severity"] == "critical"
    assert s1["tactics"][:2] == ["credential-access", "initial-access"]
    assert "203.0.113.50" in s1["entities"]["src_ip"]

    s2 = incs[("ws-04",)]
    assert s2["severity"] == "critical"
    assert {"execution", "command-and-control", "persistence", "defense-impairment"} <= set(
        s2["tactics"]
    )

    s3 = incs[("ws-02",)]
    assert s3["alert_count"] == 2
    assert s3["tactics"] == ["exfiltration"]


def test_scenario1_ssh_brute_force(loaded: dict) -> None:  # type: ignore[type-arg]
    assert rules_by_host(loaded["alerts"], "web01") >= {
        "sig-auth-brute-force",
        "sig-auth-password-spray",
        "sig-auth-success-after-brute-force",
        "sig-priv-off-hours",
        "sig-persist-new-account",
        "sig-persist-admin-group",
    }


def test_scenario2_phishing_chain(loaded: dict) -> None:  # type: ignore[type-arg]
    assert rules_by_host(loaded["alerts"], "ws-04") == {
        "sig-exec-office-child-shell",
        "sig-exec-encoded-powershell",
        "sig-c2-certutil-download",
        "sig-persist-new-account",
        "sig-persist-admin-group",
        "sig-def-log-cleared",
        "sig-wazuh-high-severity",  # the level-12 Wazuh alert for the same PowerShell event
    }


def test_scenario3_dns_exfiltration(loaded: dict) -> None:  # type: ignore[type-arg]
    assert rules_by_host(loaded["alerts"], "ws-02") == {
        "sig-exfil-dns-tunnel",
        "sig-exfil-dns-volume",
    }


def test_false_positive_bait_alerts_but_is_not_an_incident(loaded: dict) -> None:  # type: ignore[type-arg]
    in_incident = {a["id"] for a in loaded["alerts"] if a["incident_id"]}
    bait = {
        ("db01", "sig-priv-off-hours"): "nightly backup job",
        ("ws-03", "sig-persist-new-account"): "helpdesk creates a contractor",
        ("ws-05", "sig-c2-certutil-download"): "admin checks a CRL",
    }
    for (host, rule), why in bait.items():
        hits = [a for a in loaded["alerts"] if a["host"] == host and a["rule_id"] == rule]
        assert len(hits) == 1, f"{why}: expected one {rule} alert on {host}"
        assert hits[0]["id"] not in in_incident, why
    # ...and so does the web scanner, which is an alert on its own.
    web = [a for a in loaded["alerts"] if a["rule_id"] == "sig-web-attack-patterns"]
    assert web
    assert not {a["id"] for a in web} & in_incident


def test_normal_business_hours_activity_is_quiet(loaded: dict) -> None:  # type: ignore[type-arg]
    allowed = {
        "web01",
        "db01",
        "ws-02",
        "ws-03",
        "ws-04",
        "ws-05",
    }
    noisy = [a for a in loaded["alerts"] if a["host"] and a["host"] not in allowed]
    assert noisy == [], [(a["host"], a["rule_id"]) for a in noisy]
    # 0 alerts from the ~15 users' ordinary logons, processes, DNS and web traffic
    assert len(loaded["alerts"]) <= 26
