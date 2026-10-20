"""Windows Security and Sysmon events.

One mapper (`map_event`) turns (provider, event id, computer, time, named fields) into a
NormalizedEvent. Every input shape funnels into it:

- EVTX files (python-evtx → record XML, parsed with defusedxml)
- evtx_dump JSON ({"Event": {"System": …, "EventData": …}})
- PowerShell `Get-WinEvent | ConvertTo-Json` (positional Properties, see TEMPLATES)
- Wazuh alerts carrying data.win (see parsers.wazuh)

Unsupported event IDs are still kept as events (action "windows_event") with their
fields in extra["event_data"], so nothing is lost.
"""

from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET

from app.ingest.normalise import basename, clean_int, clean_port, clean_str, finalise
from app.ingest.readers import JsonRecord
from app.ingest.timeparse import parse_any, parse_iso_assume_utc
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, ParseResult, Unparsed
from app.storage.models import Outcome

SYSMON_PROVIDER = "microsoft-windows-sysmon"
SECURITY_PROVIDERS = {"microsoft-windows-security-auditing", "microsoft-windows-eventlog"}
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins"}
LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network_cleartext",
    "9": "new_credentials",
    "10": "remote_interactive",
    "11": "cached_interactive",
}

# Positional field order of each event's template, for PowerShell's Properties array,
# which carries values without names. Matches current Windows 10/11 / Server 2016+
# templates and Sysmon schema 4.x; records with fewer values than expected are rejected.
TEMPLATES: dict[tuple[str, int], list[str]] = {
    ("security", 4624): [
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "LogonGuid",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
    ],
    ("security", 4625): [
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "Status",
        "FailureReason",
        "SubStatus",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
    ],
    ("security", 4672): [
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "PrivilegeList",
    ],
    ("security", 4688): [
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "NewProcessId",
        "NewProcessName",
        "TokenElevationType",
        "ProcessId",
        "CommandLine",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
        "ParentProcessName",
        "MandatoryLabel",
    ],
    ("security", 4720): [
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "PrivilegeList",
        "SamAccountName",
    ],
    ("security", 4728): [
        "MemberName",
        "MemberSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "PrivilegeList",
    ],
    ("security", 4732): [
        "MemberName",
        "MemberSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "PrivilegeList",
    ],
    ("security", 1102): [
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
    ],
    ("sysmon", 1): [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "FileVersion",
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonGuid",
        "LogonId",
        "TerminalSessionId",
        "IntegrityLevel",
        "Hashes",
        "ParentProcessGuid",
        "ParentProcessId",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser",
    ],
    ("sysmon", 3): [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "User",
        "Protocol",
        "Initiated",
        "SourceIsIpv6",
        "SourceIp",
        "SourceHostname",
        "SourcePort",
        "SourcePortName",
        "DestinationIsIpv6",
        "DestinationIp",
        "DestinationHostname",
        "DestinationPort",
        "DestinationPortName",
    ],
    ("sysmon", 11): [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "User",
    ],
    ("sysmon", 22): [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "QueryName",
        "QueryStatus",
        "QueryResults",
        "Image",
        "User",
    ],
}

# Template minimums: trailing fields added in newer OS builds may be absent.
_MIN_FIELDS = {("sysmon", 1): 21, ("security", 4688): 9}


def family(provider: str) -> str:
    return "sysmon" if provider.lower() == SYSMON_PROVIDER else "security"


def _s(d: Mapping[str, Any], k: str) -> str | None:
    return clean_str(d.get(k))


def _cn(member_name: str | None) -> str | None:
    """Extract the account from an LDAP DN like 'CN=bob,CN=Users,DC=corp'."""
    if member_name and member_name.upper().startswith("CN="):
        return member_name[3:].split(",", 1)[0] or None
    return member_name


def _is_machine_or_system(user: str | None) -> bool:
    if not user:
        return True
    u = user.lower()
    return u.endswith("$") or u in {"system", "local service", "network service", "anonymous logon"}


def map_event(
    provider: str,
    event_id: int,
    computer: str | None,
    ts: datetime,
    data: Mapping[str, Any],
    raw: str,
    *,
    channel: str | None = None,
) -> NormalizedEvent:
    fam = family(provider)
    source = "sysmon" if fam == "sysmon" else "windows_security"
    ev = NormalizedEvent(
        timestamp=ts, source_type=source, raw=raw, host=computer, event_code=str(event_id)
    )
    ev.extra["provider"] = provider
    if channel:
        ev.extra["channel"] = channel

    def domain_user(user_key: str, domain_key: str) -> str | None:
        u, d = _s(data, user_key), _s(data, domain_key)
        if u and d:
            return f"{d}\\{u}"
        return u

    key = (fam, event_id)
    if key == ("security", 4624) or key == ("security", 4625):
        ev.action = "logon"
        ev.outcome = Outcome.success if event_id == 4624 else Outcome.failure
        ev.user = domain_user("TargetUserName", "TargetDomainName")
        ev.src_ip = _s(data, "IpAddress")
        ev.src_port = clean_port(data.get("IpPort"))
        ev.process_name = basename(data.get("ProcessName"))
        lt = _s(data, "LogonType")
        ev.extra.update(
            {
                k: v
                for k, v in {
                    "logon_type": clean_int(lt),
                    "logon_type_name": LOGON_TYPES.get(lt or ""),
                    "logon_process": _s(data, "LogonProcessName"),
                    "auth_package": _s(data, "AuthenticationPackageName"),
                    "workstation": _s(data, "WorkstationName"),
                    "status": _s(data, "Status"),
                    "sub_status": _s(data, "SubStatus"),
                    "failure_reason": _s(data, "FailureReason"),
                    "subject_user": _s(data, "SubjectUserName"),
                }.items()
                if v is not None
            }
        )
        if lt == "10":
            ev.tags.append("rdp")
    elif key == ("security", 4672):
        ev.action, ev.outcome = "special_privileges_assigned", Outcome.success
        ev.user = domain_user("SubjectUserName", "SubjectDomainName")
        privs = [p.strip() for p in (_s(data, "PrivilegeList") or "").split() if p.strip()]
        ev.extra["privileges"] = privs
        ev.tags.append("privileged")
        if _is_machine_or_system(_s(data, "SubjectUserName")):
            ev.tags.append("system_account")
    elif key == ("security", 4688):
        ev.action, ev.outcome = "process_created", Outcome.success
        ev.user = domain_user("SubjectUserName", "SubjectDomainName")
        ev.process_name = basename(data.get("NewProcessName"))
        ev.process_cmdline = _s(data, "CommandLine")
        ev.parent_process = basename(data.get("ParentProcessName"))
        ev.extra.update(
            image=_s(data, "NewProcessName"),
            parent_image=_s(data, "ParentProcessName"),
            token_elevation=_s(data, "TokenElevationType"),
        )
    elif key == ("security", 4720):
        ev.action, ev.outcome = "user_created", Outcome.success
        ev.user = domain_user("TargetUserName", "TargetDomainName")
        ev.extra.update(subject_user=_s(data, "SubjectUserName"), target_sid=_s(data, "TargetSid"))
    elif key in (("security", 4728), ("security", 4732)):
        ev.action, ev.outcome = "group_member_added", Outcome.success
        ev.user = _cn(_s(data, "MemberName"))
        group = _s(data, "TargetUserName")
        ev.extra.update(
            group=group,
            group_scope="global" if event_id == 4728 else "local",
            member_sid=_s(data, "MemberSid"),
            subject_user=_s(data, "SubjectUserName"),
        )
        if group and group.lower() in ADMIN_GROUPS:
            ev.tags.append("privileged_group")
    elif key == ("security", 1102):
        ev.action, ev.outcome = "log_cleared", Outcome.success
        ev.user = domain_user("SubjectUserName", "SubjectDomainName")
        ev.extra["log"] = "Security"
    elif key == ("sysmon", 1):
        ev.action, ev.outcome = "process_created", Outcome.success
        ev.user = _s(data, "User")
        ev.process_name = basename(data.get("Image"))
        ev.process_cmdline = _s(data, "CommandLine")
        ev.parent_process = basename(data.get("ParentImage"))
        ev.extra.update(
            {
                k: v
                for k, v in {
                    "image": _s(data, "Image"),
                    "parent_image": _s(data, "ParentImage"),
                    "parent_cmdline": _s(data, "ParentCommandLine"),
                    "original_file_name": _s(data, "OriginalFileName"),
                    "integrity_level": _s(data, "IntegrityLevel"),
                    "hashes": _s(data, "Hashes"),
                    "process_id": clean_int(data.get("ProcessId")),
                    "cwd": _s(data, "CurrentDirectory"),
                }.items()
                if v is not None
            }
        )
    elif key == ("sysmon", 3):
        ev.action, ev.outcome = "network_connection", Outcome.success
        ev.user = _s(data, "User")
        ev.process_name = basename(data.get("Image"))
        ev.src_ip, ev.dst_ip = _s(data, "SourceIp"), _s(data, "DestinationIp")
        ev.src_port = clean_port(data.get("SourcePort"))
        ev.dst_port = clean_port(data.get("DestinationPort"))
        ev.extra.update(
            {
                k: v
                for k, v in {
                    "image": _s(data, "Image"),
                    "protocol": _s(data, "Protocol"),
                    "initiated": _s(data, "Initiated"),
                    "dst_hostname": _s(data, "DestinationHostname"),
                }.items()
                if v is not None
            }
        )
    elif key == ("sysmon", 11):
        ev.action, ev.outcome = "file_created", Outcome.success
        ev.user = _s(data, "User")
        ev.process_name = basename(data.get("Image"))
        ev.extra.update(image=_s(data, "Image"), target_filename=_s(data, "TargetFilename"))
    elif key == ("sysmon", 22):
        ev.action = "dns_query"
        status = _s(data, "QueryStatus")
        ev.outcome = Outcome.success if status in (None, "0") else Outcome.failure
        ev.user = _s(data, "User")
        ev.process_name = basename(data.get("Image"))
        ev.dns_query = _s(data, "QueryName")
        ev.extra.update(
            {
                k: v
                for k, v in {
                    "image": _s(data, "Image"),
                    "query_status": status,
                    "query_results": _s(data, "QueryResults"),
                }.items()
                if v is not None
            }
        )
    else:
        ev.action = "windows_event"
        ev.extra["event_data"] = {k: clean_str(v, 2048) for k, v in list(data.items())[:64]}

    return finalise(ev)


# --------------------------------------------------------------------------- XML (EVTX)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _event_fields(root: Element) -> dict[str, str]:
    """EventData/Data[@Name] pairs, or the children of UserData's single element."""
    fields: dict[str, str] = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed.findall(f"{NS}Data")):
            fields[d.get("Name") or f"Data{i}"] = (d.text or "").strip()
    ud = root.find(f"{NS}UserData")
    if ud is not None:
        for inner in list(ud):
            for child in list(inner):
                fields[_local(child.tag)] = (child.text or "").strip()
    return fields


def map_xml(xml: str) -> NormalizedEvent:
    root = SafeET.fromstring(xml)
    sys = root.find(f"{NS}System")
    if sys is None:
        raise ValueError("record has no System element")
    prov = sys.find(f"{NS}Provider")
    provider = prov.get("Name", "") if prov is not None else ""
    eid_el = sys.find(f"{NS}EventID")
    if eid_el is None or not (eid_el.text or "").strip().isdigit():
        raise ValueError("record has no numeric EventID")
    tc = sys.find(f"{NS}TimeCreated")
    st = tc.get("SystemTime") if tc is not None else None
    if not st:
        raise ValueError("record has no TimeCreated/@SystemTime")
    computer_el = sys.find(f"{NS}Computer")
    channel_el = sys.find(f"{NS}Channel")
    return map_event(
        provider,
        int((eid_el.text or "0").strip()),
        computer_el.text if computer_el is not None else None,
        parse_iso_assume_utc(st),
        _event_fields(root),
        xml,
        channel=channel_el.text if channel_el is not None else None,
    )


def parse_evtx(path: Path) -> Iterator[ParseResult]:
    from Evtx.Evtx import Evtx  # imported lazily: heavy, only needed for EVTX uploads

    with Evtx(str(path)) as log:
        for n, record in enumerate(log.records(), 1):
            try:
                xml = record.xml()
            except Exception as e:  # corrupt record: keep going, report it
                yield Unparsed(raw=f"<record {n}>", reason=f"corrupt EVTX record: {e}", line_no=n)
                continue
            try:
                yield Parsed(map_xml(xml), n)
            except Exception as e:
                yield Unparsed(raw=xml, reason=f"unmappable record: {e}", line_no=n)


# --------------------------------------------------------------------------- JSON exports


def _attr(v: Any, name: str) -> Any:
    """evtx_dump puts XML attributes under '#attributes' and text under '#text'."""
    if isinstance(v, dict):
        attrs = v.get("#attributes")
        if isinstance(attrs, dict) and name in attrs:
            return attrs[name]
        return v.get(name, v.get("#text"))
    return v


def _flatten_user_data(ud: Any) -> dict[str, Any]:
    if not isinstance(ud, dict):
        return {}
    for inner in ud.values():
        if isinstance(inner, dict):
            return {k: v for k, v in inner.items() if not k.startswith("#")}
    return {}


def map_evtx_dump(obj: dict[str, Any], raw: str) -> NormalizedEvent:
    ev_obj = obj["Event"]
    sys = ev_obj.get("System") or {}
    provider = str(_attr(sys.get("Provider"), "Name") or "")
    eid = clean_int(_attr(sys.get("EventID"), "#text"))
    if eid is None:
        raise ValueError("no numeric EventID")
    st = _attr(sys.get("TimeCreated"), "SystemTime")
    if not st:
        raise ValueError("no TimeCreated.SystemTime")
    data: dict[str, Any] = {}
    ed = ev_obj.get("EventData")
    if isinstance(ed, dict):
        data.update({k: v for k, v in ed.items() if not k.startswith("#")})
    data.update(_flatten_user_data(ev_obj.get("UserData")))
    return map_event(
        provider,
        eid,
        sys.get("Computer"),
        parse_iso_assume_utc(str(st)),
        data,
        raw,
        channel=sys.get("Channel"),
    )


def map_powershell(obj: dict[str, Any], raw: str) -> NormalizedEvent:
    provider = str(obj.get("ProviderName") or "")
    eid = clean_int(obj.get("Id"))
    if eid is None:
        raise ValueError("no numeric Id")
    if "TimeCreated" not in obj:
        raise ValueError("no TimeCreated")
    ts = parse_any(obj["TimeCreated"])
    props = obj.get("Properties") or []
    values = [p.get("Value") if isinstance(p, dict) else p for p in props]
    template = TEMPLATES.get((family(provider), eid))
    if template is None:
        data: dict[str, Any] = {f"Data{i}": v for i, v in enumerate(values)}
    else:
        minimum = _MIN_FIELDS.get((family(provider), eid), len(template))
        if len(values) < minimum:
            raise ValueError(
                f"event {eid} has {len(values)} properties, expected at least {minimum}"
            )
        data = dict(zip(template, values, strict=False))
    return map_event(
        provider, eid, obj.get("MachineName"), ts, data, raw, channel=obj.get("LogName")
    )


def parse_json_records(records: Iterable[JsonRecord], ctx: ParseContext) -> Iterator[ParseResult]:
    del ctx  # Windows records carry their own UTC time
    for rec in records:
        if rec.error:
            yield Unparsed(raw=rec.raw, reason=rec.error, line_no=rec.line_no)
            continue
        obj = rec.obj
        try:
            if isinstance(obj, dict) and isinstance(obj.get("Event"), dict):
                yield Parsed(map_evtx_dump(obj, rec.raw), rec.line_no)
            elif isinstance(obj, dict) and "Id" in obj:
                yield Parsed(map_powershell(obj, rec.raw), rec.line_no)
            else:
                yield Unparsed(rec.raw, "not a Windows event export record", rec.line_no)
        except (ValueError, KeyError, TypeError) as e:
            yield Unparsed(rec.raw, f"unmappable Windows record: {e}", rec.line_no)
