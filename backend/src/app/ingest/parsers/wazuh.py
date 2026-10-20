"""Wazuh alerts.json (one alert per line).

Windows/Sysmon alerts (data.win) go through the Windows mapper, and syslog-based alerts
re-use the Linux auth classifiers on full_log. Both keep their underlying source_type
(windows_security, sysmon, linux_auth) so SIGNAL's own rules fire on lab data unchanged;
they are tagged "wazuh" with the Wazuh rule in extra["wazuh"]. Anything else is stored
as source_type "wazuh".
"""

from collections.abc import Iterable, Iterator
from typing import Any

from app.ingest.normalise import clean_int, clean_port, clean_str, finalise
from app.ingest.parsers import linux_auth, windows
from app.ingest.readers import JsonRecord
from app.ingest.timeparse import parse_iso, parse_iso_assume_utc
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, ParseResult, Unparsed


def level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _win_fields(d: dict[str, Any]) -> dict[str, Any]:
    """Wazuh lower-cases the first letter of Windows field names (targetUserName) and
    double-escapes backslashes in values (C:\\\\Windows). Undo both."""
    return {
        (k[:1].upper() + k[1:]): (v.replace("\\\\", "\\") if isinstance(v, str) else v)
        for k, v in d.items()
    }


def _metadata(obj: dict[str, Any]) -> dict[str, Any]:
    rule = obj.get("rule") or {}
    agent = obj.get("agent") or {}
    level = clean_int(rule.get("level")) or 0
    mitre = rule.get("mitre") or {}
    return {
        "rule_id": clean_str(rule.get("id")),
        "level": level,
        "severity": level_to_severity(level),
        "description": clean_str(rule.get("description"), 512),
        "groups": list(rule.get("groups") or [])[:20],
        "mitre_ids": list(mitre.get("id") or [])[:20],
        "agent_id": clean_str(agent.get("id")),
        "agent_name": clean_str(agent.get("name")),
        "agent_ip": clean_str(agent.get("ip")),
        "decoder": clean_str((obj.get("decoder") or {}).get("name")),
        "alert_id": clean_str(obj.get("id")),
    }


def map_alert(obj: dict[str, Any], raw: str) -> NormalizedEvent:
    if "timestamp" not in obj:
        raise ValueError("alert has no timestamp")
    ts = parse_iso(str(obj["timestamp"]))
    meta = _metadata(obj)
    data = obj.get("data") or {}
    agent_name = meta["agent_name"]

    win = data.get("win") if isinstance(data, dict) else None
    if isinstance(win, dict) and isinstance(win.get("system"), dict):
        sysd = win["system"]
        eid = clean_int(sysd.get("eventID"))
        if eid is None:
            raise ValueError("data.win.system.eventID missing")
        st = sysd.get("systemTime")
        ev = windows.map_event(
            str(sysd.get("providerName") or ""),
            eid,
            sysd.get("computer") or agent_name,
            parse_iso_assume_utc(str(st)) if st else ts,
            _win_fields(win.get("eventdata") or {}),
            raw,
            channel=sysd.get("channel"),
        )
    else:
        full_log = clean_str(obj.get("full_log"), 16384)
        m = None
        if full_log:
            m = linux_auth.CLASSIC.match(full_log) or linux_auth.RFC3339.match(full_log)
        if m:
            ev = NormalizedEvent(
                timestamp=ts,
                source_type=linux_auth.SOURCE,
                raw=raw,
                host=m["host"],
                process_name=m["prog"],
            )
            linux_auth.classify(ev, m["prog"], m["msg"])
        else:
            ev = NormalizedEvent(timestamp=ts, source_type="wazuh", raw=raw, host=agent_name)
            ev.action = "wazuh_alert"
            if isinstance(data, dict):
                ev.src_ip = clean_str(data.get("srcip"))
                ev.dst_ip = clean_str(data.get("dstip"))
                ev.src_port = clean_port(data.get("srcport"))
                ev.dst_port = clean_port(data.get("dstport"))
                ev.user = clean_str(data.get("dstuser") or data.get("srcuser"))
                ev.url = clean_str(data.get("url"), 8192)
                ev.http_status = clean_int(data.get("id")) if data.get("protocol") else None
        # Fallback fields Wazuh decoders put at top level.
        if ev.src_ip is None and isinstance(data, dict):
            ev.src_ip = clean_str(data.get("srcip"))
        ev.event_code = meta["rule_id"]

    ev.tags.append("wazuh")
    ev.extra["wazuh"] = meta
    return finalise(ev)


def parse_json_records(records: Iterable[JsonRecord], ctx: ParseContext) -> Iterator[ParseResult]:
    del ctx
    for rec in records:
        if rec.error:
            yield Unparsed(rec.raw, rec.error, rec.line_no)
            continue
        if not isinstance(rec.obj, dict) or not isinstance(rec.obj.get("rule"), dict):
            yield Unparsed(rec.raw, "not a Wazuh alert (no rule object)", rec.line_no)
            continue
        try:
            yield Parsed(map_alert(rec.obj, rec.raw), rec.line_no)
        except (ValueError, TypeError, KeyError) as e:
            yield Unparsed(rec.raw, f"unmappable Wazuh alert: {e}", rec.line_no)
