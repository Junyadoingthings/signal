"""Incident report: one data structure, rendered as Markdown or print-ready HTML.

Everything that came from logs (hostnames, command lines, URLs...) is attacker-
controlled. In Markdown it only ever appears inside code spans with backticks and
newlines removed; in HTML every value goes through html.escape.
"""

import html
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app import attack
from app.api.alerts import history_for, notes_for
from app.correlation.correlator import storyline
from app.ingest.entities import registered_domain
from app.storage.models import Alert, AlertEvent, Event, Incident, Rule, utcnow

CAP = 25


def _ts(d: datetime | None) -> str:
    return d.strftime("%Y-%m-%d %H:%M:%SZ") if d else "—"


def _dur(seconds: float) -> str:
    s = int(seconds)
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    return f"{s / 3600:.1f}h"


@dataclass
class Report:
    incident: Incident
    generated_at: datetime
    steps: list[dict[str, Any]]
    alerts: list[Alert]
    rule_titles: dict[str, str]
    techniques: list[tuple[str, str, str]]  # id, name, url
    tactics: list[str]
    iocs: dict[str, list[str]]
    notes: list[tuple[str, datetime, str]]
    history: list[tuple[datetime, str, str]]
    assignee: str | None
    event_total: int
    fp_notes: dict[str, list[str]] = field(default_factory=dict)


def build(db: Session, incident: Incident) -> Report:
    alerts = list(
        db.exec(
            select(Alert)
            .where(Alert.incident_id == incident.id)
            .order_by(col(Alert.first_event_at), col(Alert.id))
        ).all()
    )
    rules = {
        r.id: r for r in db.exec(select(Rule).where(col(Rule.id).in_({a.rule_id for a in alerts})))
    }
    steps = storyline(alerts, rules)

    tech: dict[str, tuple[str, str]] = {}
    for r in rules.values():
        for tid in r.techniques:
            t = attack.technique(tid)
            tech[tid] = (t.name if t else "unknown", t.url if t else "")
    names = {t.shortname: t.name for t in attack.tactics()}

    ids = select(AlertEvent.event_id).where(col(AlertEvent.alert_id).in_([a.id for a in alerts]))
    events = db.exec(select(Event).where(col(Event.id).in_(ids)).limit(5000)).all()
    c: dict[str, Counter[str]] = {
        k: Counter()
        for k in (
            "IP addresses",
            "Domains",
            "URLs",
            "Accounts",
            "Hosts",
            "Processes / command lines",
            "File hashes",
            "Files",
        )
    }
    for e in events:
        for ip in (e.src_ip, e.dst_ip):
            if ip:
                c["IP addresses"][ip] += 1
        if e.dns_query:
            c["Domains"][registered_domain(e.dns_query)] += 1
        if e.url and e.source_type == "web_access":
            c["URLs"][e.url[:200]] += 1
        if e.user:
            c["Accounts"][e.user] += 1
        if e.host:
            c["Hosts"][e.host] += 1
        if e.process_cmdline:
            c["Processes / command lines"][e.process_cmdline[:300]] += 1
        if (h := e.extra.get("hashes")) and isinstance(h, str):
            c["File hashes"][h[:200]] += 1
        if (f := e.extra.get("target_filename")) and isinstance(f, str):
            c["Files"][f[:200]] += 1
    iocs = {k: [v for v, _ in cnt.most_common(CAP)] for k, cnt in c.items() if cnt}

    notes = [
        (n.author_name, n.created_at, n.markdown)
        for n in notes_for(db, "incident", incident.id or 0)
    ]
    hist = [
        (h.ts, h.actor or "system", h.action or "")
        for h in history_for(db, "incident", incident.id or 0)
        if h.kind == "audit"
    ]
    for a in alerts:  # alert-level triage is part of the incident's story
        for h in history_for(db, "alert", a.id or 0):
            if h.kind == "audit":
                change = ", ".join(
                    f"{k.replace('_id', '')} {str((h.before or {}).get(k) or 'none').replace('_', ' ')} → "
                    f"{str(v).replace('_', ' ')}"
                    for k, v in (h.after or {}).items()
                    if (h.before or {}).get(k) != v
                )
                hist.append((h.ts, h.actor or "system", f"alert #{a.id}: {change or h.action}"))
            elif h.note:
                hist.append((h.ts, h.actor or "system", f"alert #{a.id}: note added"))
                notes.append((f"{h.actor} (alert #{a.id})", h.ts, h.note.markdown))
    hist.sort(key=lambda x: x[0])
    notes.sort(key=lambda x: x[1])
    return Report(
        incident=incident,
        generated_at=utcnow(),
        steps=steps,
        alerts=alerts,
        rule_titles={k: r.title for k, r in rules.items()},
        techniques=[(k, *v) for k, v in sorted(tech.items())],
        tactics=[names.get(t, t) for t in incident.tactics],
        iocs=iocs,
        notes=notes,
        history=hist,
        assignee=None,
        event_total=len(events),
    )


# ------------------------------------------------------------------ markdown


def _code(v: object) -> str:
    s = str(v).replace("`", "'").replace("\r", " ").replace("\n", " ").replace("|", "¦")
    return f"`{s}`"


def _plain(v: object) -> str:
    """Untrusted text outside code spans: neutralise Markdown/HTML metacharacters."""
    s = str(v).replace("\r", " ").replace("\n", " ")
    for ch in "\\`*_{}[]<>()#+!|":
        s = s.replace(ch, "\\" + ch)
    return s


def to_markdown(r: Report) -> str:
    i = r.incident
    out = [
        f"# Incident #{i.id}: {_plain(i.title)}",
        "",
        "| | |",
        "|---|---|",
        f"| **Severity** | {i.severity.upper()} (score {i.score}/100) |",
        f"| **Status** | {i.status}{f' · {i.verdict.replace(chr(95), chr(32))}' if i.verdict else ''} |",
        f"| **Window** | {_ts(i.first_event_at)} → {_ts(i.last_event_at)} |",
        f"| **Alerts** | {i.alert_count} ({r.event_total} supporting events) |",
        f"| **Report generated** | {_ts(r.generated_at)} |",
        "",
        "## Summary",
        "",
    ]
    ents = i.entities
    out.append(
        f"{i.alert_count} related alerts involving "
        + ", ".join(
            f"{len(v)} {k.replace('_', ' ')}{'s' if len(v) != 1 else ''}"
            for k, v in ents.items()
            if v
        )
        + f" were grouped into one {i.severity} incident. Observed tactics, in kill-chain order: "
        + (" → ".join(r.tactics) or "none")
        + "."
    )
    out += [
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Tactic | Alert | Severity |",
        "|---|---|---|---|",
    ]
    names = {t.shortname: t.name for t in attack.tactics()}
    for s in r.steps:
        out.append(
            f"| {_ts(s['time'])} | {_plain(names.get(s['tactic'] or '', s['tactic'] or '—'))} "
            f"| {_plain(s['title'])} | {s['severity']} |"
        )
    out += ["", "## MITRE ATT&CK techniques", ""]
    out += [
        f"- {_code(tid)} {_plain(name)}" + (f" — <{url}>" if url.startswith("https://") else "")
        for tid, name, url in r.techniques
    ] or ["- none mapped"]
    out += ["", "## Indicators of compromise", ""]
    for kind, vals in r.iocs.items():
        out += [f"**{kind}**", ""] + [f"- {_code(v)}" for v in vals] + [""]
    if not r.iocs:
        out += ["None extracted.", ""]
    out += [
        "## Alerts",
        "",
        "| # | Rule | Severity | Entity | Events | Status |",
        "|---|---|---|---|---|---|",
    ]
    for a in r.alerts:
        ent = " · ".join(x for x in (a.host, a.user, a.src_ip) if x)
        out.append(
            f"| {a.id} | {_plain(r.rule_titles.get(a.rule_id, a.rule_id))} | {a.severity} "
            f"| {_code(ent) if ent else '—'} | {a.event_count} | {a.status}{f' · {a.verdict}' if a.verdict else ''} |"
        )
    out += ["", "## Analyst notes", ""]
    if r.notes:
        for author, when, md in r.notes:
            out += (
                [f"**{_plain(author)}** · {_ts(when)}", ""]
                + [f"> {line}" for line in md.splitlines() or [""]]
                + [""]
            )
    else:
        out += ["No notes recorded.", ""]
    out += ["## Activity log", ""] + [
        f"- {_ts(t)} · {_plain(who)} · {_plain(act)}" for t, who, act in r.history
    ]
    out += [
        "",
        "---",
        "_Generated by SIGNAL. ATT&CK® is a registered trademark of The MITRE Corporation._",
        "",
    ]
    return "\n".join(out)


# ------------------------------------------------------------------ html

CSS = """
@page { size: A4; margin: 16mm; }
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 13px/1.55 ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; color: #1c1a17; margin: 0 auto; max-width: 860px; padding: 32px 24px; background: #fff; }
h1 { font-size: 24px; letter-spacing: -0.02em; margin: 0 0 4px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #625d55; border-bottom: 1px solid #e3dfd6; padding-bottom: 4px; margin: 28px 0 10px; }
.meta { color: #625d55; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; background: #ece9e2; }
.badge.critical { background: #c9300a; color: #fff; } .badge.high { background: #d9600f; color: #fff; }
.badge.medium { background: #a67c12; color: #fff; } .badge.low { background: #857e70; color: #fff; }
.score { float: right; text-align: right; } .score b { display: block; font-size: 44px; line-height: 1; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; margin: 6px 0; } th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid #e3dfd6; vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #625d55; }
code, .mono { font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 12px; overflow-wrap: anywhere; }
ul { padding-left: 18px; margin: 4px 0; } .note { border-left: 3px solid #cfc9bd; padding: 4px 12px; margin: 8px 0; white-space: pre-wrap; }
.story { list-style: none; padding: 0; border-left: 2px solid #cfc9bd; margin-left: 6px; } .story li { padding: 0 0 10px 14px; position: relative; }
.story li::before { content: ''; position: absolute; left: -6px; top: 6px; width: 10px; height: 10px; background: #1c1a17; border-radius: 50%; }
footer { margin-top: 32px; color: #9b958b; font-size: 11px; } h2, tr, .note, .story li { break-inside: avoid; }
@media print { body { padding: 0; } a { color: inherit; text-decoration: none; } }
"""


def to_html(r: Report) -> str:
    e = html.escape
    i = r.incident
    names = {t.shortname: t.name for t in attack.tactics()}
    p: list[str] = [
        f"<!doctype html><html lang=en><head><meta charset=utf-8><title>Incident #{i.id} report</title>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body>",
        f"<div class=score><b>{i.score}</b><span class=meta>score / 100</span></div>",
        f"<p><span class='badge {e(str(i.severity))}'>{e(str(i.severity))}</span> "
        f"<span class=meta>Incident #{i.id} · {e(str(i.status))}"
        f"{' · ' + e(str(i.verdict).replace('_', ' ')) if i.verdict else ''}</span></p>",
        f"<h1>{e(i.title)}</h1>",
        f"<p class=meta>{_ts(i.first_event_at)} → {_ts(i.last_event_at)} · {i.alert_count} alerts · "
        f"{r.event_total} supporting events · generated {_ts(r.generated_at)}</p>",
        "<h2>Summary</h2>",
        f"<p>{i.alert_count} related alerts were grouped into one {e(str(i.severity))} incident. "
        f"Tactics in kill-chain order: <b>{e(' → '.join(r.tactics) or 'none')}</b>.</p>",
        "<table>"
        + "".join(
            f"<tr><th>{e(k.replace('_', ' '))}</th><td class=mono>{e(', '.join(v))}</td></tr>"
            for k, v in i.entities.items()
            if v
        )
        + "</table>",
        "<h2>Timeline</h2><ol class=story>",
    ]
    for s in r.steps:
        p.append(
            f"<li><span class=mono>{_ts(s['time'])}</span> · "
            f"<span class='badge {e(str(s['severity']))}'>{e(str(s['severity']))}</span> "
            f"<b>{e(s['title'])}</b><br><span class=meta>{e(names.get(s['tactic'] or '', s['tactic'] or ''))}"
            f" · {e(', '.join(s['techniques']))}</span></li>"
        )
    p.append("</ol><h2>MITRE ATT&amp;CK techniques</h2><ul>")
    p += [f"<li><code>{e(tid)}</code> {e(name)}</li>" for tid, name, _ in r.techniques] or [
        "<li>none mapped</li>"
    ]
    p.append("</ul><h2>Indicators of compromise</h2>")
    for kind, vals in r.iocs.items():
        p.append(
            f"<p><b>{e(kind)}</b></p><ul>"
            + "".join(f"<li><code>{e(v)}</code></li>" for v in vals)
            + "</ul>"
        )
    if not r.iocs:
        p.append("<p>None extracted.</p>")
    p.append(
        "<h2>Alerts</h2><table><tr><th>#</th><th>Rule</th><th>Severity</th><th>Entity</th><th>Events</th><th>Status</th></tr>"
    )
    for a in r.alerts:
        ent = " · ".join(x for x in (a.host, a.user, a.src_ip) if x) or "—"
        p.append(
            f"<tr><td>{a.id}</td><td>{e(r.rule_titles.get(a.rule_id, a.rule_id))}</td>"
            f"<td>{e(str(a.severity))}</td><td class=mono>{e(ent)}</td><td>{a.event_count}</td><td>{e(str(a.status))}{e(' · ' + str(a.verdict).replace('_', ' ')) if a.verdict else ''}</td></tr>"
        )
    p.append("</table><h2>Analyst notes</h2>")
    p += [
        f"<div class=note><span class=meta>{e(a)} · {_ts(w)}</span><br>{e(md)}</div>"
        for a, w, md in r.notes
    ] or ["<p>No notes recorded.</p>"]
    p.append(
        "<h2>Activity log</h2><ul>"
        + "".join(
            f"<li><span class=mono>{_ts(t)}</span> · {e(who)} · {e(act)}</li>"
            for t, who, act in r.history
        )
        + "</ul>"
    )
    p.append(
        "<footer>Generated by SIGNAL. ATT&amp;CK® is a registered trademark of The MITRE Corporation.</footer></body></html>"
    )
    return "".join(p)
