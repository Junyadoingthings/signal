"""Linux auth.log / secure (syslog). Classic BSD timestamps and RFC 3339 (newer Ubuntu).

Every structurally valid syslog line becomes an event. Lines we understand get a
specific `action`; the rest keep action=None but are still searchable. Only lines that
aren't syslog at all go to the unparsed bucket.

Convention: for account-management actions `user` is the account acted on, and the
actor (when logged) is extra["subject_user"].
"""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from app.ingest.normalise import finalise
from app.ingest.timeparse import parse_iso, resolve_syslog_year
from app.ingest.types import NormalizedEvent, ParseContext, Parsed, ParseResult, Unparsed
from app.storage.models import Outcome

SOURCE = "linux_auth"

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) "
    r"(?P<host>\S+) (?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)

# --- sshd
SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
PAM_AUTH_FAIL = re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")
# --- sudo
SUDO_CMD = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<fail>.*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ;(?: .*?;)? COMMAND=(?P<cmd>.*)$"
)
SUDO_NOT_ALLOWED = re.compile(r"^\s*(?P<user>\S+) : (?:user NOT in sudoers|command not allowed)")
# --- su
SU_OK = re.compile(
    r"^(?:Successful su for (?P<target>\S+) by (?P<user>\S+)"
    r"|\(to (?P<target2>\S+)\) (?P<user2>\S+) on)"
)
SU_FAIL = re.compile(
    r"^FAILED (?:SU|su) "
    r"(?:\(to (?P<target>\S+)\) (?P<user>\S+)|for (?P<target2>\S+) by (?P<user2>\S+))"
)
# --- account management
USERADD = re.compile(r"^new user: name=(?P<user>[^,\s]+)(?:, UID=(?P<uid>\d+))?")
GROUPADD = re.compile(r"^new group: name=(?P<group>[^,\s]+)")
USERDEL = re.compile(r"^delete user '(?P<user>[^']+)'")
USERMOD_ADD = re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
GPASSWD_ADD = re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")
PASSWD = re.compile(r"password (?:changed|updated successfully) for (?P<user>\S+)")
SESSION = re.compile(
    r"^pam_unix\((?P<svc>[^:]+):session\): session (?P<state>opened|closed) for user "
    r"(?P<user>[^\s(]+)"
)

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}


def _event(ts: datetime, host: str, prog: str, pid: str | None, line: str) -> NormalizedEvent:
    ev = NormalizedEvent(timestamp=ts, source_type=SOURCE, raw=line, host=host, process_name=prog)
    if pid:
        ev.extra["pid"] = int(pid)
    return ev


def classify(ev: NormalizedEvent, prog: str, msg: str) -> None:
    """Fill action/outcome/user/IPs from the syslog message body."""
    p = prog.lower()
    if p == "sshd":
        if m := SSH_FAILED.match(msg):
            ev.action, ev.outcome = "ssh_login", Outcome.failure
            ev.user, ev.src_ip, ev.src_port = m["user"] or None, m["ip"], int(m["port"])
            ev.extra["auth_method"] = m["method"]
            if m["invalid"]:
                ev.extra["invalid_user"] = True
        elif m := SSH_ACCEPTED.match(msg):
            ev.action, ev.outcome = "ssh_login", Outcome.success
            ev.user, ev.src_ip, ev.src_port = m["user"], m["ip"], int(m["port"])
            ev.extra["auth_method"] = m["method"]
        elif m := SSH_INVALID.match(msg):
            # Logged alongside "Failed password for invalid user", so it is a separate
            # action and not counted as a second failed login.
            ev.action, ev.outcome = "ssh_invalid_user", Outcome.failure
            ev.user, ev.src_ip = m["user"] or None, m["ip"]
            if m["port"]:
                ev.src_port = int(m["port"])
    if ev.action is None and (m := PAM_AUTH_FAIL.search(msg)):
        ev.action, ev.outcome = "pam_auth_failure", Outcome.failure
        ev.src_ip = m["ip"] or None
        ev.user = m["user"]
    if p == "sudo" and ev.action is None:
        if m := SUDO_CMD.match(msg):
            ev.action = "sudo_command"
            ev.user = m["user"]
            ev.outcome = Outcome.failure if m["fail"] else Outcome.success
            ev.process_cmdline = m["cmd"].strip()
            ev.extra.update(target_user=m["target"], tty=m["tty"], cwd=m["pwd"])
            if m["fail"]:
                ev.extra["failure_reason"] = m["fail"].strip()
        elif m := SUDO_NOT_ALLOWED.match(msg):
            ev.action, ev.outcome, ev.user = "sudo_command", Outcome.failure, m["user"]
    if p == "su" and ev.action is None:
        if m := SU_FAIL.match(msg):
            ev.action, ev.outcome = "su", Outcome.failure
            ev.user = m["user"] or m["user2"]
            ev.extra["target_user"] = m["target"] or m["target2"]
        elif m := SU_OK.match(msg):
            ev.action, ev.outcome = "su", Outcome.success
            ev.user = m["user"] or m["user2"]
            ev.extra["target_user"] = m["target"] or m["target2"]
    if ev.action is None:
        if m := USERADD.match(msg):
            ev.action, ev.outcome, ev.user = "user_created", Outcome.success, m["user"]
            if m["uid"]:
                ev.extra["uid"] = int(m["uid"])
        elif m := USERDEL.match(msg):
            ev.action, ev.outcome, ev.user = "user_deleted", Outcome.success, m["user"]
        elif m := GROUPADD.match(msg):
            ev.action, ev.outcome = "group_created", Outcome.success
            ev.extra["group"] = m["group"]
        elif m := USERMOD_ADD.match(msg):
            ev.action, ev.outcome, ev.user = "group_member_added", Outcome.success, m["user"]
            ev.extra["group"] = m["group"]
        elif m := GPASSWD_ADD.match(msg):
            ev.action, ev.outcome, ev.user = "group_member_added", Outcome.success, m["user"]
            ev.extra.update(group=m["group"], subject_user=m["by"])
        elif m := PASSWD.search(msg):
            ev.action, ev.outcome, ev.user = "password_changed", Outcome.success, m["user"]
        elif m := SESSION.match(msg):
            ev.action = f"session_{m['state']}"
            ev.outcome, ev.user = Outcome.success, m["user"]
            ev.extra["service"] = m["svc"]
    group = ev.extra.get("group")
    if isinstance(group, str) and group.lower() in PRIVILEGED_GROUPS:
        ev.tags.append("privileged_group")
    if ev.action == "sudo_command" or ev.extra.get("target_user") == "root":
        ev.tags.append("privileged")


def parse_line(line: str, ctx: ParseContext) -> NormalizedEvent | str:
    """Returns an event, or the reason the line is not syslog."""
    if m := RFC3339.match(line):
        try:
            ts = parse_iso(m["ts"])
        except ValueError as e:
            return f"bad timestamp: {e}"
    elif m := CLASSIC.match(line):
        month = _MONTHS.get(m["mon"])
        if month is None:
            return f"unknown month {m['mon']!r}"
        now_local = ctx.now.astimezone(ctx.syslog_tz)
        day = int(m["day"])
        year = resolve_syslog_year(month, day, now_local, ctx.syslog_year)
        try:
            hh, mm, ss = (int(x) for x in m["time"].split(":"))
            ts = datetime(year, month, day, hh, mm, ss, tzinfo=ctx.syslog_tz)
        except ValueError as e:
            return f"bad timestamp: {e}"
    else:
        return "not a syslog line"

    ev = _event(ts, m["host"], m["prog"], m["pid"], line)
    classify(ev, m["prog"], m["msg"])
    if not ev.action:
        ev.extra["message"] = m["msg"][:2048]
    return finalise(ev)


def parse_lines(lines: Iterable[tuple[int, str]], ctx: ParseContext) -> Iterator[ParseResult]:
    for line_no, line in lines:
        out = parse_line(line, ctx)
        if isinstance(out, str):
            yield Unparsed(raw=line, reason=out, line_no=line_no)
        else:
            yield Parsed(out, line_no)
