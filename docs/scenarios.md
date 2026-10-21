# Sample data and expected detections

`make seed` (with `make dev` running) generates one business day of logs for a fake
company, Northwind Traders, and uploads them. The generator is deterministic
(`tools/seed/generate.py`), and **`backend/tests/test_seed_scenarios.py` runs the same
data through the real pipeline and asserts everything below**, so this page can't drift
from what the product does.

| File | What it is |
|---|---|
| `web01-auth.log`, `db01-auth.log` | Linux auth logs |
| `web01-access.log` | nginx access log |
| `windows-events.jsonl` | Windows Security + Sysmon (evtx_dump JSON) |
| `wazuh-alerts.json` | two Wazuh alerts |

Background: ~15 users, normal logons, Office and browser processes, ordinary DNS and web
traffic, cron jobs, a few mistyped passwords and routine `sudo`. None of it should alert.

## Scenario 1: SSH brute force to new admin user (web01, 03:11 UTC)

`203.0.113.50` fires 48 failed logons at eight usernames, gets in as `deploy`, runs `sudo useradd sysupdate`, and adds the new account to `sudo`.

| Expected alert | Why |
|---|---|
| SSH / RDP brute force (T1110.001) | ≥ 8 failures from one IP in 5 min |
| Password spraying (T1110.003) | 8 distinct users from one IP |
| Successful logon after brute force (T1110, T1078), **critical** | failures then a success from the same IP |
| Privileged activity outside business hours (T1078) | sudo at 03:14 |
| New local account created (T1136.001) | `useradd sysupdate` |
| User added to an administrative group (T1098.007) | `usermod -aG sudo` |

**One critical incident** on `web01`: Credential Access → Initial Access → Privilege Escalation → Persistence. The alert names `deploy` (the account that got in), not the guessed ones.

## Scenario 2: phishing to log cleared (ws-04, 14:03 UTC)

`jdoe` opens `Invoice_4471.docm`; Word starts an encoded PowerShell, which calls out to `203.0.113.80`; `certutil` downloads `a.exe`; a local admin `helpdesk2` is created; the Security log is cleared.

| Expected alert | Why |
|---|---|
| Office application spawned a shell or script host | WINWORD → powershell.exe |
| Encoded PowerShell command | `-enc` + base64 |
| certutil used to download or decode a file | `-urlcache -split -f http://…` |
| New local account created | Security 4720 |
| User added to an administrative group | Security 4732 → Administrators. The event logs only a SID, which SIGNAL resolves to `helpdesk2` using the 4720 |
| Windows Security log cleared | Security 1102 |
| Wazuh high-severity alert | the seeded level-12 Wazuh alert for the same PowerShell event |

**One critical incident** on `ws-04` covering Execution, Command and Control, Persistence and Defense Impairment.

## Scenario 3: DNS exfiltration (ws-02, 15:40 UTC)

`upd.exe` sends 200 Sysmon DNS queries in 4 minutes to base64-looking subdomains of `exfil-example.net`.

| Expected alert | Why |
|---|---|
| DNS tunnelling (long or high-entropy subdomains) | long, high-entropy labels, ≥ 10 in 10 min |
| High DNS query volume to one domain | 200 queries in 5 min |

**One incident** on `ws-02` (Exfiltration).

## False-positive bait (these must alert, and a good analyst closes them)

| Where | What happened | Alert | Right call |
|---|---|---|---|
| db01, 02:00 | nightly `backup-svc` job runs `sudo` | Privileged activity outside business hours | Benign true positive |
| ws-03, 10:30 | helpdesk creates a contractor account (approved ticket) | New local account created | Benign true positive |
| ws-05, 11:42 | an admin checks a certificate revocation list with `certutil -verifyctl` | certutil used to download or decode a file | False positive |
| web01, 12:20 | a vulnerability scanner (sqlmap UA) probes the site | Web attack patterns | True positive, no compromise. It is not merged into the host incident |

None of the bait alerts joins an incident: each is a single alert with nothing related in its window.

## Verify it yourself

```bash
make dev        # terminal 1
make seed       # terminal 2: 1,247 records → 3 new incidents + 4 stand-alone alerts
```

Then open **Incidents**; the three attack incidents should be at the top. Or just run `make test-backend`.
