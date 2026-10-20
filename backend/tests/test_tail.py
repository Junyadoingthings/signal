"""signal-tail: following, rotation, resume, retries, and shipping into the real API."""

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient
from tests.conftest import admin_login

_spec = importlib.util.spec_from_file_location(
    "signal_tail", Path(__file__).parents[2] / "tools" / "signal_tail.py"
)
assert _spec
assert _spec.loader
tail: ModuleType = importlib.util.module_from_spec(_spec)
sys.modules["signal_tail"] = tail
_spec.loader.exec_module(tail)

L1 = "Oct 20 03:14:09 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2"
L2 = "Oct 20 03:14:10 web01 sshd[2]: Failed password for root from 203.0.113.50 port 2 ssh2"
L3 = "Oct 20 03:14:11 web01 sshd[3]: Accepted password for root from 203.0.113.50 port 3 ssh2"


def texts(rows: list[tuple[str, str, int]]) -> list[str]:
    return [r[0] for r in rows]


def test_first_run_starts_at_end_like_tail_f(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text(L1 + "\n")
    fol = tail.Follower(f, tail.Position())
    assert fol.read(100) == []
    with f.open("a") as fh:
        fh.write(L2 + "\n")
    assert texts(fol.read(100)) == [L2]


def test_from_start_and_partial_lines(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text(L1 + "\n" + L2[:20])
    fol = tail.Follower(f, tail.Position(), from_start=True)
    assert texts(fol.read(100)) == [L1]
    with f.open("a") as fh:
        fh.write(L2[20:] + "\n")
    rows = fol.read(100)
    assert texts(rows) == [L2]
    ino = os.stat(f).st_ino
    assert rows[0][1] == f"{ino}:{len(L1) + 1}"  # seq = inode:offset of the line start


def test_rotation_and_truncation(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text(L1 + "\n")
    fol = tail.Follower(f, tail.Position(), from_start=True)
    assert texts(fol.read(100)) == [L1]

    f.rename(tmp_path / "auth.log.1")  # logrotate
    f.write_text(L2 + "\n")
    assert texts(fol.read(100)) == [L2]

    f.write_text(L3 + "\n")  # truncated in place (copytruncate) and rewritten shorter
    with f.open("r+") as fh:
        fh.truncate(0)
    f.write_text(L3[:10] + "\n")
    assert texts(fol.read(100)) == [L3[:10]]


def test_resume_from_state(tmp_path: Path) -> None:
    f, state = tmp_path / "auth.log", tmp_path / "state.json"
    f.write_text(L1 + "\n" + L2 + "\n")
    shipped: list[list[str]] = []

    def post(body: dict[str, object]) -> dict[str, object]:
        shipped.append([r["raw"] for r in body["records"]])  # type: ignore[attr-defined]
        return {}

    shipper = tail.Shipper(post, "linux_auth", "s")
    fol = tail.Follower(f, tail.Position.load(state), from_start=True)
    assert tail.run(fol, shipper, state, batch_size=100, interval=0, once=True) == 2

    with f.open("a") as fh:
        fh.write(L3 + "\n")
    fol2 = tail.Follower(f, tail.Position.load(state))  # a fresh process
    assert tail.run(fol2, shipper, state, batch_size=100, interval=0, once=True) == 1
    assert shipped == [[L1, L2], [L3]]


def test_retries_then_succeeds() -> None:
    calls: list[int] = []
    sleeps: list[float] = []

    def flaky(_: dict[str, object]) -> dict[str, object]:
        calls.append(1)
        if len(calls) < 3:
            raise tail.RetryableError("connection refused")
        return {"parsed": 1}

    s = tail.Shipper(flaky, "linux_auth", "s", sleep=sleeps.append)
    assert s.send([(L1, "1:0", 10)]) == {"parsed": 1}
    assert sleeps == [1.0, 2.0]


def test_refuses_plain_http_to_remote(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNAL_INGEST_TOKEN", "sig_x")
    with pytest.raises(SystemExit, match="plain http"):
        tail.main([str(tmp_path / "x.log"), "--format", "linux_auth", "--url", "http://10.0.0.5"])


def test_ships_into_the_api_idempotently(client: TestClient, tmp_path: Path) -> None:
    h = admin_login(client)
    token = client.post("/api/ingest/tokens", json={"name": "t"}, headers=h).json()["token"]
    client.cookies.clear()

    def post(body: dict[str, object]) -> dict[str, object]:
        r = client.post(
            "/api/ingest/events", json=body, headers={"Authorization": f"Bearer {token}"}
        )
        if r.status_code >= 400:
            raise tail.FatalError(r.text)
        out: dict[str, object] = r.json()
        return out

    f = tmp_path / "auth.log"
    f.write_text(f"{L1}\n{L1}\n{L2}\n")  # the same line twice at different offsets
    shipper = tail.Shipper(post, "linux_auth", "web01:/var/log/auth.log")

    fol = tail.Follower(f, tail.Position(), from_start=True)
    tail.run(fol, shipper, None, batch_size=100, interval=0, once=True)

    # Lost state (no state file): everything is re-sent and the server dedups by seq.
    fol_again = tail.Follower(f, tail.Position(), from_start=True)
    lines = fol_again.read(100)
    result = shipper.send(lines)
    assert result["duplicates"] == 3
    assert result["parsed"] == 0

    h = admin_login(client)
    events = client.get("/api/events").json()["items"]
    assert len(events) == 3
