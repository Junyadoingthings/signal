"""Load 100k synthetic events into a throwaway SQLite DB and time the hot queries.

    uv run python scripts/perf_check.py [N]
"""

import random
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, insert
from sqlmodel import Session, SQLModel, col, select

from app.api.hunt import _epoch, bucket_size
from app.search.compiler import compile_node
from app.search.parser import parse
from app.storage import models
from app.storage.db import make_engine

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000


def timed(label: str, fn):  # type: ignore[no-untyped-def]
    t = time.perf_counter()
    out = fn()
    print(f"{label:<46}{(time.perf_counter() - t) * 1000:8.1f} ms   {out}")


def main() -> None:
    db_path = Path(tempfile.mkdtemp()) / "perf.db"
    engine = make_engine(f"sqlite:///{db_path}")
    SQLModel.metadata.create_all(engine)
    rnd = random.Random(7)
    start = datetime(2026, 10, 1, tzinfo=UTC)
    hosts = [f"host{i:02d}" for i in range(20)]
    users = [f"user{i:02d}" for i in range(200)]
    acts = ["ssh_login", "logon", "process_created", "dns_query", "http_request"]
    now = datetime.now(UTC)
    t = models.Event.__table__  # type: ignore[attr-defined]
    rows = []
    for i in range(N):
        ts = start + timedelta(seconds=rnd.randint(0, 20 * 86400))
        rows.append({
            "timestamp": ts, "ingested_at": now, "dedup_hash": f"{i:064d}", "source_type": "linux_auth",
            "host": rnd.choice(hosts), "user": rnd.choice(users),
            "src_ip": f"10.{rnd.randint(0, 9)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
            "action": rnd.choice(acts), "outcome": rnd.choice(["success", "failure", "unknown"]),
            "raw": f"Oct 1 sshd[{i}]: Failed password for user{rnd.randint(0, 199):02d} from 10.0.0.{i % 255} port {i}",
            "process_cmdline": None, "tags": [], "extra": {},
        })
    t0 = time.perf_counter()
    with engine.begin() as c:
        for k in range(0, N, 5000):
            c.execute(insert(t), rows[k : k + 5000])
    print(f"inserted {N:,} events in {time.perf_counter() - t0:.1f}s  ({db_path.stat().st_size / 1e6:.0f} MB)\n")

    lo, hi = start, start + timedelta(days=20)
    with Session(engine) as db:
        def hunt(q: str) -> str:
            node = parse(q)
            w = [col(models.Event.timestamp) >= lo, col(models.Event.timestamp) <= hi]
            if node is not None:
                w.append(compile_node(node))
            total = db.exec(select(func.count()).select_from(models.Event).where(*w)).one()
            db.exec(select(models.Event).where(*w).order_by(col(models.Event.timestamp).desc()).limit(100)).all()
            return f"{total:,} matches"

        for q in ("", "host:host03", "user:user07 AND outcome:failure", "src_ip:10.3.*",
                  "outcome:failure NOT action:dns_query", "port", "Failed password for user42"):
            timed(f"hunt  {q or '(all)'}", lambda q=q: hunt(q))

        def hist() -> str:
            size = bucket_size(hi - lo)
            first = int(lo.timestamp()) // size * size
            idx = ((_epoch(db, models.Event.timestamp) - first) / size).cast(models.Integer if False else __import__("sqlalchemy").Integer)
            rows_ = db.exec(select(idx.label("i"), func.count()).where(
                col(models.Event.timestamp) >= lo, col(models.Event.timestamp) <= hi).group_by("i")).all()
            return f"{len(rows_)} buckets"
        timed("histogram (20 days)", hist)


if __name__ == "__main__":
    main()
