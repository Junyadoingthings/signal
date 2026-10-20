"""Pinned MITRE ATT&CK Enterprise subset (built by scripts/build_attack.py).

ATT&CK® is a registered trademark of The MITRE Corporation. Data © MITRE, used under
the ATT&CK Terms of Use.
"""

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

DATA = Path(__file__).parent / "enterprise.json"


@dataclass(frozen=True, slots=True)
class Tactic:
    id: str
    shortname: str
    name: str
    url: str
    order: int


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    deprecated: bool
    revoked: bool
    revoked_by: str | None


@cache
def _load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(DATA.read_text(encoding="utf-8"))
    return data


def version() -> str:
    return str(_load()["version"])


@cache
def tactics() -> tuple[Tactic, ...]:
    return tuple(
        Tactic(t["id"], t["shortname"], t["name"], t["url"], i)
        for i, t in enumerate(_load()["tactics"])
    )


@cache
def tactic_order() -> dict[str, int]:
    return {t.shortname: t.order for t in tactics()}


def technique(tid: str) -> Technique | None:
    t = _load()["techniques"].get(tid)
    if t is None:
        return None
    return Technique(
        tid,
        t["name"],
        tuple(t["tactics"]),
        t["url"],
        t["deprecated"],
        t["revoked"],
        t.get("revoked_by"),
    )
