"""Build the pinned ATT&CK subset SIGNAL ships with (src/app/attack/enterprise.json).

Downloads one Enterprise ATT&CK STIX release from MITRE's official repository and keeps
only what SIGNAL needs: tactics in matrix order and every technique's id, name, tactics,
and deprecated/revoked status. Rule tests check every technique id against this file.

    uv run python scripts/build_attack.py 20.0

ATT&CK® is a registered trademark of The MITRE Corporation; data © MITRE, used under
the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
OUT = Path(__file__).resolve().parents[1] / "src" / "app" / "attack" / "enterprise.json"


def _ext_id(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def build(version: str) -> dict[str, Any]:
    url = f"{BASE}/enterprise-attack-{version}.json"
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https URL
        bundle = json.load(resp)
    objects: list[dict[str, Any]] = bundle["objects"]

    tactics_by_ref = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic"}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and not o.get("revoked"))
    tactics = []
    for ref in matrix["tactic_refs"]:
        t = tactics_by_ref[ref]
        tid, turl = _ext_id(t)
        tactics.append(
            {"id": tid, "shortname": t["x_mitre_shortname"], "name": t["name"], "url": turl}
        )

    ids_by_ref = {o["id"]: _ext_id(o)[0] for o in objects if o["type"] == "attack-pattern"}
    revoked_by = {
        r["source_ref"]: ids_by_ref.get(r["target_ref"])
        for r in objects
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by"
    }

    techniques: dict[str, Any] = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        tid, turl = _ext_id(o)
        if not tid:
            continue
        techniques[tid] = {
            "name": o["name"],
            "tactics": sorted(
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ),
            "url": turl,
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "revoked": bool(o.get("revoked")),
            "revoked_by": revoked_by.get(o["id"]) if o.get("revoked") else None,
        }
    return {
        "version": version,
        "source": url,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


if __name__ == "__main__":
    data = build(sys.argv[1] if len(sys.argv) > 1 else "20.0")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(
        f"wrote {OUT} ({len(data['tactics'])} tactics, {len(data['techniques'])} techniques)",
        file=sys.stderr,
    )
