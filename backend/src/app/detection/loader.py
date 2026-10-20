"""Load rule YAML from disk, validate it, and sync it into the rules table.

Files are the source of truth for rule content; the database owns runtime state
(enabled flag, hit count, last fired). A rule removed from disk is disabled, not deleted,
so its alerts keep their history.
"""

import hashlib
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError
from sqlmodel import Session, select

from app.detection.schema import RuleSpec
from app.storage.models import Rule, Severity, utcnow

log = logging.getLogger("signal.detection")

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


class RuleLoadError(ValueError):
    pass


def load_rule_file(path: Path) -> tuple[RuleSpec, str]:
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleLoadError(f"{path.name}: invalid YAML: {e}") from e
    try:
        spec = RuleSpec.model_validate(data)
    except (ValidationError, ValueError) as e:
        raise RuleLoadError(f"{path.name}: {e}") from e
    if path.stem != spec.id:
        raise RuleLoadError(f"{path.name}: file name must match rule id {spec.id!r}")
    return spec, text


def load_rules(directory: Path = DEFAULT_RULES_DIR) -> list[tuple[RuleSpec, str]]:
    rules = [load_rule_file(p) for p in sorted(directory.glob("*.yml"))]
    ids = [r.id for r, _ in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleLoadError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


def sync_rules(db: Session, rules: list[tuple[RuleSpec, str]]) -> None:
    existing = {r.id: r for r in db.exec(select(Rule)).all()}
    on_disk = set()
    for spec, text in rules:
        on_disk.add(spec.id)
        sha = hashlib.sha256(text.encode()).hexdigest()
        row = existing.get(spec.id)
        if row is None:
            row = Rule(
                id=spec.id,
                title=spec.title,
                yaml=text,
                sha256=sha,
                enabled=spec.enabled,
                severity=Severity(spec.severity),
            )
        elif row.sha256 == sha:
            continue
        row.title = spec.title
        row.yaml = text
        row.sha256 = sha
        row.severity = Severity(spec.severity)
        row.primary_tactic = spec.attack.tactic if spec.attack else None
        row.techniques = list(spec.attack.techniques) if spec.attack else []
        row.updated_at = utcnow()
        db.add(row)
    for rid, row in existing.items():
        if rid not in on_disk and row.enabled:
            log.warning("rule %s no longer exists on disk; disabling it", rid)
            row.enabled = False
            db.add(row)
    db.commit()
