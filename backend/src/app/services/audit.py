"""Append-only audit trail for logins, admin changes and triage actions."""

from typing import Any

from sqlmodel import Session

from app.storage.models import AuditLog, User
from app.storage.repositories import SqlAuditRepository


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    ip: str | None = None,
) -> AuditLog:
    return SqlAuditRepository(db).add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else actor_email,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            before=before,
            after=after,
            ip=ip,
        )
    )
