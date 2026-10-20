"""Storage interface. Services depend on these protocols, not on SQL, so the backing
store can change (SQLite → Postgres) without touching business logic.

The SQL implementations use SQLAlchemy expressions only: every value is a bound
parameter, nothing is string-formatted into SQL.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import delete, func
from sqlmodel import Session, col, select

from app.storage.models import AuditLog, AuthSession, Role, User, utcnow


class UserRepository(Protocol):
    def get(self, user_id: int) -> User | None: ...
    def by_email(self, email: str) -> User | None: ...
    def list(self) -> Sequence[User]: ...
    def count(self) -> int: ...
    def count_active_admins(self) -> int: ...
    def save(self, user: User) -> User: ...


class SessionRepository(Protocol):
    def create(self, s: AuthSession) -> AuthSession: ...
    def by_token_hash(self, token_hash: str) -> AuthSession | None: ...
    def delete(self, s: AuthSession) -> None: ...
    def delete_for_user(self, user_id: int) -> None: ...
    def purge_expired(self, now: datetime) -> int: ...


class AuditRepository(Protocol):
    def add(self, entry: AuditLog) -> AuditLog: ...
    def page(
        self,
        *,
        limit: int,
        before_id: int | None,
        action: str | None,
        target_type: str | None,
        target_id: str | None,
    ) -> Sequence[AuditLog]: ...


class SqlUserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)

    def by_email(self, email: str) -> User | None:
        return self.db.exec(select(User).where(User.email == email.lower())).first()

    def list(self) -> Sequence[User]:
        return self.db.exec(select(User).order_by(col(User.created_at))).all()

    def count(self) -> int:
        return self.db.exec(select(func.count()).select_from(User)).one()

    def count_active_admins(self) -> int:
        stmt = (
            select(func.count())
            .select_from(User)
            .where(User.role == Role.admin, col(User.is_active).is_(True))
        )
        return self.db.exec(stmt).one()

    def save(self, user: User) -> User:
        user.email = user.email.lower()
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user


class SqlSessionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, s: AuthSession) -> AuthSession:
        self.db.add(s)
        self.db.commit()
        self.db.refresh(s)
        return s

    def by_token_hash(self, token_hash: str) -> AuthSession | None:
        return self.db.exec(select(AuthSession).where(AuthSession.token_hash == token_hash)).first()

    def delete(self, s: AuthSession) -> None:
        self.db.delete(s)
        self.db.commit()

    def delete_for_user(self, user_id: int) -> None:
        self.db.execute(delete(AuthSession).where(col(AuthSession.user_id) == user_id))
        self.db.commit()

    def purge_expired(self, now: datetime | None = None) -> int:
        result: Any = self.db.execute(
            delete(AuthSession).where(col(AuthSession.expires_at) < (now or utcnow()))
        )
        self.db.commit()
        return int(result.rowcount or 0)


class SqlAuditRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def add(self, entry: AuditLog) -> AuditLog:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def page(
        self,
        *,
        limit: int,
        before_id: int | None = None,
        action: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
    ) -> Sequence[AuditLog]:
        stmt = select(AuditLog)
        if before_id is not None:
            stmt = stmt.where(col(AuditLog.id) < before_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if target_type:
            stmt = stmt.where(AuditLog.target_type == target_type)
        if target_id:
            stmt = stmt.where(AuditLog.target_id == target_id)
        return self.db.exec(stmt.order_by(col(AuditLog.id).desc()).limit(limit)).all()
