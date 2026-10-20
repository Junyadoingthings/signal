"""Login, session issue/lookup and logout."""

from dataclasses import dataclass
from datetime import timedelta

from sqlmodel import Session

from app.core.config import Settings
from app.core.security import hash_password, hash_token, needs_rehash, new_token, verify_password
from app.services import audit
from app.storage.models import AuthSession, User, utcnow
from app.storage.repositories import SqlSessionRepository, SqlUserRepository


@dataclass(frozen=True)
class IssuedSession:
    token: str  # goes in the httpOnly cookie, never stored
    csrf_token: str
    session: AuthSession
    user: User


def authenticate(
    db: Session,
    settings: Settings,
    email: str,
    password: str,
    *,
    ip: str | None,
    user_agent: str | None,
) -> IssuedSession | None:
    users = SqlUserRepository(db)
    user = users.by_email(email)
    ok = verify_password(user.password_hash if user else None, password)
    if not user or not ok or not user.is_active:
        audit.record(db, "auth.login_failed", actor_email=email.lower()[:254], ip=ip)
        return None

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = utcnow()
    users.save(user)

    token, csrf = new_token(), new_token()
    session = SqlSessionRepository(db).create(
        AuthSession(
            token_hash=hash_token(token),
            csrf_token=csrf,
            user_id=user.id or 0,
            expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours),
            ip=ip,
            user_agent=(user_agent or "")[:512] or None,
        )
    )
    audit.record(db, "auth.login", actor=user, ip=ip)
    return IssuedSession(token=token, csrf_token=csrf, session=session, user=user)


def resolve(db: Session, token: str) -> tuple[AuthSession, User] | None:
    sessions = SqlSessionRepository(db)
    s = sessions.by_token_hash(hash_token(token))
    if s is None:
        return None
    if s.expires_at <= utcnow():
        sessions.delete(s)
        return None
    user = SqlUserRepository(db).get(s.user_id)
    if user is None or not user.is_active:
        return None
    return s, user


def logout(db: Session, s: AuthSession, user: User, ip: str | None) -> None:
    SqlSessionRepository(db).delete(s)
    audit.record(db, "auth.logout", actor=user, ip=ip)
