"""Request dependencies: DB session, authenticated user, CSRF and role enforcement.

CSRF uses the synchronizer-token pattern: each session has a random token stored
server-side, returned to the SPA in JSON (never in a readable cookie), and required in
the X-CSRF-Token header on every state-changing request. SameSite=Lax cookies are a
second layer.
"""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlmodel import Session

from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.security import tokens_equal
from app.services import auth as auth_service
from app.storage.db import get_session
from app.storage.models import AuthSession, Role, User

DB = Annotated[Session, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Principal:
    user: User
    session: AuthSession


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def current_principal(request: Request, db: DB, settings: AppSettings) -> Principal:
    token = request.cookies.get(settings.cookie_name)
    resolved = auth_service.resolve(db, token) if token else None
    if resolved is None:
        raise APIError(401, "unauthenticated", "Authentication required")
    session, user = resolved

    if request.method not in SAFE_METHODS:
        sent = request.headers.get(settings.csrf_header_name, "")
        if not sent or not tokens_equal(sent, session.csrf_token):
            raise APIError(403, "csrf_failed", "Missing or invalid CSRF token")
    return Principal(user=user, session=session)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


def current_user(p: CurrentPrincipal) -> User:
    return p.user


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != Role.admin:
        raise APIError(403, "forbidden", "Admin role required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
