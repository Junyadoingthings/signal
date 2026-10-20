"""First-run setup: create the initial admin from environment variables."""

import logging

from sqlmodel import Session

from app.core.config import Settings
from app.core.security import hash_password
from app.services import audit
from app.storage.models import Role, User
from app.storage.repositories import SqlUserRepository

log = logging.getLogger("signal.bootstrap")


class BootstrapError(RuntimeError):
    pass


def ensure_admin(db: Session, settings: Settings) -> None:
    users = SqlUserRepository(db)
    if users.count() > 0:
        return
    if not settings.admin_email or settings.admin_password is None:
        raise BootstrapError(
            "No users exist. Set SIGNAL_ADMIN_EMAIL and SIGNAL_ADMIN_PASSWORD to create the "
            "first admin (there are no default credentials)."
        )
    admin = users.save(
        User(
            email=settings.admin_email,
            display_name=settings.admin_name,
            role=Role.admin,
            password_hash=hash_password(settings.admin_password.get_secret_value()),
        )
    )
    audit.record(db, "user.bootstrap_admin", actor=admin, target_type="user", target_id=admin.id)
    log.info("Created initial admin %s", admin.email)
