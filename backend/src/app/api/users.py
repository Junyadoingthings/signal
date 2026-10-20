from fastapi import APIRouter, Request

from app.api.deps import DB, AdminUser, client_ip
from app.api.schemas import UserCreate, UserOut, UserUpdate
from app.core.errors import APIError
from app.core.security import hash_password
from app.services import audit
from app.storage.models import Role, User
from app.storage.repositories import SqlSessionRepository, SqlUserRepository

router = APIRouter(prefix="/api/users", tags=["users"])


def _public(u: User) -> dict[str, object]:
    return {
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "is_active": u.is_active,
    }


@router.get("", response_model=list[UserOut])
def list_users(_: AdminUser, db: DB) -> list[User]:
    return list(SqlUserRepository(db).list())


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, admin: AdminUser, db: DB) -> User:
    users = SqlUserRepository(db)
    if users.by_email(body.email):
        raise APIError(409, "conflict", "A user with that email already exists")
    user = users.save(
        User(
            email=body.email,
            display_name=body.display_name,
            role=body.role,
            password_hash=hash_password(body.password),
        )
    )
    audit.record(
        db,
        "user.create",
        actor=admin,
        target_type="user",
        target_id=user.id,
        after=_public(user),
        ip=client_ip(request),
    )
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, request: Request, admin: AdminUser, db: DB) -> User:
    users = SqlUserRepository(db)
    user = users.get(user_id)
    if user is None:
        raise APIError(404, "not_found", "User not found")
    before = _public(user)

    removes_admin = (
        user.role == Role.admin
        and user.is_active
        and ((body.role is not None and body.role != Role.admin) or body.is_active is False)
    )
    if removes_admin and users.count_active_admins() <= 1:
        raise APIError(409, "last_admin", "Cannot demote or deactivate the last active admin")

    if body.display_name is not None:
        user.display_name = body.display_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    users.save(user)

    # Any change to access or credentials ends the user's existing sessions.
    if body.role is not None or body.is_active is False or body.password is not None:
        SqlSessionRepository(db).delete_for_user(user_id)

    after = _public(user) | ({"password": "changed"} if body.password else {})
    audit.record(
        db,
        "user.update",
        actor=admin,
        target_type="user",
        target_id=user.id,
        before=before,
        after=after,
        ip=client_ip(request),
    )
    return user
