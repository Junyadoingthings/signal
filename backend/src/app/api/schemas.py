"""Request/response models. Requests forbid unknown fields; strings are length-bounded."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.storage.models import Role

Email = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+$",
    ),
]
Password = Annotated[str, StringConstraints(min_length=1, max_length=256)]
NewPassword = Annotated[str, StringConstraints(min_length=12, max_length=256)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    email: Email
    password: Password


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class MeOut(BaseModel):
    user: UserOut
    csrf_token: str
    session_expires_at: datetime


class UserCreate(StrictModel):
    email: Email
    display_name: DisplayName
    role: Role = Role.analyst
    password: NewPassword


class UserUpdate(StrictModel):
    display_name: DisplayName | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: NewPassword | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor_id: int | None
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ip: str | None


class AuditPage(BaseModel):
    items: list[AuditOut]
    next_before_id: int | None


class SystemStatus(BaseModel):
    events_total: int
    events_last_24h: int
    unparsed_total: int
    alerts_open: int
    incidents_open: int
    rules_enabled: int
    last_event_at: datetime | None
    last_ingest_at: datetime | None


class Health(BaseModel):
    status: str = Field(examples=["ok"])
    version: str
