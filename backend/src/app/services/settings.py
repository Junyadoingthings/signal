"""Runtime settings admins change from the UI, stored in the settings table."""

from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlmodel import Session

from app.storage.models import Setting, utcnow

INGEST_KEY = "ingest"


class IngestSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Classic syslog lines carry neither. Both assumptions are shown next to every upload.
    syslog_timezone: str = Field(default="UTC", max_length=64)
    syslog_year: int | None = Field(default=None, ge=1990, le=2100)  # None = infer

    @field_validator("syslog_timezone")
    @classmethod
    def _valid_tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise ValueError(f"unknown IANA timezone {v!r}") from e
        return v

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.syslog_timezone)


def _get(db: Session, key: str) -> Any:
    row = db.get(Setting, key)
    return row.value if row else None


def _put(db: Session, key: str, value: Any) -> None:
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value)
    else:
        row.value = value
        row.updated_at = utcnow()
    db.add(row)
    db.commit()


def get_ingest(db: Session) -> IngestSettings:
    raw = _get(db, INGEST_KEY)
    return IngestSettings.model_validate(raw) if raw else IngestSettings()


def put_ingest(db: Session, value: IngestSettings) -> IngestSettings:
    _put(db, INGEST_KEY, value.model_dump())
    return value
