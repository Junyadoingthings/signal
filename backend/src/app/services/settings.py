"""Runtime settings admins change from the UI, stored in the settings table."""

import re
from datetime import time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlmodel import Session

from app.storage.models import Setting, utcnow

INGEST_KEY = "ingest"
DETECTION_KEY = "detection"


def check_timezone(v: str) -> str:
    try:
        ZoneInfo(v)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise ValueError(f"unknown IANA timezone {v!r}") from e
    return v


class IngestSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Classic syslog lines carry neither. Both assumptions are shown next to every upload.
    syslog_timezone: str = Field(default="UTC", max_length=64)
    syslog_year: int | None = Field(default=None, ge=1990, le=2100)  # None = infer

    @field_validator("syslog_timezone")
    @classmethod
    def _valid_tz(cls, v: str) -> str:
        return check_timezone(v)

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


_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


class DetectionSettings(BaseModel):
    """Business hours for off-hours rules, and the correlation window (Phase 4)."""

    model_config = ConfigDict(extra="forbid")

    business_timezone: str = Field(default="UTC", max_length=64)
    business_start: str = "08:00"
    business_end: str = "18:00"
    business_days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])

    @field_validator("business_timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        return check_timezone(v)

    @field_validator("business_start", "business_end")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        if not _HHMM.match(v):
            raise ValueError("use 24h HH:MM")
        return v

    @field_validator("business_days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if not v or any(d < 0 or d > 6 for d in v):
            raise ValueError("days are 0 (Monday) to 6 (Sunday)")
        return sorted(set(v))

    def hours(self) -> tuple[time, time]:
        sh, sm = (int(x) for x in self.business_start.split(":"))
        eh, em = (int(x) for x in self.business_end.split(":"))
        return time(sh, sm), time(eh, em)


def get_detection(db: Session) -> DetectionSettings:
    raw = _get(db, DETECTION_KEY)
    return DetectionSettings.model_validate(raw) if raw else DetectionSettings()


def put_detection(db: Session, value: DetectionSettings) -> DetectionSettings:
    _put(db, DETECTION_KEY, value.model_dump())
    return value
