import re
from datetime import UTC, datetime, timedelta

_FRACTION = re.compile(r"(\.\d{1,6})\d*")
_BASIC_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")
_PS_DATE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")


def parse_iso(value: str) -> datetime:
    """ISO 8601 with any fraction length, 'Z', '+HHMM' or '+HH:MM'. Naive → error."""
    s = value.strip().replace(" ", "T", 1) if "T" not in value else value.strip()
    s = s.replace("Z", "+00:00").replace("z", "+00:00")
    s = _FRACTION.sub(r"\1", s)
    s = _BASIC_OFFSET.sub(r"\1:\2", s)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp has no timezone: {value!r}")
    return dt.astimezone(UTC)


def parse_iso_assume_utc(value: str) -> datetime:
    """For sources documented as UTC that omit the offset (Sysmon UtcTime, EVTX SystemTime)."""
    try:
        return parse_iso(value)
    except ValueError:
        s = _FRACTION.sub(r"\1", value.strip().replace(" ", "T", 1))
        return datetime.fromisoformat(s).replace(tzinfo=UTC)


def parse_epoch(value: float | int) -> datetime:
    v = float(value)
    if v > 1e14:  # microseconds
        v /= 1e6
    elif v > 1e11:  # milliseconds
        v /= 1e3
    return datetime.fromtimestamp(v, UTC)


def parse_any(value: object) -> datetime:
    """Best effort for generic JSON: ISO strings, epoch numbers, PowerShell /Date(ms)/."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, int | float):
        return parse_epoch(value)
    if isinstance(value, str):
        m = _PS_DATE.match(value.strip())
        if m:
            return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
        if re.fullmatch(r"\d{9,16}(\.\d+)?", value.strip()):
            return parse_epoch(float(value))
        return parse_iso(value)
    raise ValueError(f"unsupported timestamp value: {type(value).__name__}")


def resolve_syslog_year(month: int, day: int, now_local: datetime, configured: int | None) -> int:
    """Classic syslog has no year. Use the configured one, else the current year, rolling
    back one year when that would put the event more than a day in the future
    (e.g. reading December logs in January)."""
    if configured is not None:
        return configured
    year = now_local.year
    try:
        candidate = now_local.replace(year=year, month=month, day=day)
    except ValueError:  # 29 Feb in a non-leap year
        return year - 1
    if candidate - now_local > timedelta(days=1):
        return year - 1
    return year
