"""Field normalisation shared by every parser, so correlation keys line up across sources.

- users: lowercase account name; a DOMAIN\\ or @domain part moves to extra["user_domain"]
- hosts: lowercase short name; the FQDN is kept in extra["host_fqdn"]
- IPs: validated and canonicalised; placeholders like "-" or "::1"-less blanks become None
"""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from app.ingest.types import NormalizedEvent

_EMPTY = {"", "-", "n/a", "null", "none", "(null)"}

# Accounts that are noise for user-entity correlation.
MACHINE_ACCOUNT_SUFFIX = "$"


def clean_str(v: Any, max_len: int = 1024) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if s.lower() in _EMPTY:
        return None
    return s[:max_len]


def clean_ip(v: Any) -> str | None:
    s = clean_str(v, 64)
    if s is None:
        return None
    s = s.removeprefix("::ffff:")
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def clean_port(v: Any) -> int | None:
    s = clean_str(v, 8)
    if s is None:
        return None
    try:
        p = int(s)
    except ValueError:
        return None
    return p if 0 <= p <= 65535 else None


def clean_int(v: Any) -> int | None:
    s = clean_str(v, 16)
    if s is None:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def split_user(v: Any) -> tuple[str | None, str | None]:
    """Returns (account, domain)."""
    s = clean_str(v, 255)
    if s is None:
        return None, None
    if "\\" in s:
        domain, _, account = s.partition("\\")
        return (account.lower() or None), (domain or None)
    if "@" in s:
        account, _, domain = s.partition("@")
        return (account.lower() or None), (domain or None)
    return s.lower(), None


def split_host(v: Any) -> tuple[str | None, str | None]:
    """Returns (short_name, fqdn). IP addresses are kept whole."""
    s = clean_str(v, 255)
    if s is None:
        return None, None
    s = s.lower().rstrip(".")
    if clean_ip(s):
        return s, None
    short, _, rest = s.partition(".")
    return short, (s if rest else None)


def basename(path: Any) -> str | None:
    """Process image path → lowercase executable name, Windows or POSIX."""
    s = clean_str(path, 1024)
    if s is None:
        return None
    return s.replace("\\", "/").rsplit("/", 1)[-1].lower() or None


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return dt.astimezone(UTC)


def finalise(ev: NormalizedEvent) -> NormalizedEvent:
    """Apply the cross-source conventions to an event a parser has filled in."""
    user, domain = split_user(ev.user)
    ev.user = user
    if domain and "user_domain" not in ev.extra:
        ev.extra["user_domain"] = domain

    host, fqdn = split_host(ev.host)
    ev.host = host
    if fqdn and "host_fqdn" not in ev.extra:
        ev.extra["host_fqdn"] = fqdn

    ev.src_ip = clean_ip(ev.src_ip)
    ev.dst_ip = clean_ip(ev.dst_ip)
    ev.timestamp = to_utc(ev.timestamp)
    if ev.dns_query:
        ev.dns_query = ev.dns_query.lower().rstrip(".")
    ev.tags = sorted(set(ev.tags))
    return ev
