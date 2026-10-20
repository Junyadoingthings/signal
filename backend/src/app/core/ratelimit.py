"""Shared rate limiter. Client IP comes from the ASGI scope; behind nginx, uvicorn's
--proxy-headers (with --forwarded-allow-ips limited to the proxy) sets it correctly."""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
