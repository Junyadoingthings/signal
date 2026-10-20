"""Runtime configuration. Everything comes from environment variables (or a local .env)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIGNAL_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "sqlite:///./data/signal.db"
    data_dir: str = "./data"  # upload spool lives under here

    # First-run admin. Only used when the users table is empty; never has a default.
    admin_email: str | None = None
    admin_password: SecretStr | None = None
    admin_name: str = "Administrator"

    # Sessions & cookies
    session_ttl_hours: int = Field(default=12, ge=1, le=24 * 7)
    cookie_secure: bool = True
    cookie_name: str = "signal_session"
    csrf_header_name: str = "X-CSRF-Token"

    # Web
    frontend_origin: str = "http://localhost:5173"
    max_request_bytes: int = 1 * 1024 * 1024
    max_upload_bytes: int = 50 * 1024 * 1024
    max_live_batch_bytes: int = 10 * 1024 * 1024
    max_live_records: int = 5000

    # Rate limits (slowapi syntax)
    login_rate_limit: str = "5/minute"
    ingest_rate_limit: str = "120/minute"

    @field_validator("admin_password")
    @classmethod
    def _password_strength(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None and len(v.get_secret_value()) < 12:
            raise ValueError("SIGNAL_ADMIN_PASSWORD must be at least 12 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
