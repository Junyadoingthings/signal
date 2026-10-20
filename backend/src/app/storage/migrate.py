"""Run Alembic migrations programmatically (on startup and from `make migrate`)."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.core.config import get_settings

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url or get_settings().database_url)
    return cfg


def upgrade_to_head(url: str | None = None) -> None:
    command.upgrade(alembic_config(url), "head")


def revision(message: str) -> None:
    command.revision(alembic_config(), message=message, autogenerate=True)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 2 and sys.argv[1] == "revision":
        revision(" ".join(sys.argv[2:]))
    else:
        upgrade_to_head()
