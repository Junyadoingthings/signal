from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine
from sqlmodel import Session, SQLModel

from app.core.config import Settings, get_settings
from app.core.ratelimit import limiter
from app.core.security import hash_password
from app.main import create_app
from app.storage import db as db_module
from app.storage.db import make_engine
from app.storage.models import Role, User

ADMIN_EMAIL = "admin@signal.test"
ADMIN_PASSWORD = "correct horse battery"
ANALYST_EMAIL = "analyst@signal.test"
ANALYST_PASSWORD = "analyst password 1"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        env="test",
        data_dir=str(tmp_path / "data"),
        database_url="sqlite://",  # unused: tests inject the engine
        admin_email=ADMIN_EMAIL,
        admin_password=SecretStr(ADMIN_PASSWORD),
        cookie_secure=False,
        frontend_origin="http://localhost:5173",
        max_request_bytes=64 * 1024,
    )


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    # A real file (WAL, one connection per session) like production. A shared in-memory
    # connection would let one thread's ROLLBACK abort another thread's SELECT.
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    SQLModel.metadata.create_all(engine)
    db_module.set_engine(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as s:
        yield s


@pytest.fixture
def client(settings: Settings, engine: Engine) -> Iterator[TestClient]:
    limiter.reset()
    app = create_app(settings, run_migrations=False)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as c:  # runs lifespan → bootstraps the admin
        yield c


@pytest.fixture
def analyst(db: Session, client: TestClient) -> User:
    user = User(
        email=ANALYST_EMAIL,
        display_name="Ana Lyst",
        role=Role.analyst,
        password_hash=hash_password(ANALYST_PASSWORD),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login(client: TestClient, email: str, password: str) -> str:
    """Logs in and returns the CSRF token; the session cookie stays on the client."""
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    token: str = r.json()["csrf_token"]
    return token


def admin_login(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": login(client, ADMIN_EMAIL, ADMIN_PASSWORD)}
