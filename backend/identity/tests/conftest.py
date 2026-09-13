"""Identity fixtures for the backend tests.

The unit tests run against an in-memory SQLite: the schema is the same
SQLAlchemy metadata the Postgres migration is generated from, and the seed
is the real seed. DATABASE_URL is pinned here before the app is imported, so
a developer's .env (which points at their real Postgres) is never touched by
the test run.

Every test that asks for `identity` gets a fresh, freshly seeded database:
a Global Admin and an ordinary engineer, both licensed for Engineering
Tools. Tests that need a lockout, a revoked seat or an expired role make
those changes on their own copy.
"""

from __future__ import annotations

import os

# Before anything imports backend.identity.config (which loads .env with
# override=False — so these values win).
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["SESSION_SECRET"] = "test-only-session-secret"

# A signing key made for this run, so the suite never signs with — or
# publishes — the developer's key from .env.
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

os.environ["OIDC_PRIVATE_KEY"] = rsa.generate_private_key(
    public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()).decode()
os.environ["OIDC_KEY_ID"] = "test-key"
os.environ["OIDC_ISSUER"] = "https://auth.test.invalid"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from backend.identity import db as identity_db  # noqa: E402
from backend.identity import router_auth, seed  # noqa: E402
from backend.identity.models import Base  # noqa: E402

ADMIN_EMAIL = "admin@mirageaec.com"
ADMIN_PASSWORD = "Correct-Horse-Battery-1"
ENGINEER_EMAIL = "engineer@mirageaec.com"
ENGINEER_PASSWORD = "Purple-Monkey-Dishwasher-2"


@pytest.fixture(autouse=True)
def _no_login_rate_limit():
    """The whole suite signs in far more than ten times a minute. The limit
    is exercised by the one test that turns it back on."""
    router_auth.limiter.enabled = False
    yield
    router_auth.limiter.enabled = False


@pytest.fixture
def identity():
    """A fresh, seeded identity database. Yields the engine."""
    engine = identity_db.engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with identity_db.session_factory()() as session:
        seed.run(session, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD,
                 test_email=ENGINEER_EMAIL, test_password=ENGINEER_PASSWORD)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def db(identity) -> Session:
    session = identity_db.session_factory()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def admin_credentials():
    return {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}


@pytest.fixture
def engineer_credentials():
    return {"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD}


@pytest.fixture
def app_client(identity):
    """A browser that has not signed in."""
    from backend.main import app
    return TestClient(app)


def _sign_in(client: TestClient, email: str, password: str):
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"fixture could not sign in as {email}"
    return response.json()


@pytest.fixture
def admin_client(app_client):
    """Signed in as the Global Admin. `.csrf` carries the token."""
    body = _sign_in(app_client, ADMIN_EMAIL, ADMIN_PASSWORD)
    app_client.csrf = body["csrf_token"]
    return app_client


@pytest.fixture
def engineer_client(identity):
    """Signed in as the ordinary engineer, in a separate browser."""
    from backend.main import app
    client = TestClient(app)
    body = _sign_in(client, ENGINEER_EMAIL, ENGINEER_PASSWORD)
    client.csrf = body["csrf_token"]
    return client
