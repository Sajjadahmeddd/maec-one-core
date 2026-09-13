"""The things SQLite cannot tell us.

The rest of the suite runs on an in-memory SQLite, which is fast and has let
two production-only defects through:

  * a 10,000-character login address overflowed `actor_email varchar(254)` and
    turned a 401 into a 500. SQLite ignores column widths.
  * `audit_logs.actor_id` referenced `users.id` ON DELETE SET NULL. A SET NULL
    is an UPDATE, the append-only trigger refuses UPDATEs, and so deleting any
    user who had ever acted was impossible. SQLite enforces neither the
    foreign key nor the trigger.

Both were found by hand, late. This module runs the same paths against a real
PostgreSQL — schema built by the real migrations, trigger and all — so the
next one is found by the suite instead.

It skips itself when no PostgreSQL is reachable, so the normal `pytest` run is
unchanged for anyone without one. The connection details come from the
developer's own .env; nothing is hardcoded here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text

SCRATCH = "maec_pgtest"

# The repository root, derived from the package rather than by counting
# directories up from this file — which was only right while the suite lived
# at <repo>/tests/. Getting this wrong does not fail: it silently finds no
# .env and skips the whole module, which is worse.
import backend.identity as _identity  # noqa: E402

REPO = Path(_identity.__file__).resolve().parents[2]


def _developer_url() -> str | None:
    """The Postgres URL from .env, if there is one. Never a literal here."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return None
    url = (dotenv_values(REPO / ".env") or {}).get("DATABASE_URL", "")
    return url if url and url.startswith(("postgresql", "postgres")) else None


def _server_url(url: str) -> str:
    """The same server, but the maintenance database, so we may CREATE."""
    return url.rsplit("/", 1)[0] + "/postgres"


def _scratch_url(url: str) -> str:
    return url.rsplit("/", 1)[0] + "/" + SCRATCH


DEV_URL = _developer_url()
pytestmark = pytest.mark.skipif(
    DEV_URL is None,
    reason="no PostgreSQL in .env — these checks need a real database")


@pytest.fixture(scope="module")
def pg():
    """A scratch database, migrated and seeded by the real code paths."""
    from alembic import command
    from alembic.config import Config

    from backend.identity import db as identity_db

    server = create_engine(_server_url(DEV_URL), isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH}"))
        conn.execute(text(f"CREATE DATABASE {SCRATCH}"))

    scratch = _scratch_url(DEV_URL)
    was = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = scratch
    identity_db.reset()

    cfg = Config(str(REPO / "backend" / "identity" / "alembic.ini"))
    command.upgrade(cfg, "head")

    from backend.identity import seed
    with identity_db.session_factory()() as session:
        seed.run(session, admin_email="admin@mirageaec.com",
                 admin_password="Scratch@2026",
                 test_email="engineer@mirageaec.com", test_password="Scratch@2026")

    yield identity_db

    identity_db.reset()
    if was is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = was
    with server.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH}"))
    server.dispose()


@pytest.fixture
def session(pg):
    db = pg.session_factory()()
    try:
        yield db
    finally:
        db.close()


def user(db, email):
    from backend.identity.models import User
    return db.scalar(select(User).where(User.email == email))


# ------------------------------------------------- the trigger is real
def test_the_append_only_trigger_exists_and_refuses(session):
    from backend.identity.models import AuditLog

    assert session.scalar(text(
        "select count(*) from pg_trigger where tgname='audit_logs_append_only'")) == 1

    session.add(AuditLog(action="probe", result="success",
                         actor_email="probe@mirageaec.com"))
    session.commit()

    for statement in ("UPDATE audit_logs SET action='tampered'",
                      "DELETE FROM audit_logs"):
        with pytest.raises(Exception, match="append-only"):
            session.execute(text(statement))
            session.commit()
        session.rollback()


# ------------------------------ the two defects this module exists for
def test_a_user_with_audit_rows_can_still_be_deleted(session):
    """The ON DELETE SET NULL defect.

    A referential action on an append-only table is an UPDATE the trigger
    refuses, which made anyone who had ever acted undeletable.
    """
    from backend.identity import accounts
    from backend.identity.models import AuditLog

    admin = user(session, "admin@mirageaec.com")
    target = accounts.create_user(
        session, actor=admin, email="doomed@mirageaec.com",
        display_name="Doomed", password="Doomed@2026")

    # give them history of their own, as an actor
    from backend.identity.permissions import audit
    audit(session, actor=target, action="test.acted", result="success")
    assert session.scalar(select(func.count(AuditLog.id))
                          .where(AuditLog.actor_id == target.id)) >= 1

    accounts.delete_user(session, actor=admin, target=target)
    assert user(session, "doomed@mirageaec.com") is None

    # the record of what they did survives, still naming them
    kept = session.scalars(select(AuditLog).where(
        AuditLog.actor_email == "doomed@mirageaec.com")).all()
    assert kept, "deleting the account must not erase what it did"
    assert any(r.action == "test.acted" for r in kept)


def test_an_oversized_login_address_does_not_overflow_the_column(pg):
    """The varchar(254) defect: a long address must be a 401, not a 500."""
    from fastapi.testclient import TestClient

    from backend.identity import router_auth
    from backend.main import app

    router_auth.limiter.enabled = False
    client = TestClient(app)
    r = client.post("/api/auth/login",
                    json={"email": "a" * 10000 + "@x.com", "password": "x"})
    assert r.status_code == 401


def test_actor_email_cannot_be_null(session):
    """`actor_id` has no foreign key, so this is the only identity a row is
    guaranteed to keep. The guarantee is a constraint, not a convention —
    which is the whole lesson of the foreign key that had to be removed."""
    from sqlalchemy.exc import IntegrityError

    from backend.identity.models import AuditLog

    session.add(AuditLog(action="nameless", result="success"))
    with pytest.raises(IntegrityError, match="actor_email"):
        session.commit()
    session.rollback()


def test_an_anonymous_login_attempt_still_names_something(session):
    """A login POST with no address at all: nobody to name, but the row must
    still exist and still satisfy the constraint."""
    from backend.identity.models import AuditLog
    from backend.identity.permissions import ANONYMOUS_ACTOR, audit

    # a unique action: the scratch database is module-scoped, so an earlier
    # test's login.failed rows are still here
    audit(session, action="login.failed.anon-probe", result="warning",
          actor_email=None)
    row = session.scalars(select(AuditLog).where(
        AuditLog.action == "login.failed.anon-probe")).one()
    assert row.actor_email == ANONYMOUS_ACTOR
    assert "@" not in ANONYMOUS_ACTOR      # cannot collide with a real address


def test_every_string_column_survives_an_oversized_audit_write(session):
    """Whatever a caller passes, the row must fit — the audit log is the one
    thing that must never fail to write."""
    from backend.identity.models import AuditLog
    from backend.identity.permissions import audit

    audit(session, actor_email="x" * 5000 + "@mirageaec.com",
          action="a" * 500, target_type="t" * 500, target_id="i" * 500,
          source="s" * 500, result="success")
    row = session.scalars(select(AuditLog).order_by(
        AuditLog.created_at.desc())).first()
    assert len(row.actor_email) <= 254
    assert len(row.action) <= 80


# -------------------------------------------- constraints SQLite ignores
def test_the_email_lowercase_check_is_enforced(session):
    from backend.identity.models import Organization, User
    org = session.scalar(select(Organization))
    session.add(User(org_id=org.id, email="NotLower@mirageaec.com",
                     display_name="x", password_hash="x"))
    with pytest.raises(Exception, match="ck_users_email_lower"):
        session.commit()
    session.rollback()


def test_the_scope_id_rule_is_enforced(session):
    """platform takes no id; every other scope needs one."""
    from backend.identity.models import Role, UserRole
    admin = user(session, "admin@mirageaec.com")
    role = session.scalar(select(Role).where(Role.key == "employee"))
    session.add(UserRole(user_id=admin.id, role_id=role.id,
                         scope_type="project", scope_id=None))
    with pytest.raises(Exception, match="ck_user_roles_scope_id"):
        session.commit()
    session.rollback()


def test_the_composite_audit_index_is_present(session):
    """The audit screen reads one organisation newest-first, and this table
    grows fastest of any."""
    assert session.scalar(text(
        "select indexdef from pg_indexes "
        "where indexname='ix_audit_logs_org_created'")).endswith(
            "(org_id, created_at DESC)")


# ------------------------------------------- migrations run in this process
def test_running_the_migrations_in_process_leaves_the_service_logging(pg):
    """Alembic's env.py configures logging from alembic.ini, and
    logging.config.fileConfig disables every logger that already exists by
    default — `maec.identity` included. This module runs the migrations inside
    the test process, so every fail-closed warning written by a later test
    went nowhere, and the first test to assert on one failed for a reason
    unrelated to what it tested. Found in Prompt 6."""
    import logging
    assert logging.getLogger("maec.identity").disabled is False


# ------------------------------------------------ the OIDC tables (Prompt 6)
def test_a_signing_key_status_and_algorithm_are_checked(session):
    """Autogenerate has missed CHECK constraints three times in this repo.
    These ask PostgreSQL whether this migration's arrived."""
    from backend.identity.models import SigningKey
    for bad, constraint in (({"status": "compromised"}, "ck_signing_keys_status"),
                            ({"algorithm": "HS256"}, "ck_signing_keys_algorithm")):
        session.add(SigningKey(kid=f"probe-{constraint}", public_pem="x", **bad))
        with pytest.raises(Exception, match=constraint):
            session.commit()
        session.rollback()


def _probe_client(session, client_id):
    from backend.identity.models import Application, OAuthClient
    app = session.scalar(select(Application).where(Application.key == "engineering"))
    return OAuthClient(client_id=client_id, client_secret_hash="x", application_id=app.id,
                       name="Probe", redirect_uris=["https://probe.invalid/cb"])


def test_an_oauth_client_status_is_checked(session):
    client = _probe_client(session, "probe-status")
    client.status = "paused"
    session.add(client)
    with pytest.raises(Exception, match="ck_oauth_clients_status"):
        session.commit()
    session.rollback()


def test_an_authorization_code_hash_is_unique(session):
    """The token endpoint looks a code up by its hash; two rows under one
    hash would make that lookup ambiguous."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.exc import IntegrityError

    from backend.identity.models import AuthorizationCode

    client = _probe_client(session, "probe-unique")
    session.add(client)
    session.commit()
    admin = user(session, "admin@mirageaec.com")
    expires = datetime.now(timezone.utc) + timedelta(seconds=30)
    for _ in range(2):
        session.add(AuthorizationCode(
            code_hash="0" * 64, oauth_client_id=client.id, user_id=admin.id,
            application_id=client.application_id, redirect_uri="https://probe.invalid/cb",
            nonce="n", expires_at=expires))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_the_oidc_migration_round_trips_with_rows_present(pg):
    """Up, down and up again, with rows in the new tables and the old ones —
    so the downgrade is known to work on a database that has been used, not
    only on an empty one. Last in this module: it leaves the schema at head."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect as schema

    from backend.identity import keys

    oidc_tables = {"signing_keys", "oauth_clients", "authorization_codes"}
    cfg = Config(str(REPO / "backend" / "identity" / "alembic.ini"))

    with pg.session_factory()() as session:
        keys.ensure_published(session)                      # a row in a new table
        session.add(_probe_client(session, "probe-round-trip"))
        session.commit()
        users_before = session.scalar(text("select count(*) from users"))
    assert users_before > 0

    command.downgrade(cfg, "1340605a8316")
    assert not oidc_tables & set(schema(pg.engine()).get_table_names())
    with pg.session_factory()() as session:
        assert session.scalar(text("select count(*) from users")) == users_before

    command.upgrade(cfg, "head")
    assert oidc_tables <= set(schema(pg.engine()).get_table_names())
    with pg.session_factory()() as session:
        assert session.scalar(text("select count(*) from users")) == users_before
