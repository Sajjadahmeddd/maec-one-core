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
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
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
        import existing_registry
        existing_registry.install(session)

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


def test_two_sessions_racing_to_consume_one_code_get_exactly_one_row(pg):
    """The single-use guarantee under real concurrency. Two transactions run
    the conditional UPDATE at the same moment; PostgreSQL row-locks, the
    second re-checks `consumed_at IS NULL` after the first commits, and
    changes nothing. SQLite cannot show this; it serialises the whole file."""
    import threading

    from backend.identity import oauth

    with pg.session_factory()() as session:
        client, _secret = oauth.register_client(
            session, application_key="engineering", name="Race",
            redirect_uris=["https://race.invalid/cb"])
        admin = user(session, "admin@mirageaec.com")
        code = oauth.mint_code(session, client=client, user=admin,
                               redirect_uri="https://race.invalid/cb", nonce="n", state="s")
        session.commit()
        client_pk = client.id

    barrier, won = threading.Barrier(2), []

    def attempt():
        with pg.session_factory()() as session:
            barrier.wait()
            row = oauth.consume_code(session, code, client_id=client_pk,
                                     redirect_uri="https://race.invalid/cb")
            session.commit()
            won.append(row is not None)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(won) == [False] * 7 + [True]


def test_eight_exchanges_racing_through_the_token_endpoint_yield_one_token(pg):
    """The same guarantee through the whole endpoint — client verification,
    consume, claims, signing — with eight requests released at once, each on
    its own pooled connection.

    It lives here, not beside the other token tests, because SQLite cannot run
    it: the unit suite shares one connection across threads, and two request
    threads interleaving on it failed inside the driver about one run in six
    ("bad parameter or other API misuse") — the test setup failing, not the
    endpoint. Found in Prompt 6."""
    import threading

    from fastapi.testclient import TestClient

    from backend.identity import oauth
    from backend.main import app

    redirect = "https://endpoint-race.invalid/cb"
    with pg.session_factory()() as session:
        client, secret = oauth.register_client(
            session, application_key="engineering", name="Endpoint race",
            redirect_uris=[redirect])
        admin = user(session, "admin@mirageaec.com")
        code = oauth.mint_code(session, client=client, user=admin, redirect_uri=redirect,
                               nonce="n", state="s")
        session.commit()
        client_id = client.client_id

    barrier, statuses = threading.Barrier(8), []

    def attempt():
        server = TestClient(app)
        barrier.wait()
        statuses.append(server.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
            "client_id": client_id, "client_secret": secret}).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(statuses) == [200] + [400] * 7


# ------------------------------------------- server-side sessions (Prompt 9a)
def _session_row(session, *, created, absolute, idle, digest=None):
    import secrets

    from backend.identity.models import LoginSession
    return LoginSession(
        session_hash=digest or secrets.token_hex(32),
        user_id=user(session, "admin@mirageaec.com").id,
        created_at=created, last_seen_at=created,
        absolute_expires_at=absolute, idle_expires_at=idle)


def test_a_session_row_is_checked_by_the_database(session):
    """Both CHECKs on `sessions`, asked of PostgreSQL: the idle window never
    outruns the absolute one, and a session ends after it starts."""
    from datetime import datetime, timedelta, timezone

    moment = datetime.now(timezone.utc)
    for absolute, idle, constraint in (
            (moment + timedelta(hours=1), moment + timedelta(hours=2),
             "ck_sessions_idle_within_absolute"),
            (moment - timedelta(hours=1), moment - timedelta(hours=2),
             "ck_sessions_ends_after_it_starts")):
        session.add(_session_row(session, created=moment, absolute=absolute, idle=idle))
        with pytest.raises(Exception, match=constraint):
            session.commit()
        session.rollback()


def test_a_session_hash_is_unique(session):
    """The cookie's id is looked up by its hash; two rows under one hash would
    make a sign-in ambiguous."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.exc import IntegrityError

    moment = datetime.now(timezone.utc)
    for _ in range(2):
        session.add(_session_row(session, created=moment, digest="f" * 64,
                                 absolute=moment + timedelta(hours=10),
                                 idle=moment + timedelta(hours=2)))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_a_session_revoked_on_one_connection_is_refused_on_another_at_once(pg):
    """Revocation under real concurrency. A browser keeps calling a guarded
    route, each request on its own pooled connection, while an administrator's
    revocation commits on a different connection. Every request that starts
    after that commit is refused — no cache, no grace period — and the ones
    before it were served. SQLite cannot show this: the unit suite shares one
    connection, so there is no "other connection" to fail to see the write."""
    import threading
    import time

    from fastapi.testclient import TestClient

    from backend.identity import router_auth, sessions
    from backend.main import app

    router_auth.limiter.enabled = False
    browser = TestClient(app)
    assert browser.post("/api/auth/login", json={
        "email": "admin@mirageaec.com", "password": "Scratch@2026"}).status_code == 200

    seen: list[tuple[float, int]] = []
    stop = threading.Event()

    def keep_calling():
        while not stop.is_set():
            started = time.monotonic()
            seen.append((started, browser.get("/api/admin/whoami").status_code))

    worker = threading.Thread(target=keep_calling)
    worker.start()
    try:
        while sum(1 for _, status in seen if status == 200) < 3:
            time.sleep(0.01)
        with pg.session_factory()() as admin_connection:
            revoked = sessions.revoke_all(
                admin_connection, user(admin_connection, "admin@mirageaec.com").id)
            admin_connection.commit()
        committed = time.monotonic()
        while sum(1 for started, _ in seen if started > committed) < 3:
            time.sleep(0.01)
    finally:
        stop.set()
        worker.join()

    assert revoked >= 1
    before = [status for started, status in seen if started < committed]
    after = [status for started, status in seen if started > committed]
    assert 200 in before
    assert after and set(after) == {401}, after


# --------------------------------------------- the lockout table (Prompt 11)
def _lock_row(session, address, *, failed=0, strikes=0):
    from datetime import datetime, timezone

    from backend.identity.models import LoginLock
    return LoginLock(user_id=user(session, "admin@mirageaec.com").id, address=address,
                     failed_count=failed, strikes=strikes,
                     updated_at=datetime.now(timezone.utc))


def test_a_login_lock_is_checked_by_the_database(session):
    from sqlalchemy.exc import IntegrityError

    for row, constraint in ((_lock_row(session, "198.51.100.1", failed=-1),
                             "ck_login_locks_failed_count"),
                            (_lock_row(session, "198.51.100.2", strikes=-1),
                             "ck_login_locks_strikes")):
        session.add(row)
        with pytest.raises(Exception, match=constraint):
            session.commit()
        session.rollback()

    session.add(_lock_row(session, "198.51.100.3"))
    session.add(_lock_row(session, "198.51.100.3"))
    with pytest.raises(IntegrityError, match="uq_login_locks_user_address"):
        session.commit()
    session.rollback()


def test_the_account_wide_lock_columns_are_gone(session):
    """One count per account is what let anyone lock anyone out; a column
    left behind would be a second, stale answer."""
    columns = set(session.scalars(text(
        "select column_name from information_schema.columns where table_name = 'users'")))
    assert not {"failed_login_count", "locked_until"} & columns


# ------------------------------------- simultaneous feature reports (Prompt 18)
RACE_SECRETS = {"racea": "racea-gate-secret-for-tests-0123456789abcdef",
                "raceb": "raceb-gate-secret-for-tests-0123456789abcdef"}


@pytest.fixture
def racing_apps(pg, monkeypatch):
    """Two apps Core knows, neither yet reported, each with its gate secret."""
    from backend.identity.models import Application
    monkeypatch.setenv("GATE_SECRETS", ",".join(f"{k}={v}" for k, v in RACE_SECRETS.items()))
    with pg.session_factory()() as session:
        for key in RACE_SECRETS:
            if session.scalar(select(Application).where(Application.key == key)) is None:
                session.add(Application(key=key, name=f"Race {key[-1].upper()}", status="coming_soon"))
        session.commit()


def _report(app_key, features):
    from backend.main import app
    caller = TestClient(app, raise_server_exceptions=False)
    return caller.put("/api/gate/features", json={"app_version": "v1", "features": features},
                      headers={"X-MAEC-App": app_key, "X-MAEC-Gate-Secret": RACE_SECRETS[app_key]})


def test_simultaneous_identical_first_reports_create_everything_once(pg, racing_apps):
    """Several servers of one app start together and report at the same moment.
    Each would find the features missing and create them: duplicate rows, a
    500, an audit row each. Registration takes the app's row lock, so they run
    one after another — the first creates, the rest find nothing to do."""
    from backend.identity.models import AuditLog, Feature, Permission, Role, RolePermission

    features = [{"key": f"task{n}", "name": f"Task {n}", "actions": ["use", "view"]}
                for n in range(1, 6)]
    barrier, statuses = threading.Barrier(15), []

    def attempt():
        barrier.wait()
        statuses.append(_report("racea", features).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert sorted(statuses) == [200] * 15, statuses

    with pg.session_factory()() as session:
        app_id = session.scalar(text("select id from applications where key = 'racea'"))
        assert session.scalar(select(func.count(Feature.id)).where(Feature.application_id == app_id)) == 5
        permission_ids = session.scalars(select(Permission.id).where(
            Permission.application_id == app_id)).all()
        assert len(permission_ids) == 10
        roles = session.scalar(select(func.count(Role.id)))
        assert session.scalar(select(func.count()).select_from(RolePermission).where(
            RolePermission.permission_id.in_(permission_ids))) == 10 * roles
        assert session.scalar(select(func.count(AuditLog.id)).where(
            AuditLog.action == "features.register", AuditLog.target_id == "racea")) == 1


def test_one_apps_report_never_waits_for_another_apps(pg, racing_apps):
    """The lock is the app's own row: while one app's report is held, another
    app's goes straight through — and the held app's next report waits its turn."""
    import time

    holder = pg.engine().connect()
    held = holder.begin()
    holder.execute(text("select id from applications where key = 'raceb' for update"))
    try:
        waiting, done = [], threading.Event()

        def report_b():
            waiting.append(_report("raceb", [{"key": "task1", "name": "B", "actions": ["use"]}]).status_code)
            done.set()

        behind = threading.Thread(target=report_b)
        behind.start()
        started = time.monotonic()
        r = _report("racea", [{"key": "task9", "name": "A", "actions": ["use"]}])
        assert r.status_code == 200, r.text
        assert time.monotonic() - started < 10, "another app's report did not wait"
        assert not done.wait(timeout=1.5), "the held app's report waits for its lock"
    finally:
        held.rollback()
        holder.close()
    assert done.wait(timeout=60) and waiting == [200], waiting
    behind.join(timeout=60)


def test_the_tool_settings_migration_round_trips_with_rows_present(pg):
    """3d7a1c9e4b20, OPEN-DECISIONS #22: down with a tool switched off, an old
    'view' rule written under the old constraint, then up again — where the
    'view' becomes 'full', the retired levels are refused, and the users are
    all still there."""
    import pytest
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect as schema
    from sqlalchemy.exc import IntegrityError

    cfg = Config(str(REPO / "backend" / "identity" / "alembic.ini"))
    ids = ("(select id from organizations limit 1), "
           "(select id from applications where key = 'engineering'), ")
    role = "(select id from roles where key = 'employee' and org_id is null)"

    with pg.session_factory()() as session:
        session.execute(text(
            "insert into tool_settings (id, org_id, application_id, module_key, status, updated_at) "
            f"values (gen_random_uuid(), {ids}'rebadge', 'inactive', now())"))
        session.commit()
        users_before = session.scalar(text("select count(*) from users"))

    command.downgrade(cfg, "58d9a22f38be")
    assert "tool_settings" not in schema(pg.engine()).get_table_names()
    with pg.session_factory()() as session:
        session.execute(text(
            "insert into tool_rules (id, org_id, application_id, module_key, role_id, "
            "access_level, status, updated_at) values "
            f"(gen_random_uuid(), {ids}'hapext', {role}, 'view', 'active', now())"))
        session.commit()

    command.upgrade(cfg, "head")
    assert "tool_settings" in schema(pg.engine()).get_table_names()
    with pg.session_factory()() as session:
        assert session.scalar(text(
            "select access_level from tool_rules where module_key = 'hapext'")) == "full"
        assert session.scalar(text("select count(*) from users")) == users_before
        with pytest.raises(IntegrityError):
            session.execute(text(
                "insert into tool_rules (id, org_id, application_id, module_key, role_id, "
                "access_level, status, updated_at) values "
                f"(gen_random_uuid(), {ids}'airsizer', {role}, 'hidden', 'active', now())"))
        session.rollback()
        session.execute(text("delete from tool_rules"))
        session.commit()


def test_the_features_migration_round_trips_with_rows_present(pg):
    """7b2e5d1f9c40, OPEN-DECISIONS #23: down with a reported feature, a
    retired key and an app's monitoring fields present, and up again — the
    permissions and role rules from before reports untouched throughout."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect as schema

    cfg = Config(str(REPO / "backend" / "identity" / "alembic.ini"))
    app = "(select id from applications where key = 'engineering')"
    with pg.session_factory()() as session:
        session.execute(text(
            "insert into features (id, application_id, key, name, is_new, created_at) "
            f"values (gen_random_uuid(), {app}, 'sheet', 'Sheet', true, now())"))
        session.execute(text(
            "insert into retired_features (id, application_id, key, retired_at) "
            f"values (gen_random_uuid(), {app}, 'oldsheet', now())"))
        session.execute(text(
            "update applications set features_reported_at = now(), features_version = 'abc', "
            "features_report = '{\"total\": 1}' where key = 'engineering'"))
        session.commit()
        rules_before = session.scalar(text("select count(*) from role_permissions"))
        permissions_before = session.scalar(text("select count(*) from permissions"))

    command.downgrade(cfg, "3d7a1c9e4b20")
    tables = set(schema(pg.engine()).get_table_names())
    assert not {"features", "retired_features"} & tables
    columns = {c["name"] for c in schema(pg.engine()).get_columns("applications")}
    assert not {"features_reported_at", "features_version", "features_report"} & columns

    command.upgrade(cfg, "head")
    assert {"features", "retired_features"} <= set(schema(pg.engine()).get_table_names())
    with pg.session_factory()() as session:
        assert session.scalar(text("select count(*) from role_permissions")) == rules_before
        assert session.scalar(text("select count(*) from permissions")) == permissions_before


def test_the_oidc_migration_round_trips_with_rows_present(pg):
    """Up, down and up again, with rows in the new tables and the old ones —
    so the downgrade is known to work on a database that has been used, not
    only on an empty one. Last in this module: it leaves the schema at head."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect as schema

    from datetime import datetime, timedelta, timezone

    from backend.identity import keys

    # the OIDC tables, and every table a later revision added on top of them
    oidc_tables = {"signing_keys", "oauth_clients", "authorization_codes", "sessions",
                   "login_locks", "tool_settings", "features", "retired_features"}
    cfg = Config(str(REPO / "backend" / "identity" / "alembic.ini"))

    with pg.session_factory()() as session:
        keys.ensure_published(session)                      # a row in a new table
        session.add(_probe_client(session, "probe-round-trip"))
        moment = datetime.now(timezone.utc)                 # and one in sessions
        session.add(_session_row(session, created=moment,
                                 absolute=moment + timedelta(hours=10),
                                 idle=moment + timedelta(hours=2)))
        session.add(_lock_row(session, "203.0.113.200"))     # and in login_locks
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
