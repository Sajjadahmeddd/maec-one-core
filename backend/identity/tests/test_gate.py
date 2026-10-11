"""GET /api/gate/check — the question every app's front door asks.

Each test plays two parts: a browser that signed in at Core and holds its
cookie, and an app's server that forwards that cookie with its own gate secret
— the way Engineering Tools will. The server is a separate client with no
cookie jar of its own, so nothing reaches the gate that the app did not send.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import router_gate
from backend.identity.config import CSRF_HEADER, SESSION_COOKIE
from backend.identity.models import (
    Application, AuditLog, LoginSession, Organization, Permission, Role, ToolRule,
    User, UserLicense,
)
from backend.identity.permissions import can
from backend.identity.resolution import now

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL, ENGINEER_PASSWORD

GATE = "/api/gate/check"
SECRET = "engineering-gate-secret-for-tests-0123456789"
ET = "http://et.maec.local:8080"
CORE = "http://auth.maec.local:8000"
WANTED = f"{ET}/hapext/convert?file=a b&x=1"


@pytest.fixture
def gate(identity, db, monkeypatch):
    """Core configured for one app, and Engineering Tools' address set."""
    monkeypatch.setenv("GATE_SECRETS", f"engineering={SECRET}")
    monkeypatch.setenv("CORE_PUBLIC_URL", CORE)
    db.scalar(select(Application).where(Application.key == "engineering")).base_url = ET
    db.commit()


def _browser(email=ENGINEER_EMAIL, password=ENGINEER_PASSWORD) -> str:
    """Sign in at Core; return the cookie the browser now holds."""
    from backend.main import app
    browser = TestClient(app)
    r = browser.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return browser.cookies.get(SESSION_COOKIE)


def ask(cookie=None, *, app="engineering", secret=SECRET, method="GET",
        origin=None, url=WANTED):
    """What an app's server sends."""
    from backend.main import app as core
    server = TestClient(core)
    headers = {"X-MAEC-App": app, "X-Original-URL": url, "X-Original-Method": method}
    if secret is not None:
        headers["X-MAEC-Gate-Secret"] = secret
    if origin is not None:
        headers["X-Original-Origin"] = origin
    if cookie is not None:
        headers["Cookie"] = f"{SESSION_COOKIE}={cookie}"
    return server.get(GATE, headers=headers)


def _person(db, email=ENGINEER_EMAIL) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == email))


def _rows(db, action) -> int:
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == action))


def _refused(r, status, reason):
    assert r.status_code == status, (r.status_code, r.text)
    assert r.json()["reason"] == reason
    assert r.headers["cache-control"] == "no-store"
    return r.json()


# ------------------------------------------------------------- yes
def test_a_signed_in_engineer_with_a_seat_is_let_in(gate, db):
    r = ask(_browser())
    assert r.status_code == 200, r.text
    body = r.json()
    engineer = _person(db)
    assert body["user"] == {"id": str(engineer.id), "email": ENGINEER_EMAIL,
                            "name": engineer.display_name}
    assert body["org_id"] == str(engineer.org_id)
    assert "engineering:hapext:convert" in body["permissions"]
    assert "engineering:hapext:configure" not in body["permissions"]    # denied to employees
    assert body["nav_hidden"] == []
    assert r.headers["cache-control"] == "no-store"
    assert "set-cookie" not in r.headers, "the gate must not write to the browser's cookie"


def test_the_guard_leaves_the_gate_alone(gate):
    """No session at all: the gate's own answer, not the guard's 401."""
    body = _refused(ask(None), 401, "not_signed_in")
    assert "login_url" in body


def test_a_session_used_through_the_gate_stays_alive(gate, db):
    cookie = _browser()
    for row in db.scalars(select(LoginSession)).all():
        row.last_seen_at = now() - timedelta(minutes=5)
    db.commit()
    assert ask(cookie).status_code == 200
    db.expire_all()
    [row] = db.scalars(select(LoginSession)).all()
    assert now() - row.last_seen_at.replace(tzinfo=row.last_seen_at.tzinfo or now().tzinfo) \
        < timedelta(minutes=1)


# ---------------------------------------------- the permissions agree with can()
@pytest.mark.parametrize("email", [ENGINEER_EMAIL, ADMIN_EMAIL])
def test_the_permissions_are_exactly_what_can_says(gate, db, email):
    """One load(), resolved in memory per key — and the same answers can()
    gives one call at a time, for every registered key, across the
    equivalence scenarios the engine's own tests use."""
    from conftest import ADMIN_PASSWORD
    from test_resolution import SCENARIOS

    password = ENGINEER_PASSWORD if email == ENGINEER_EMAIL else ADMIN_PASSWORD
    keys = db.scalars(select(Permission.key).where(
        Permission.key.like("engineering:%"))).all()
    checked = 0
    for scenario in SCENARIOS:
        # a fresh database per scenario would be cleaner; scenarios that only
        # add are safe to stack, and the ones that remove access are last
        scenario(db)
        db.commit()
        person = _person(db, email)
        if person is None or person.status != "active":
            continue
        cookie = _browser(email, password) if person.org.status == "active" else None
        r = ask(cookie)
        expected = sorted(k for k in keys if can(db, person, k))
        if r.status_code == 200:
            assert r.json()["permissions"] == expected, scenario.__name__
            checked += 1
        else:
            assert expected == [], (scenario.__name__, r.status_code, expected)
    assert checked >= 3


def test_nav_hidden_follows_the_winning_tool_rule(gate, db):
    engineer = _person(db)
    employee = db.scalar(select(Role).where(Role.key == "employee", Role.org_id.is_(None)))
    app_id = db.scalar(select(Application.id).where(Application.key == "engineering"))
    for module, level in (("hapaudit", "hidden"), ("hapext", "no_access"), ("airsizer", "view")):
        db.add(ToolRule(org_id=engineer.org_id, application_id=app_id, module_key=module,
                        role_id=employee.id, access_level=level))
    db.commit()

    body = ask(_browser()).json()
    assert body["nav_hidden"] == ["hapaudit", "hapext"]
    # hidden is not a boundary: the API still answers for it
    assert "engineering:hapaudit:view" in body["permissions"]
    # no_access is: nothing in that module
    assert not [k for k in body["permissions"] if k.startswith("engineering:hapext:")]
    # view narrows without hiding
    assert [k for k in body["permissions"] if k.startswith("engineering:airsizer:")] == [
        "engineering:airsizer:view"]


# ----------------------------------------------------------------- 1. bad_app
def test_a_wrong_secret_is_refused_and_audited(gate, db):
    _refused(ask(_browser(), secret="x" * 43), 403, "bad_app")
    assert _rows(db, "gate.bad_secret") == 1
    row = db.scalar(select(AuditLog).where(AuditLog.action == "gate.bad_secret"))
    assert row.result == "blocked" and row.target_id == "engineering"
    assert row.org_id is None, "a platform event: shown under Platform events (E3)"


def test_a_missing_secret_is_refused(gate, db):
    _refused(ask(_browser(), secret=None), 403, "bad_app")
    assert _rows(db, "gate.bad_secret") == 1


def test_another_apps_secret_does_not_open_this_one(gate, monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"engineering={SECRET},timesheet={'t' * 40}")
    _refused(ask(_browser(), app="engineering", secret="t" * 40), 403, "bad_app")


def test_an_app_with_no_secret_configured_is_refused(gate):
    _refused(ask(_browser(), app="timesheet", secret=router_gate._NO_SECRET), 403, "bad_app")


def test_an_app_that_is_not_live_is_refused(gate, db, monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"engineering={SECRET},projects={'p' * 40}")
    _refused(ask(_browser(), app="projects", secret="p" * 40), 403, "bad_app")


# -------------------------------------------------------------- 2. bad_origin
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_a_mutation_from_another_origin_is_refused(gate, db, method):
    cookie = _browser()
    for origin in (None, "http://evil.maec.local:8080", "http://et.maec.local:8081",
                   "https://et.maec.local:8080", "null"):
        _refused(ask(cookie, method=method, origin=origin), 403, "bad_origin")
    assert _rows(db, "gate.bad_origin") == 1, "one row per address, app and ten minutes"


def test_a_mutation_from_the_apps_own_pages_goes_through(gate):
    assert ask(_browser(), method="POST", origin=ET).status_code == 200


def test_a_read_needs_no_origin(gate):
    for method in ("GET", "HEAD", "OPTIONS"):
        assert ask(_browser(), method=method).status_code == 200


def test_with_no_address_set_every_mutation_is_refused(gate, db):
    db.scalar(select(Application).where(Application.key == "engineering")).base_url = None
    db.commit()
    _refused(ask(_browser(), method="POST", origin=ET), 403, "bad_origin")


# ----------------------------------------------------------- 3–4. not_signed_in
def test_a_forged_or_unknown_cookie_is_not_signed_in(gate):
    _refused(ask("not-a-signed-cookie"), 401, "not_signed_in")


def test_a_signed_out_session_is_not_signed_in(gate):
    from backend.main import app
    browser = TestClient(app)
    csrf = browser.post("/api/auth/login", json={
        "email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD}).json()["csrf_token"]
    cookie = browser.cookies.get(SESSION_COOKIE)
    assert ask(cookie).status_code == 200
    browser.post("/api/auth/logout", headers={CSRF_HEADER: csrf})
    _refused(ask(cookie), 401, "not_signed_in")


def test_an_expired_session_is_not_signed_in(gate, db):
    cookie = _browser()
    for row in db.scalars(select(LoginSession)).all():
        row.idle_expires_at = now() - timedelta(seconds=1)
    db.commit()
    _refused(ask(cookie), 401, "not_signed_in")


def test_a_suspended_person_is_not_signed_in(gate, db):
    cookie = _browser()
    _person(db).status = "suspended"          # straight to the row: no revocation
    db.commit()
    _refused(ask(cookie), 401, "not_signed_in")


# --------------------------------------------------------- 5. password_change
def test_an_outstanding_password_change_sends_them_to_change_it(gate, db):
    cookie = _browser()
    _person(db).must_change_password = True
    db.commit()
    body = _refused(ask(cookie), 401, "password_change")
    parts = urlsplit(body["login_url"])
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{CORE}/change-password"
    assert parse_qs(parts.query)["next"] == [WANTED]


# ----------------------------------------------------------- 6. org_suspended
def test_a_suspended_organisation_is_refused(gate, db):
    cookie = _browser()
    db.scalar(select(Organization)).status = "suspended"
    db.commit()
    _refused(ask(cookie), 403, "org_suspended")


# ---------------------------------------------------------------- 7. no_access
def test_no_seat_is_no_access_and_audited_once_an_hour(gate, db):
    cookie = _browser()
    engineer = _person(db)
    db.delete(db.scalar(select(UserLicense).where(UserLicense.user_id == engineer.id)))
    db.commit()

    for _ in range(3):
        _refused(ask(cookie), 403, "no_access")
    assert _rows(db, "gate.no_access") == 1, "one row an hour, not one a click"

    row = db.scalar(select(AuditLog).where(AuditLog.action == "gate.no_access"))
    row_id = row.id
    db.execute(AuditLog.__table__.update().where(AuditLog.id == row_id)
               .values(created_at=now() - timedelta(hours=2))) \
        if db.bind.dialect.name == "sqlite" else None
    db.commit()
    _refused(ask(cookie), 403, "no_access")
    assert _rows(db, "gate.no_access") == 2, "an hour on, it is recorded again"


# ---------------------------------------------------------------- the login link
def test_the_login_link_comes_back_to_the_exact_page(gate):
    body = _refused(ask(None), 401, "not_signed_in")
    assert body["login_url"].startswith(f"{CORE}/?next=")
    encoded = body["login_url"].split("?next=", 1)[1]
    assert "/" not in encoded and "&" not in encoded and " " not in encoded
    assert parse_qs(urlsplit(body["login_url"]).query)["next"] == [WANTED]


def test_the_cookie_is_never_logged(gate, caplog):
    cookie = _browser()
    caplog.set_level(logging.DEBUG)
    ask(cookie, secret="x" * 43)
    ask(cookie, method="POST", origin="http://evil.example")
    ask("garbage-cookie-value")
    assert cookie not in caplog.text
    assert "garbage-cookie-value" not in caplog.text
    assert "gate: bad_app refused" in caplog.text
