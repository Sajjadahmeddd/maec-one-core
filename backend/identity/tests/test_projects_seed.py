"""Project Management in the seed (Prompt 15, A2).

One permission, projects:app:use, allowed for every built-in role; a
subscription without a seat cap; the application left coming_soon with no
address until the person makes it live at deploy time. And Timesheet, seeded
live with nothing behind it, corrected to coming_soon — on an existing
database too, without touching anything else.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import seed
from backend.identity.config import SESSION_COOKIE
from backend.identity.models import (
    Application, Permission, Role, RolePermission, Subscription, User, UserLicense, UserRole,
)

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ENGINEER_EMAIL, ENGINEER_PASSWORD

KEY = "projects:app:use"


def _app(db, key) -> Application:
    db.expire_all()
    return db.scalar(select(Application).where(Application.key == key))


def _projects_shape(db):
    projects = _app(db, "projects")
    keys = db.scalars(select(Permission.key).where(Permission.application_id == projects.id)).all()
    rules = db.execute(
        select(Role.key, RolePermission.effect)
        .join(RolePermission, RolePermission.role_id == Role.id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(Permission.key == KEY)).all()
    subs = db.scalars(select(Subscription).where(Subscription.application_id == projects.id)).all()
    return keys, sorted(rules), subs


def _reseed(db):
    return seed.run(db, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD,
                    test_email=ENGINEER_EMAIL, test_password=ENGINEER_PASSWORD)


def test_a_fresh_seed_registers_project_management(identity, db):
    keys, rules, subs = _projects_shape(db)
    assert keys == [KEY]
    assert rules == [("business_admin", "allow"), ("employee", "allow"),
                     ("global_admin", "allow"), ("project_lead", "allow")]
    assert len(subs) == 1 and subs[0].seats is None          # no seat cap
    projects = _app(db, "projects")
    assert (projects.status, projects.base_url) == ("coming_soon", None)
    assert _app(db, "timesheet").status == "coming_soon"


def test_a_re_seed_changes_nothing(identity, db):
    before = _projects_shape(db)
    created = _reseed(db)
    assert created == {}
    keys, rules, subs = _projects_shape(db)
    assert (keys, rules, len(subs)) == (before[0], before[1], 1)


def _snapshot(db):
    """Everything the seed could touch, except timesheet's status."""
    db.expire_all()
    apps = sorted((a.key, a.name, a.description, a.base_url,
                   a.status if a.key != "timesheet" else "-")
                  for a in db.scalars(select(Application)).all())
    return (apps,
            sorted(db.scalars(select(Permission.key)).all()),
            db.scalar(select(func.count()).select_from(RolePermission)),
            db.scalar(select(func.count()).select_from(Subscription)),
            sorted((u.email, u.password_hash, u.status) for u in db.scalars(select(User)).all()),
            db.scalar(select(func.count()).select_from(UserRole)),
            db.scalar(select(func.count()).select_from(UserLicense)))


def test_an_existing_database_with_timesheet_live_is_corrected_and_nothing_else(identity, db):
    """A database seeded before Prompt 15 has timesheet live. The seed that
    runs on the next start corrects it, and changes nothing else."""
    _app(db, "timesheet").status = "live"
    db.commit()
    before = _snapshot(db)
    created = _reseed(db)
    assert created == {"application corrections": 1}
    assert _app(db, "timesheet").status == "coming_soon"
    assert _snapshot(db) == before


def test_a_timesheet_someone_made_live_with_an_address_is_left_alone(identity, db):
    timesheet = _app(db, "timesheet")
    timesheet.status, timesheet.base_url = "live", "https://timesheet.example.test"
    db.commit()
    assert _reseed(db) == {}
    assert _app(db, "timesheet").status == "live"


def test_making_project_management_live_survives_a_re_seed(identity, db):
    """The person sets it live at deploy time; the seed runs on every start
    and must not put it back."""
    projects = _app(db, "projects")
    projects.status, projects.base_url = "live", "https://pm.example.test"
    db.commit()
    assert _reseed(db) == {}
    projects = _app(db, "projects")
    assert (projects.status, projects.base_url) == ("live", "https://pm.example.test")


# ------------------------------------------------------------------ the gate
SECRET = "projects-gate-secret-for-tests-0123456789"


def test_the_gate_tells_a_seated_employee_they_may_use_project_management(identity, db, monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"projects={SECRET}")
    monkeypatch.setenv("CORE_PUBLIC_URL", "http://auth.maec.local:8000")
    projects = _app(db, "projects")
    projects.status, projects.base_url = "live", "http://pm.maec.local:8083"
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    employee = db.scalar(select(Role).where(Role.key == "employee", Role.org_id.is_(None)))
    db.add(UserRole(user_id=engineer.id, role_id=employee.id,
                    scope_type="application", scope_id="projects"))
    db.add(UserLicense(user_id=engineer.id, application_id=projects.id))
    db.commit()

    from backend.main import app
    browser = TestClient(app)
    assert browser.post("/api/auth/login", json={
        "email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD}).status_code == 200
    r = TestClient(app).get("/api/gate/check", headers={
        "X-MAEC-App": "projects", "X-MAEC-Gate-Secret": SECRET,
        "X-Original-URL": "http://pm.maec.local:8083/", "X-Original-Method": "GET",
        "Cookie": f"{SESSION_COOKIE}={browser.cookies.get(SESSION_COOKIE)}"})
    assert r.status_code == 200, r.text
    assert r.json()["permissions"] == [KEY]


def test_without_a_projects_seat_the_gate_says_no_access(identity, db, monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"projects={SECRET}")
    projects = _app(db, "projects")
    projects.status, projects.base_url = "live", "http://pm.maec.local:8083"
    db.commit()
    from backend.main import app
    browser = TestClient(app)
    browser.post("/api/auth/login", json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    r = TestClient(app).get("/api/gate/check", headers={
        "X-MAEC-App": "projects", "X-MAEC-Gate-Secret": SECRET,
        "X-Original-URL": "http://pm.maec.local:8083/", "X-Original-Method": "GET",
        "Cookie": f"{SESSION_COOKIE}={browser.cookies.get(SESSION_COOKIE)}"})
    assert (r.status_code, r.json()["reason"]) == (403, "no_access")
