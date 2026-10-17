"""The Applications screen: a Global Admin adds and edits applications.

Prompt 19 Part B. The key is permanent and never reused; only name, status
and address change; nothing is deleted (inactive instead); the gate secret is
shown as configured or not, never itself; every add and edit is audited; and
the seed, which runs on every start, never undoes an administrator's change.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import db as identity_db, seed
from backend.identity.config import CSRF_HEADER
from backend.identity.models import Application, AuditLog, Subscription, User

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ENGINEER_EMAIL, ENGINEER_PASSWORD

APPS = "/api/admin/applications"
SECRET = "the-engineering-gate-secret-never-shown-0123456789"


@pytest.fixture
def secrets(monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"engineering={SECRET}")


def h(client):
    return {CSRF_HEADER: client.csrf}


def new(client, **over):
    body = {"key": "itdesk", "name": "IT Ticketing", "status": "coming_soon",
            "base_url": "https://itdesk.example.test"} | over
    return client.post(APPS, headers=h(client), json=body)


def _rows(db, action):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == action)).all()


def _app(db, key):
    db.expire_all()
    return db.scalar(select(Application).where(Application.key == key))


# ------------------------------------------------------------ the list
def test_the_list_shows_every_application_and_whether_its_secret_is_set(admin_client, secrets):
    body = admin_client.get(APPS).json()
    apps = {a["key"]: a for a in body["applications"]}
    assert {"engineering", "projects", "timesheet"} <= set(apps)
    assert apps["engineering"]["gate_secret_configured"] is True
    assert apps["projects"]["gate_secret_configured"] is False
    assert set(apps["engineering"]) >= {"key", "name", "status", "base_url"}
    assert body["statuses"] == ["live", "coming_soon", "inactive"]


def test_the_secret_never_appears_in_any_answer(admin_client, secrets):
    answers = [admin_client.get(APPS), new(admin_client),
               admin_client.patch(f"{APPS}/engineering", headers=h(admin_client),
                                  json={"name": "Engineering Tools"})]
    for r in answers:
        assert r.status_code in (200, 201), r.text
        assert SECRET not in r.text


# ------------------------------------------------------------ add
def test_add_an_application(admin_client, db):
    r = new(admin_client)
    assert r.status_code == 201, r.text
    assert r.json()["key"] == "itdesk" and r.json()["gate_secret_configured"] is False
    app = _app(db, "itdesk")
    assert (app.name, app.status, app.base_url) == (
        "IT Ticketing", "coming_soon", "https://itdesk.example.test")
    row = _rows(db, "application.create")[0]
    assert row.target_id == "itdesk" and row.actor_email == ADMIN_EMAIL


def test_a_new_application_can_be_given_seats_at_once(admin_client, db):
    """Adding it subscribes the organisation, so a seat is not refused."""
    new(admin_client)
    assert db.scalar(select(func.count(Subscription.id)).where(
        Subscription.application_id == _app(db, "itdesk").id)) == 1
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    r = admin_client.post(f"/api/admin/users/{engineer.id}/licenses", headers=h(admin_client),
                          json={"application_key": "itdesk"})
    assert r.status_code == 201, r.text


def test_a_duplicate_key_is_refused(admin_client, db):
    assert new(admin_client).status_code == 201
    r = new(admin_client, name="Another")
    assert r.status_code == 409 and "never reused" in r.json()["detail"]
    r = new(admin_client, key="engineering")
    assert r.status_code == 409
    assert _app(db, "engineering").name != "IT Ticketing"


@pytest.mark.parametrize("bad", [
    {"key": "IT-Desk"}, {"key": "1desk"}, {"key": "d" * 41}, {"key": ""},
    {"status": "retired"}, {"base_url": "ftp://x.example"}, {"base_url": "not a url"},
    {"name": ""}, {"surprise": "field"},
])
def test_a_bad_application_is_refused(admin_client, db, bad):
    assert new(admin_client, **bad).status_code == 422
    assert _app(db, "itdesk") is None


# ------------------------------------------------------------ edit
def test_edit_name_status_and_address(admin_client, db):
    new(admin_client)
    r = admin_client.patch(f"{APPS}/itdesk", headers=h(admin_client), json={
        "name": "IT Desk", "status": "live", "base_url": "https://desk.example.test"})
    assert r.status_code == 200, r.text
    app = _app(db, "itdesk")
    assert (app.name, app.status, app.base_url) == ("IT Desk", "live", "https://desk.example.test")
    row = _rows(db, "application.update")[0]
    assert row.before["name"] == "IT Ticketing" and row.after["status"] == "live"


def test_an_edit_that_changes_nothing_writes_no_audit_row(admin_client, db):
    new(admin_client)
    admin_client.patch(f"{APPS}/itdesk", headers=h(admin_client), json={"name": "IT Ticketing"})
    assert _rows(db, "application.update") == []


@pytest.mark.parametrize("body", [{"key": "newkey"}, {"key": "itdesk", "name": "X"},
                                  {"description": "x"}])
def test_the_key_can_never_change(admin_client, db, body):
    new(admin_client)
    r = admin_client.patch(f"{APPS}/itdesk", headers=h(admin_client), json=body)
    assert r.status_code == 422
    assert _app(db, "itdesk").name == "IT Ticketing" and _app(db, "newkey") is None


def test_there_is_no_delete(admin_client):
    new(admin_client)
    r = admin_client.delete(f"{APPS}/itdesk", headers=h(admin_client))
    assert r.status_code == 405


def test_editing_an_unknown_application(admin_client):
    r = admin_client.patch(f"{APPS}/nope", headers=h(admin_client), json={"name": "X"})
    assert r.status_code == 404


def test_inactive_takes_it_off_the_launcher_and_out_of_the_gate(admin_client, db, monkeypatch):
    monkeypatch.setenv("GATE_SECRETS", f"engineering={SECRET}")
    admin_client.patch(f"{APPS}/engineering", headers=h(admin_client),
                       json={"status": "inactive", "base_url": "http://et.maec.local:8080"})
    assert "engineering" not in {a["key"] for a in admin_client.get("/api/auth/me").json()["apps"]}
    from backend.main import app as core
    r = TestClient(core).get("/api/gate/check", headers={
        "X-MAEC-App": "engineering", "X-MAEC-Gate-Secret": SECRET,
        "X-Original-URL": "http://et.maec.local:8080/", "X-Original-Method": "GET"})
    assert r.status_code == 403 and r.json()["reason"] == "bad_app"
    assert "engineering" in {a["key"] for a in admin_client.get(APPS).json()["applications"]}


# ------------------------------------------------------------ who may
def test_global_admin_only(engineer_client):
    assert engineer_client.get(APPS).status_code == 403
    assert new(engineer_client).status_code == 403
    r = engineer_client.patch(f"{APPS}/engineering", headers=h(engineer_client),
                              json={"name": "Mine"})
    assert r.status_code == 403


def test_a_change_without_a_csrf_token_is_refused(admin_client):
    r = admin_client.post(APPS, json={"key": "itdesk", "name": "IT"})
    assert r.status_code == 403


# ------------------------------------------------------------ the seed
def test_an_admins_edits_and_additions_survive_a_re_seed(admin_client, db):
    """The seed runs on every start. It creates the first applications only
    when absent and never changes or removes one an administrator touched."""
    admin_client.patch(f"{APPS}/engineering", headers=h(admin_client), json={
        "name": "Engineering Suite", "status": "inactive", "base_url": "https://eng.example.test"})
    new(admin_client)

    with identity_db.session_factory()() as session:
        seed.run(session, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD,
                 test_email=ENGINEER_EMAIL, test_password=ENGINEER_PASSWORD)

    eng = _app(db, "engineering")
    assert (eng.name, eng.status, eng.base_url) == (
        "Engineering Suite", "inactive", "https://eng.example.test")
    assert _app(db, "itdesk") is not None
