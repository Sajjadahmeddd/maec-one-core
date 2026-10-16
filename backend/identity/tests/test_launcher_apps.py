"""What the launcher is told: every application, and whether this person may
open it. GET /api/auth/me, `apps` — one entry per application in Core's
registry, in name order, with key, name, status, base_url and `entitled`:
a seat on it, under an in-date subscription, in an active organisation. The
same three things the gate checks, so a tile never opens onto a refusal.

The launcher decides how a tile looks from exactly these fields; its own
rules are tested in frontend/src/maecone/launcher.test.js.
"""

from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import delete, event, select, update

from backend.identity.models import Application, Organization, User, UserLicense
from backend.identity.router_auth import _apps_payload

from conftest import ENGINEER_EMAIL

ME = "/api/auth/me"
REGISTRY = ["attendance", "engineering", "expenses", "finance",
            "kpa", "people", "projects", "timesheet"]


def _apps(client) -> dict:
    body = client.get(ME).json()
    assert body["authenticated"] is True
    return {app["key"]: app for app in body["apps"]}


def _make_projects_live(db):
    db.execute(update(Application).where(Application.key == "projects")
               .values(status="live", base_url="https://pm.example.test"))
    db.execute(update(Application).where(Application.key == "engineering")
               .values(base_url="https://et.example.test"))
    db.commit()


def _seat(db, email, key):
    person = db.scalar(select(User).where(User.email == email))
    app = db.scalar(select(Application).where(Application.key == key))
    db.add(UserLicense(user_id=person.id, application_id=app.id))
    db.commit()


@contextmanager
def _statements(engine):
    seen = []
    def record(conn, cursor, statement, *args):
        seen.append(statement)
    event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", record)


# ------------------------------------------------------------- the answers
def test_every_application_in_the_registry_with_the_fields_the_launcher_needs(
        engineer_client):
    apps = engineer_client.get(ME).json()["apps"]
    assert sorted(a["key"] for a in apps) == REGISTRY
    for app in apps:
        assert {"key", "name", "status", "base_url", "entitled"} <= set(app), app
    assert [a["name"] for a in apps] == sorted(a["name"] for a in apps)


def test_a_global_admin_is_told_their_seats_not_given_every_app(admin_client, db):
    """Global Admin is a role, not a seat: the admin opens what they hold a
    seat on, like anyone. The Admin panel is offered separately."""
    _make_projects_live(db)
    me = admin_client.get(ME).json()
    assert me["is_global_admin"] is True and me["organization_suspended"] is False
    apps = {a["key"]: a for a in me["apps"]}
    assert apps["engineering"] == {**apps["engineering"], "status": "live",
                                   "base_url": "https://et.example.test", "entitled": True}
    assert apps["projects"]["status"] == "live" and apps["projects"]["entitled"] is False
    assert all(apps[k]["status"] == "coming_soon" and not apps[k]["entitled"]
               for k in REGISTRY if k not in ("engineering", "projects"))

    _seat(db, me["email"], "projects")
    assert _apps(admin_client)["projects"]["entitled"] is True


def test_an_employee_with_one_seat(engineer_client, db):
    _make_projects_live(db)
    me = engineer_client.get(ME).json()
    assert me["is_global_admin"] is False
    apps = {a["key"]: a for a in me["apps"]}
    assert [k for k in REGISTRY if apps[k]["entitled"]] == ["engineering"]
    assert apps["projects"]["status"] == "live" and apps["projects"]["entitled"] is False


def test_an_employee_with_no_seat(engineer_client, db):
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    db.execute(delete(UserLicense).where(UserLicense.user_id == person.id))
    db.commit()
    apps = _apps(engineer_client)
    assert not any(app["entitled"] for app in apps.values())
    assert apps["engineering"]["status"] == "live", "still listed, just not openable"


def test_a_seat_in_a_suspended_organisation_opens_nothing(engineer_client, db):
    _make_projects_live(db)
    db.execute(update(Organization).values(status="suspended"))
    db.commit()
    me = engineer_client.get(ME).json()
    assert me["organization_suspended"] is True
    assert sorted(a["key"] for a in me["apps"]) == REGISTRY, "every tile still shown"
    assert not any(a["entitled"] for a in me["apps"])


def test_signed_out_the_catalogue_says_nothing_about_seats(app_client):
    body = app_client.get(ME).json()
    assert body["authenticated"] is False
    assert sorted(a["key"] for a in body["apps"]) == REGISTRY
    assert not any("entitled" in a for a in body["apps"])


# ------------------------------------------------------------- the cost
def _count(engine, db, client):
    """Statements for the catalogue alone, and for the whole of /me."""
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    db.expire_all()
    with _statements(engine) as catalogue:
        _apps_payload(db, person)
    with _statements(engine) as whole:
        assert client.get(ME).status_code == 200
    return catalogue, whole


def test_one_query_for_the_catalogue_and_the_same_count_for_one_app_as_eight(
        identity, engineer_client, db):
    eight_catalogue, eight_whole = _count(identity, db, engineer_client)
    reads_apps = [s for s in eight_catalogue if "FROM applications" in s]
    assert len(reads_apps) == 1, eight_catalogue

    db.execute(delete(Application).where(Application.key != "engineering"))
    db.commit()
    assert len(_apps(engineer_client)) == 1

    one_catalogue, one_whole = _count(identity, db, engineer_client)
    assert len(one_catalogue) == len(eight_catalogue), (one_catalogue, eight_catalogue)
    assert len(one_whole) == len(eight_whole), (one_whole, eight_whole)
