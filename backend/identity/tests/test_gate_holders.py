"""GET /api/gate/holders — who holds one of the asking app's features.

Project Management's lead picker asks Core who has the Project Lead section.
The answer is decided by the same engine as the gate, from the person's roles
in that app — so a role scoped to another app never counts — and carries ids
only. Set up as Prompt 19 describes: Engineer (task1), Project Lead (task2) and
BU Head (task3), switched on per role in the grid.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity.models import UserLicense

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL
from test_features import (  # noqa: F401  (apps is a fixture)
    SECRETS, _grid, _person, _role, _seat_and_role, apps, feature, report,
)

HOLDERS = "/api/gate/holders"


def holders(key, *, app="projects", secret=None, action="use"):
    from backend.main import app as core
    return TestClient(core).get(HOLDERS, params={"key": key, "action": action}, headers={
        "X-MAEC-App": app,
        "X-MAEC-Gate-Secret": SECRETS.get(app, "") if secret is None else secret})


@pytest.fixture
def sections(apps, admin_client, db):
    """Project Management's three sections, switched on as Prompt 19 sets them."""
    r = report([feature("task1", "Engineer"), feature("task2", "Project Lead"),
                feature("task3", "BU Head")], app="projects")
    assert r.status_code == 200, r.text
    for key, roles in (("task1", ("employee", "project_lead")),
                       ("task2", ("project_lead",)),
                       ("task3", ("business_admin",))):
        for role in roles:
            assert _grid(admin_client, "projects", key, _role(db, role), "full").status_code == 200


def _id(db, email=ENGINEER_EMAIL):
    return str(_person(db, email).id)


def test_chenthil_project_lead_in_pm_and_engineer_in_et(sections, db):
    """Project Lead scoped to Project Management, Normal User / Engineer to
    Engineering Tools (as seeded): listed for the Project Lead and Engineer
    sections of Project Management — not BU Head."""
    _seat_and_role(db, "projects", "project_lead")
    r = holders("task2")
    assert r.status_code == 200 and _id(db) in r.json()["core_user_ids"]
    assert _id(db) in holders("task1").json()["core_user_ids"]
    assert _id(db) not in holders("task3").json()["core_user_ids"]


def test_ids_only(sections, db):
    _seat_and_role(db, "projects", "project_lead")
    body = holders("task2").json()
    assert set(body) == {"core_user_ids"}
    assert all(len(i) == 36 and "@" not in i for i in body["core_user_ids"])
    assert ENGINEER_EMAIL not in str(body) and "Engineer" not in str(body)


def test_global_admin_holds_every_section_once_seated(sections, db):
    admin = _person(db, ADMIN_EMAIL)
    assert _id(db, ADMIN_EMAIL) not in holders("task2").json()["core_user_ids"], "no seat yet"
    db.add(UserLicense(user_id=admin.id, application_id=_app_id(db, "projects")))
    db.commit()
    for key in ("task1", "task2", "task3"):
        assert _id(db, ADMIN_EMAIL) in holders(key).json()["core_user_ids"], key


def _app_id(db, key):
    from backend.identity.models import Application
    return db.scalar(select(Application.id).where(Application.key == key))


def test_a_role_scoped_to_another_app_does_not_count(sections, db):
    """Project Lead in Engineering Tools makes nobody a Project Lead in Project
    Management: a seat there and Normal User / Engineer is all they have."""
    person = _person(db)
    from backend.identity.models import UserRole
    db.add(UserRole(user_id=person.id, role_id=_role(db, "project_lead").id,
                    scope_type="application", scope_id="engineering"))
    db.commit()
    _seat_and_role(db, "projects", "employee")
    assert _id(db) not in holders("task2").json()["core_user_ids"]
    assert _id(db) in holders("task1").json()["core_user_ids"], "the Engineer section, yes"


def test_no_seat_is_not_listed(sections, db):
    from backend.identity.models import UserRole
    person = _person(db)
    db.add(UserRole(user_id=person.id, role_id=_role(db, "project_lead").id,
                    scope_type="application", scope_id="projects"))
    db.commit()
    assert _id(db) not in holders("task2").json()["core_user_ids"]


def test_an_inactive_person_is_not_listed(sections, db):
    _seat_and_role(db, "projects", "project_lead")
    assert _id(db) in holders("task2").json()["core_user_ids"]
    for status in ("suspended", "invited"):
        _person(db).status = status
        db.commit()
        assert _id(db) not in holders("task2").json()["core_user_ids"], status


def test_switching_a_section_off_takes_people_out_of_the_list(sections, admin_client, db):
    _seat_and_role(db, "projects", "project_lead")
    _grid(admin_client, "projects", "task2", _role(db, "project_lead"), "no_access")
    assert _id(db) not in holders("task2").json()["core_user_ids"]


# ------------------------------------------------------------ who may ask
@pytest.mark.parametrize("secret", ["", "x" * 43, SECRETS["engineering"]])
def test_a_caller_without_the_apps_secret_is_refused(sections, secret):
    r = holders("task2", secret=secret)
    assert r.status_code == 403 and "core_user_ids" not in r.json()


@pytest.mark.parametrize("key", ["hapext", "engineering:hapext", "Task2", "", "task99"])
def test_an_app_may_ask_only_about_its_own_keys(sections, key):
    """Engineering Tools' feature, another app's permission key, a bad key, a
    key Project Management never reported: all refused, nothing listed."""
    r = holders(key)
    assert r.status_code == 422, (key, r.text)
    assert "core_user_ids" not in r.json()


def test_an_unknown_action_is_refused(sections):
    assert holders("task2", action="delete").status_code == 422
    assert holders("task2", action="view").status_code == 422, "task2 reports only use"
