"""Apps tell Core their features: PUT /api/gate/features. OPEN-DECISIONS #23.

An application reports its own feature keys when it starts; Core creates the
new ones — allowed for Global Admin only — marks the ones that went quiet,
never changes a role rule, and lets an administrator remove (and so retire)
only what an app no longer reports. The grid then switches each feature on
or off per role, and the gate answers from it on the person's next request.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import router_auth
from backend.identity.config import CSRF_HEADER, SESSION_COOKIE
from backend.identity.models import (
    Application, AuditLog, Feature, Permission, RetiredFeature, Role, RolePermission,
    Subscription, User, UserLicense, UserRole,
)

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ENGINEER_EMAIL, ENGINEER_PASSWORD

FEATURES = "/api/gate/features"
CHECK = "/api/gate/check"
SECRETS = {
    "engineering": "engineering-gate-secret-for-tests-0123456789",
    "projects": "projects-gate-secret-for-tests-0123456789ab",
    "fieldapp": "fieldapp-gate-secret-for-tests-0123456789ab",
}
FIELD_URL = "http://field.maec.local:8095"


@pytest.fixture
def apps(identity, db, monkeypatch):
    """Three apps Core can be told about: Engineering Tools and Project
    Management as seeded, and a made-up new one, live, subscribed."""
    monkeypatch.setenv("GATE_SECRETS", ",".join(f"{k}={v}" for k, v in SECRETS.items()))
    org_id = db.scalar(select(User.org_id).where(User.email == ADMIN_EMAIL))
    field = Application(key="fieldapp", name="Field App", status="live", base_url=FIELD_URL)
    db.add(field)
    db.flush()
    db.add(Subscription(org_id=org_id, application_id=field.id,
                        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    for key, url in (("engineering", "http://et.maec.local:8080"),
                     ("projects", "http://pm.maec.local:8081")):
        app = db.scalar(select(Application).where(Application.key == key))
        app.status, app.base_url = "live", url
    db.commit()


def report(features, *, app="fieldapp", secret=None, version="93e6aee", body=None):
    from backend.main import app as core
    headers = {"X-MAEC-App": app,
               "X-MAEC-Gate-Secret": SECRETS.get(app, "") if secret is None else secret}
    payload = body if body is not None else {"app_version": version, "features": features}
    return TestClient(core).put(FEATURES, headers=headers, json=payload)


def feature(key, name=None, actions=("use",)):
    return {"key": key, "name": name or key.title(), "actions": list(actions)}


def _app(db, key):
    return db.scalar(select(Application).where(Application.key == key))


def _feature(db, app_key, key):
    db.expire_all()
    return db.scalar(select(Feature).where(Feature.application_id == _app(db, app_key).id,
                                           Feature.key == key))


def _effects(db, permission_key):
    db.expire_all()
    rows = db.execute(select(Role.key, Role.org_id, RolePermission.effect)
                      .join(RolePermission, RolePermission.role_id == Role.id)
                      .join(Permission, Permission.id == RolePermission.permission_id)
                      .where(Permission.key == permission_key)).all()
    return {key: effect for key, _org, effect in rows}


def _rows(db, action):
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == action))


def _person(db, email=ENGINEER_EMAIL):
    return db.scalar(select(User).where(User.email == email))


def _role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def _cookie(email=ENGINEER_EMAIL, password=ENGINEER_PASSWORD):
    from backend.main import app as core
    browser = TestClient(core)
    assert browser.post("/api/auth/login", json={"email": email, "password": password}).status_code == 200
    return browser.cookies.get(SESSION_COOKIE)


def ask(cookie, app):
    from backend.main import app as core
    return TestClient(core).get(CHECK, headers={
        "X-MAEC-App": app, "X-MAEC-Gate-Secret": SECRETS[app],
        "X-Original-URL": "http://x/", "X-Original-Method": "GET",
        "Cookie": f"{SESSION_COOKIE}={cookie}"})


def _seat_and_role(db, app_key, role_key, email=ENGINEER_EMAIL):
    person = _person(db, email)
    app = _app(db, app_key)
    if db.scalar(select(UserLicense).where(UserLicense.user_id == person.id,
                                           UserLicense.application_id == app.id)) is None:
        db.add(UserLicense(user_id=person.id, application_id=app.id))
    db.add(UserRole(user_id=person.id, role_id=_role(db, role_key).id,
                    scope_type="application", scope_id=app_key))
    db.commit()


def _grid(admin_client, app_key, module, role, level):
    return admin_client.put("/api/admin/tool-rules", headers={CSRF_HEADER: admin_client.csrf},
                            json={"changes": [{"application_key": app_key, "module_key": module,
                                               "role_id": str(role.id), "access_level": level}]})


# ------------------------------------------------------------ who may call
@pytest.mark.parametrize("secret", ["", "x" * 43, SECRETS["projects"]])
def test_a_caller_without_the_apps_secret_is_refused(apps, db, secret):
    r = report([feature("task1")], secret=secret)
    assert r.status_code == 403 and r.json()["reason"] == "bad_app"
    assert _feature(db, "fieldapp", "task1") is None


def test_an_app_core_does_not_know_is_refused(apps):
    assert report([feature("task1")], app="nope", secret="y" * 43).status_code == 403


def test_an_app_cannot_register_for_another(apps, db):
    """Its secret proves which app it is; a body claiming another is refused."""
    r = report([feature("task1")], body={"app": "projects", "features": [feature("task1")]})
    assert r.status_code == 422 and "only its own" in r.json()["detail"]
    r = report([feature("task1")], app="projects", secret=SECRETS["fieldapp"])
    assert r.status_code == 403
    assert db.scalar(select(func.count(Feature.id))) == 0


def test_an_app_that_is_not_live_yet_may_report(apps, db):
    _app(db, "fieldapp").status = "coming_soon"
    db.commit()
    assert report([feature("task1")]).status_code == 200


# ------------------------------------------------------------ what it may say
@pytest.mark.parametrize("bad,why", [
    ([feature("Task71")], "must match"),
    ([feature("1task")], "must match"),
    ([feature("task-71")], "must match"),
    ([feature("t" * 41)], "must match"),
    ([feature("task1", actions=["delete"])], "unknown action"),
    ([feature("task1", actions=[])], "non-empty"),
    ([feature("task1", actions=["use", "use"])], "listed twice"),
    ([feature("task1"), feature("task1")], "more than once"),
    ([{"key": "task1", "name": "", "actions": ["use"]}], "name must be"),
    ([{"key": "task1", "name": "bell\x07", "actions": ["use"]}], "name must be"),
    ([feature(f"task{n}") for n in range(201)], "At most 200"),
])
def test_a_bad_report_is_refused_whole(apps, db, bad, why):
    r = report([feature("good")] + bad if why != "At most 200" else bad)
    assert r.status_code == 422, r.text
    assert why in r.json()["detail"]
    assert db.scalar(select(func.count(Feature.id))) == 0, "not even the good one"


@pytest.mark.parametrize("version", ["v" * 65, "bad\nversion", ""])
def test_a_bad_version_is_refused(apps, version):
    assert report([feature("task1")], version=version).status_code == 422


def test_a_body_that_is_not_a_report_is_refused(apps):
    from backend.main import app as core
    r = TestClient(core).put(FEATURES, content=b"not json", headers={
        "X-MAEC-App": "fieldapp", "X-MAEC-Gate-Secret": SECRETS["fieldapp"]})
    assert r.status_code == 422
    assert report(None, body={"features": "task1"}).status_code == 422


# ------------------------------------------------------------ a new feature
def test_a_new_feature_is_allowed_for_global_admin_only(apps, db):
    org_id = _person(db, ADMIN_EMAIL).org_id
    db.add(Role(key="it_admin", name="IT Admin", level=4, org_id=org_id, is_custom=True))
    db.commit()

    r = report([feature("task71", "Project Lead", ["use", "view"])])
    assert r.status_code == 200
    assert r.json() == {"registered": 1, "new": 1, "not_reported": 0}
    for action in ("use", "view"):
        assert _effects(db, f"fieldapp:task71:{action}") == {
            "global_admin": "allow", "business_admin": "deny", "project_lead": "deny",
            "employee": "deny", "it_admin": "deny"}
    f = _feature(db, "fieldapp", "task71")
    assert (f.name, f.is_new, f.not_reported_since) == ("Project Lead", True, None)


def test_reporting_again_changes_nothing_and_writes_no_audit_row(apps, db):
    assert report([feature("task1"), feature("task2")]).status_code == 200
    assert _rows(db, "features.register") == 1
    r = report([feature("task1"), feature("task2")])
    assert r.json() == {"registered": 2, "new": 0, "not_reported": 0}
    assert _rows(db, "features.register") == 1
    assert db.scalar(select(func.count(Permission.id)).where(
        Permission.application_id == _app(db, "fieldapp").id)) == 2


def test_the_audit_row_says_what_changed(apps, db):
    report([feature("task1")])
    row = db.scalar(select(AuditLog).where(AuditLog.action == "features.register"))
    assert row.actor_email == "(fieldapp app)" and row.org_id is None
    assert row.after["app_version"] == "93e6aee" and row.after["new"] == ["task1"]
    assert row.after["counts"] == {"total": 1, "new": 1, "not_reported": 0}


def test_a_role_rule_is_never_changed_by_registration(apps, db):
    report([feature("task1")])
    rule = db.scalar(select(RolePermission).join(Permission).where(
        Permission.key == "fieldapp:task1:use",
        RolePermission.role_id == _role(db, "employee").id))
    rule.effect = "allow"                     # an administrator's decision
    db.commit()
    r = report([feature("task1", "Renamed")])
    assert r.status_code == 200
    assert _effects(db, "fieldapp:task1:use")["employee"] == "allow"
    assert _feature(db, "fieldapp", "task1").name == "Renamed", "the name follows the app"


def test_existing_rows_from_before_reports_are_existing_not_new(apps, db):
    """Engineering Tools' features and their role rules predate reports. When
    it reports them they gain a name and stay exactly as they were — nobody
    loses access, and nothing is marked New."""
    before = {k: _effects(db, f"engineering:hapext:{k}") for k in ("view", "configure")}
    r = report([feature("hapext", "HAP Extractor", ["view", "convert", "export", "configure"]),
                feature("airsizer", "AirSizer Pro", ["view", "convert", "export", "configure"]),
                feature("hapaudit", "HAP Audit", ["view", "convert", "export", "configure"]),
                feature("rebadge", "Rebadge", ["view", "convert", "export", "configure"])],
               app="engineering")
    assert r.json() == {"registered": 4, "new": 0, "not_reported": 0}
    assert {k: _effects(db, f"engineering:hapext:{k}") for k in ("view", "configure")} == before
    assert _effects(db, "engineering:hapext:configure")["employee"] == "deny"
    hapext = _feature(db, "engineering", "hapext")
    assert (hapext.name, hapext.is_new) == ("HAP Extractor", False)


def test_a_new_action_on_an_existing_feature_starts_switched_off(apps, db):
    report([feature("hapext", "HAP Extractor", ["view", "convert", "export", "configure", "use"])],
           app="engineering")
    assert _effects(db, "engineering:hapext:use")["employee"] == "deny"
    assert _effects(db, "engineering:hapext:use")["global_admin"] == "allow"
    assert _effects(db, "engineering:hapext:convert")["employee"] == "allow", "untouched"
    assert _feature(db, "engineering", "hapext").is_new is True


# ------------------------------------------------------------ gone quiet
def test_a_feature_no_longer_reported_is_marked_not_deleted(apps, db):
    report([feature("task1"), feature("task2")])
    r = report([feature("task1")])
    assert r.json() == {"registered": 1, "new": 0, "not_reported": 1}
    quiet = _feature(db, "fieldapp", "task2")
    assert quiet is not None and quiet.not_reported_since is not None
    assert _effects(db, "fieldapp:task2:use"), "its rules are kept"
    report([feature("task1"), feature("task2")])
    assert _feature(db, "fieldapp", "task2").not_reported_since is None, "back again"


# ------------------------------------------------------------ remove, retire
def test_only_an_unreported_feature_can_be_removed(apps, admin_client, db):
    report([feature("task1"), feature("task2")])
    r = admin_client.delete("/api/admin/features/fieldapp/task1",
                            headers={CSRF_HEADER: admin_client.csrf})
    assert r.status_code == 409 and "still reports" in r.json()["detail"]
    report([feature("task1")])
    r = admin_client.delete("/api/admin/features/fieldapp/task2",
                            headers={CSRF_HEADER: admin_client.csrf})
    assert r.status_code == 200, r.text
    assert _feature(db, "fieldapp", "task2") is None
    assert not _effects(db, "fieldapp:task2:use")
    assert db.scalar(select(func.count(Permission.id)).where(
        Permission.key == "fieldapp:task2:use")) == 0
    assert db.scalar(select(RetiredFeature.key)) == "task2"
    assert _rows(db, "features.remove") == 1


def test_remove_is_global_admin_only(apps, engineer_client, db):
    report([feature("task1"), feature("task2")])
    report([feature("task1")])
    r = engineer_client.delete("/api/admin/features/fieldapp/task2",
                               headers={CSRF_HEADER: engineer_client.csrf})
    assert r.status_code == 403
    assert _feature(db, "fieldapp", "task2") is not None


def test_removing_something_that_does_not_exist(apps, admin_client):
    h = {CSRF_HEADER: admin_client.csrf}
    assert admin_client.delete("/api/admin/features/nope/task1", headers=h).status_code == 404
    assert admin_client.delete("/api/admin/features/fieldapp/ghost", headers=h).status_code == 404


def test_a_retired_key_is_refused(apps, admin_client, db):
    report([feature("task1"), feature("task2")])
    report([feature("task1")])
    admin_client.delete("/api/admin/features/fieldapp/task2",
                        headers={CSRF_HEADER: admin_client.csrf})
    r = report([feature("task1"), feature("task2", "Something else")])
    assert r.status_code == 422
    assert "task2 was retired on" in r.json()["detail"]
    assert "can't be reused; use a new key." in r.json()["detail"]
    assert _feature(db, "fieldapp", "task2") is None


# ------------------------------------------------------------ monitoring
def test_the_monitoring_fields_follow_each_report(apps, admin_client, db):
    report([feature("task1"), feature("task2")], version="aaa111")
    report([feature("task1")], version="bbb222")
    app = _app(db, "fieldapp")
    db.refresh(app)
    assert app.features_version == "bbb222" and app.features_reported_at is not None
    assert app.features_report == {"total": 2, "new": 2, "not_reported": 1}
    line = next(a for a in admin_client.get("/api/admin/tool-rules").json()["applications"]
                if a["key"] == "fieldapp")
    assert (line["version"], line["features"], line["new"], line["not_reported"]) == (
        "bbb222", 2, 2, 1)
    assert line["reported_at"]


def test_the_grid_shows_names_and_marks(apps, admin_client, db):
    report([feature("task71", "Project Lead")])
    rows = {m["module_key"]: m for m in admin_client.get("/api/admin/tool-rules").json()["modules"]
            if m["application_key"] == "fieldapp"}
    assert rows["task71"]["name"] == "Project Lead" and rows["task71"]["is_new"] is True
    _grid(admin_client, "fieldapp", "task71", _role(db, "employee"), "no_access")
    rows = {m["module_key"]: m for m in admin_client.get("/api/admin/tool-rules").json()["modules"]
            if m["application_key"] == "fieldapp"}
    assert rows["task71"]["is_new"] is False, "a rule was changed on it"


# ------------------------------------------------------------ to the gate
def test_the_gate_answers_with_a_new_feature_once_it_is_switched_on(apps, admin_client, db):
    _seat_and_role(db, "fieldapp", "employee")
    report([feature("task71", "Project Lead")])
    cookie = _cookie()
    r = ask(cookie, "fieldapp")
    assert r.status_code == 403, "a role here, and nothing switched on for it"

    assert _grid(admin_client, "fieldapp", "task71", _role(db, "employee"), "full").status_code == 200
    r = ask(cookie, "fieldapp")
    assert r.status_code == 200 and r.json()["permissions"] == ["fieldapp:task71:use"]

    _grid(admin_client, "fieldapp", "task71", _role(db, "employee"), "no_access")
    assert ask(cookie, "fieldapp").status_code == 403, "off again, from the next request"


def test_each_feature_is_switched_independently(apps, admin_client, db):
    _seat_and_role(db, "fieldapp", "employee")
    report([feature("task1"), feature("task2"), feature("task3")])
    employee = _role(db, "employee")
    for key in ("task1", "task2", "task3"):
        _grid(admin_client, "fieldapp", key, employee, "full")
    _grid(admin_client, "fieldapp", "task2", employee, "no_access")
    body = ask(_cookie(), "fieldapp").json()
    assert body["permissions"] == ["fieldapp:task1:use", "fieldapp:task3:use"]
    assert body["nav_hidden"] == ["task2"]


# ------------------------------------------------------------ A4: scoped roles
def test_scoped_roles_give_each_app_its_own_keys(apps, admin_client, db):
    """Project Lead in Project Management, Normal User / Engineer in
    Engineering Tools: each app's gate answer carries only that app's role."""
    report([feature("task71", "Lead area"), feature("task72", "Engineer area")], app="projects")
    _grid(admin_client, "projects", "task71", _role(db, "project_lead"), "full")
    _grid(admin_client, "projects", "task72", _role(db, "employee"), "full")
    _seat_and_role(db, "projects", "project_lead")         # the engineer leads in PM
    cookie = _cookie()

    pm = ask(cookie, "projects").json()["permissions"]
    assert "projects:task71:use" in pm, "the Project Lead keys"
    assert "projects:task72:use" not in pm, "Engineer here only by a role that does not reach PM"

    et = ask(cookie, "engineering").json()["permissions"]
    assert "engineering:hapext:convert" in et
    assert "engineering:hapext:configure" not in et, "the Engineer keys only, not the Lead's"


def test_a_role_scoped_to_one_app_never_leaks_into_another(apps, db):
    cookie = _cookie()
    before = ask(cookie, "engineering").json()
    _seat_and_role(db, "projects", "business_admin")        # leads everything — in PM only
    after = ask(cookie, "engineering").json()
    assert after["permissions"] == before["permissions"]
    assert after["nav_hidden"] == before["nav_hidden"]
    assert not [k for k in after["permissions"] if not k.startswith("engineering:")]


# ------------------------------------------------------------ rate limit
@pytest.fixture
def limited():
    router_auth.limiter.reset()
    router_auth.limiter.enabled = True
    yield
    router_auth.limiter.enabled = False
    router_auth.limiter.reset()


def test_bad_secrets_are_limited_and_a_good_one_never_is(apps, limited):
    statuses = [report([feature("task1")], secret="z" * 43).status_code for _ in range(32)]
    assert statuses[0] == 403 and statuses[-1] == 429
    assert all(report([feature("task1")]).status_code == 200 for _ in range(35))
