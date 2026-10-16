"""Screens 001 and 002: the role scheme, and the Tool-Level Settings grid.

Since OPEN-DECISIONS #22 each cell of the grid is Full Access or No Access —
who may open the tool; what they may do in it is still the role's — and a
tool's Status can switch it off for the whole organisation.

These are integration tests through the real HTTP stack — the guard, the
Global Admin dependency and the CSRF check all run, because those are the
things that must not be bypassable.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from backend.identity.config import CSRF_HEADER
from backend.identity.models import (
    AuditLog, Permission, Role, ToolRule, ToolSetting, User, UserRole,
)
from backend.identity.permissions import can

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

ROLES = "/api/admin/roles"
TOOLS = "/api/admin/tool-rules"
STATUS = "/api/admin/tool-status"


def headers(client):
    return {CSRF_HEADER: client.csrf}


def role_named(body, key):
    return next(r for r in body["roles"] if r["key"] == key)


def db_role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def db_user(db, email):
    return db.scalar(select(User).where(User.email == email))


# ------------------------------------------------------- 001: reading
def test_roles_are_drawn_from_the_real_registry(admin_client):
    body = admin_client.get(ROLES).json()
    # qualified by application: module names are only unique within one
    assert body["modules"] == ["engineering:airsizer", "engineering:hapaudit",
                               "engineering:hapext", "engineering:rebadge", "projects:app"]
    assert body["actions"] == ["configure", "convert", "export", "view", "use"]
    # each module lists only the actions it actually has
    assert body["module_actions"]["engineering:hapext"] == [
        "configure", "convert", "export", "view"]
    assert body["module_actions"]["projects:app"] == ["use"]
    assert len(body["permissions"]) == 17          # 16 for Engineering Tools, 1 for PM
    assert {r["key"] for r in body["roles"]} == {
        "global_admin", "business_admin", "project_lead", "employee"}


def test_a_role_carries_its_real_allow_and_deny_rows(admin_client):
    employee = role_named(admin_client.get(ROLES).json(), "employee")
    assert employee["permissions"]["engineering:hapext:convert"] == "allow"
    assert employee["permissions"]["engineering:hapext:configure"] == "deny"
    assert employee["is_system"] is True
    assert employee["user_count"] == 1          # the seeded engineer


def test_the_badge_is_derived_not_invented(admin_client):
    body = admin_client.get(ROLES).json()
    assert role_named(body, "global_admin")["summary"]["engineering:hapext"] == "full"
    # the employee is allowed view/convert/export but denied configure
    assert role_named(body, "employee")["summary"]["engineering:hapext"] == "partial"
    # and on hapaudit only view is allowed
    assert role_named(body, "employee")["summary"]["engineering:hapaudit"] == "view"
    # Project Management's one module has one action, and every role holds it
    assert role_named(body, "employee")["summary"]["projects:app"] == "full"
    empty = admin_client.post(ROLES, headers=headers(admin_client), json={"name": "Empty"}).json()
    assert set(empty["summary"].values()) == {"none"}


# ------------------------------------------------------- 001: writing
def test_a_system_role_cannot_be_edited(admin_client, db):
    employee = db_role(db, "employee")
    r = admin_client.patch(f"{ROLES}/{employee.id}", headers=headers(admin_client),
                           json={"changes": [{"key": "engineering:hapext:configure",
                                              "effect": "allow"}]})
    assert r.status_code == 409
    assert "system role" in r.json()["detail"]


def test_a_custom_role_can_be_cloned_and_edited(admin_client, db):
    employee = db_role(db, "employee")
    r = admin_client.post(ROLES, headers=headers(admin_client),
                          json={"name": "Senior Engineer", "clone_from": str(employee.id)})
    assert r.status_code == 201, r.text
    clone = r.json()
    assert clone["is_custom"] is True and clone["is_system"] is False
    # the clone carried the employee's rows, including the deny
    assert clone["permissions"]["engineering:hapext:configure"] == "deny"

    r = admin_client.patch(f"{ROLES}/{clone['id']}", headers=headers(admin_client),
                           json={"changes": [{"key": "engineering:hapext:configure",
                                              "effect": "allow"}]})
    assert r.status_code == 200
    assert r.json()["permissions"]["engineering:hapext:configure"] == "allow"


def test_a_permission_can_be_cleared_back_to_silence(admin_client, db):
    employee = db_role(db, "employee")
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Temp", "clone_from": str(employee.id)}).json()
    r = admin_client.patch(f"{ROLES}/{clone['id']}", headers=headers(admin_client),
                           json={"changes": [{"key": "engineering:hapext:convert",
                                              "effect": None}]})
    assert "engineering:hapext:convert" not in r.json()["permissions"]


def test_a_role_still_held_cannot_be_deleted(admin_client, db):
    employee = db_role(db, "employee")
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Held Role", "clone_from": str(employee.id)}).json()
    engineer = db_user(db, ENGINEER_EMAIL)
    db.add(UserRole(user_id=engineer.id, role_id=uuid.UUID(clone["id"]),
                    scope_type="application", scope_id="engineering"))
    db.commit()

    r = admin_client.delete(f"{ROLES}/{clone['id']}", headers=headers(admin_client))
    assert r.status_code == 409
    assert "1 person" in r.json()["detail"]


def test_an_unheld_custom_role_can_be_deleted(admin_client, db):
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Unused"}).json()
    assert admin_client.delete(f"{ROLES}/{clone['id']}",
                               headers=headers(admin_client)).status_code == 200


def test_editing_a_role_bumps_everyone_holding_it(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    before = engineer.permissions_version
    employee = db_role(db, "employee")
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Bumped", "clone_from": str(employee.id)}).json()
    db.add(UserRole(user_id=engineer.id, role_id=uuid.UUID(clone["id"]),
                    scope_type="application", scope_id="engineering"))
    db.commit()

    admin_client.patch(f"{ROLES}/{clone['id']}", headers=headers(admin_client),
                       json={"changes": [{"key": "engineering:hapext:view",
                                          "effect": "deny"}]})
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version > before


def test_a_malformed_permission_key_is_refused(admin_client, db):
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Bad Key"}).json()
    r = admin_client.patch(f"{ROLES}/{clone['id']}", headers=headers(admin_client),
                           json={"changes": [{"key": "not-a-key", "effect": "allow"}]})
    assert r.status_code == 422


def test_an_unknown_permission_key_is_refused(admin_client, db):
    clone = admin_client.post(ROLES, headers=headers(admin_client),
                              json={"name": "Ghost"}).json()
    r = admin_client.patch(f"{ROLES}/{clone['id']}", headers=headers(admin_client),
                           json={"changes": [{"key": "engineering:hapext:teleport",
                                              "effect": "allow"}]})
    assert r.status_code == 422


# ------------------------------------------- 002: the grid decides
def _cell(client, tool, role):
    return client.get(TOOLS).json()["cells"][tool][str(role.id)]


def _put(client, module, role, level, application="engineering"):
    return client.put(TOOLS, headers=headers(client), json={"changes": [{
        "application_key": application, "module_key": module,
        "role_id": str(role.id), "access_level": level}]})


def _engineer_holds(db, role):
    """The seeded engineer's one grant now names this role."""
    engineer = db_user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.role_id = role.id
    db.commit()
    return engineer


def test_each_cell_is_reported_as_it_is_enforced(admin_client, db):
    employee = db_role(db, "employee")
    # nobody has set it: the role's own permissions, all or nothing
    assert _cell(admin_client, "engineering:hapext", employee) == {
        "access_level": "full", "set": False}
    assert _put(admin_client, "hapext", employee, "no_access").status_code == 200
    assert _cell(admin_client, "engineering:hapext", employee) == {
        "access_level": "no_access", "set": True}


def test_full_access_on_a_role_that_allows_nothing_is_refused(admin_client, db):
    """A cell never claims access that does not exist: Full Access for a role
    with no permissions in the tool would open nothing, so it is refused,
    audited, and nothing is stored."""
    it_admin = Role(key="it_admin", name="IT Admin", level=4, is_custom=True,
                    org_id=db_user(db, ADMIN_EMAIL).org_id)
    db.add(it_admin)
    db.commit()
    r = _put(admin_client, "hapext", it_admin, "full")
    assert r.status_code == 409
    assert "would open nothing" in r.json()["detail"]
    assert "User & Role Access" in r.json()["detail"]
    db.expire_all()
    assert db.scalar(select(ToolRule)) is None
    row = db.scalar(select(AuditLog).where(AuditLog.action == "tool_rule.set"))
    assert (row.result, row.target_id) == ("blocked", "engineering:hapext:it_admin")
    # No Access on it is fine: it takes away nothing, and says so
    assert _put(admin_client, "hapext", it_admin, "no_access").status_code == 200


def test_no_access_refuses_every_action_of_that_tool(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    assert _put(admin_client, "hapext", db_role(db, "employee"), "no_access").status_code == 200
    for action in ("view", "convert", "export", "configure"):
        assert can(db, engineer, f"engineering:hapext:{action}") is False, action
    assert can(db, engineer, "engineering:airsizer:convert") is True


def test_full_access_leaves_the_role_deciding_inside_the_tool(admin_client, db):
    """The grid says who may open the tool; the role says what they may do:
    an engineer with Full Access to HAPExt still may not configure it."""
    assert _put(admin_client, "hapext", db_role(db, "employee"), "full").status_code == 200
    engineer = db_user(db, ENGINEER_EMAIL)
    assert can(db, engineer, "engineering:hapext:convert") is True
    assert can(db, engineer, "engineering:hapext:configure") is False


@pytest.mark.parametrize("retired", ["view", "edit", "hidden", "partial"])
def test_only_full_and_no_access_are_accepted(admin_client, db, retired):
    r = _put(admin_client, "hapext", db_role(db, "employee"), retired)
    assert r.status_code == 422
    assert db.scalar(select(ToolRule)) is None


def test_a_set_with_an_unknown_target_persists_nothing(admin_client, db):
    """"Any rejection rejects the whole set", with more than one change: the
    first is valid, the second names a module that does not exist."""
    employee = db_role(db, "employee")
    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [
        {"application_key": "engineering", "module_key": "airsizer",
         "role_id": str(employee.id), "access_level": "no_access"},
        {"application_key": "engineering", "module_key": "ghost",
         "role_id": str(employee.id), "access_level": "full"},
    ]})
    assert r.status_code == 422
    db.expire_all()
    assert db.scalar(select(ToolRule)) is None
    assert not db.scalars(select(AuditLog).where(AuditLog.action == "tool_rule.set")).all()


def test_a_cell_change_is_audited(admin_client, db):
    _put(admin_client, "hapext", db_role(db, "employee"), "no_access")
    row = db.scalar(select(AuditLog).where(AuditLog.action == "tool_rule.set"))
    assert row.result == "success" and row.actor_email == ADMIN_EMAIL
    assert row.after["changes"] == [{"application": "engineering", "module": "hapext",
                                     "role": "employee", "access_level": "no_access"}]


# ------------------------------------------------- 002: the Status column
def _status(client, module, status, application="engineering"):
    return client.put(STATUS, headers=headers(client), json={
        "application_key": application, "module_key": module, "status": status})


def test_inactive_switches_a_tool_off_for_everyone(admin_client, db):
    engineer, admin = db_user(db, ENGINEER_EMAIL), db_user(db, ADMIN_EMAIL)
    r = _status(admin_client, "hapext", "inactive")
    assert r.status_code == 200, r.text

    for person in (engineer, admin):        # a Global Admin included
        assert can(db, person, "engineering:hapext:view") is False
        assert can(db, person, "engineering:airsizer:view") is True
    statuses = {m["module_key"]: m["status"] for m in admin_client.get(TOOLS).json()["modules"]}
    assert statuses["hapext"] == "inactive" and statuses["airsizer"] == "active"

    # even a Full Access cell does not reach through a switched-off tool
    _put(admin_client, "hapext", db_role(db, "employee"), "full")
    assert can(db, engineer, "engineering:hapext:view") is False

    assert _status(admin_client, "hapext", "active").status_code == 200
    assert can(db, engineer, "engineering:hapext:view") is True


def test_a_status_change_is_audited_and_bumps_everyone(admin_client, db):
    before = db_user(db, ENGINEER_EMAIL).permissions_version
    _status(admin_client, "rebadge", "inactive")
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version > before
    row = db.scalar(select(AuditLog).where(AuditLog.action == "tool_status.set"))
    assert (row.before, row.after["status"]) == ({"module": "rebadge", "status": "active"},
                                                 "inactive")
    assert db.scalar(select(ToolSetting)).status == "inactive"


@pytest.mark.parametrize("module,status", [("ghost", "inactive"), ("hapext", "paused")])
def test_a_bad_status_change_is_refused(admin_client, db, module, status):
    assert _status(admin_client, module, status).status_code == 422
    assert db.scalar(select(ToolSetting)) is None


def test_the_status_is_global_admin_only(engineer_client):
    r = engineer_client.put(STATUS, headers={CSRF_HEADER: engineer_client.csrf}, json={
        "application_key": "engineering", "module_key": "hapext", "status": "inactive"})
    assert r.status_code == 403


def test_a_refused_role_edit_does_not_commit_the_rename(db):
    """patch_role checks every change before writing any — the rename included.

    Unreachable over HTTP: the router is Global Admin only, and a Global Admin
    holds everything. So the route function is called directly with a
    narrower actor, which is the day this exists for.
    """
    from fastapi import HTTPException
    from backend.identity.admin_roles import PermissionChange, RolePatch, patch_role

    engineer = db_user(db, ENGINEER_EMAIL)
    custom = Role(key="renamable", name="Renamable", level=4,
                  org_id=engineer.org_id, is_custom=True)
    db.add(custom)
    # the engineer must not hold what the patch grants: No Access on hapext
    db.add(ToolRule(org_id=engineer.org_id, module_key="hapext",
                    application_id=db.scalar(select(Permission.application_id).where(
                        Permission.key == "engineering:hapext:configure")),
                    role_id=db_role(db, "employee").id, access_level="no_access"))
    db.commit()

    body = RolePatch(name="Renamed", changes=[
        PermissionChange(key="engineering:hapext:configure", effect="allow")])
    with pytest.raises(HTTPException) as refused:
        patch_role(custom.id, body, None, db, engineer)
    assert refused.value.status_code == 403

    db.rollback()                                    # what closing the request does
    db.expire_all()
    assert db.get(Role, custom.id).name == "Renamable"


def test_a_rule_can_be_cleared(admin_client, db):
    employee = db_role(db, "employee")
    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": "no_access"}]})
    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": None}]})
    assert r.status_code == 200
    assert db.scalar(select(ToolRule)) is None


def test_setting_a_rule_bumps_the_holders(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    before = engineer.permissions_version
    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(db_role(db, "employee").id), "access_level": "no_access"}]})
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version > before


def test_clearing_a_rule_bumps_the_holders_too(admin_client, db):
    """Clearing a rule changes access as surely as setting one — here it
    lifts a no_access. Under the token design the version is how a product
    learns its tool-rule claims are stale, so a clear that did not bump would
    leave the removed rule enforced for the token's whole lifetime."""
    rule = {"application_key": "engineering", "module_key": "hapext",
            "role_id": str(db_role(db, "employee").id)}
    assert admin_client.put(TOOLS, headers=headers(admin_client), json={
        "changes": [{**rule, "access_level": "no_access"}]}).status_code == 200
    db.expire_all()
    before = db_user(db, ENGINEER_EMAIL).permissions_version

    assert admin_client.put(TOOLS, headers=headers(admin_client), json={
        "changes": [{**rule, "access_level": None}]}).status_code == 200
    db.expire_all()
    cleared = db_user(db, ENGINEER_EMAIL).permissions_version
    assert cleared > before

    # clearing a rule that no longer exists changes nobody's access: no bump
    assert admin_client.put(TOOLS, headers=headers(admin_client), json={
        "changes": [{**rule, "access_level": None}]}).status_code == 200
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version == cleared


def test_the_matrix_lists_the_real_modules(admin_client):
    body = admin_client.get(TOOLS).json()
    assert [(m["application_key"], m["module_key"]) for m in body["modules"]] == [
        ("engineering", "airsizer"), ("projects", "app"), ("engineering", "hapaudit"),
        ("engineering", "hapext"), ("engineering", "rebadge")]
    assert [lvl["key"] for lvl in body["levels"]] == ["full", "no_access"]
    assert [s["key"] for s in body["statuses"]] == ["active", "inactive"]


@pytest.mark.parametrize("bad", [
    {"application_key": "nope", "module_key": "hapext", "access_level": "no_access"},
    {"application_key": "engineering", "module_key": "ghost", "access_level": "no_access"},
])
def test_unknown_targets_are_refused(admin_client, db, bad):
    bad = {**bad, "role_id": str(db_role(db, "employee").id)}
    assert admin_client.put(TOOLS, headers=headers(admin_client),
                            json={"changes": [bad]}).status_code == 422


def test_an_unknown_level_is_refused(admin_client, db):
    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(db_role(db, "employee").id), "access_level": "superuser"}]})
    assert r.status_code == 422


# --------------------------------------------------- authorization floor
@pytest.mark.parametrize("method,path", [
    ("GET", ROLES), ("POST", ROLES), ("GET", TOOLS), ("PUT", TOOLS),
])
def test_an_engineer_is_refused_every_admin_route(engineer_client, method, path):
    r = engineer_client.request(method, path, json={}, headers={CSRF_HEADER: engineer_client.csrf})
    assert r.status_code == 403


@pytest.mark.parametrize("method,path", [
    ("GET", ROLES), ("POST", ROLES), ("GET", TOOLS), ("PUT", TOOLS),
])
def test_a_stranger_is_refused_every_admin_route(app_client, method, path):
    assert app_client.request(method, path, json={}).status_code == 401


@pytest.mark.parametrize("method,path", [
    ("POST", ROLES), ("PUT", TOOLS),
])
def test_a_mutation_without_csrf_is_refused(admin_client, method, path):
    r = admin_client.request(method, path, json={"name": "x", "changes": []})
    assert r.status_code == 403
    assert "CSRF" in r.json()["detail"]


def test_each_tool_row_carries_its_applications_status(admin_client):
    """Tool-Level Settings shows Active for a live application's tools and
    In-Active for one still coming soon — read from the registry."""
    modules = admin_client.get("/api/admin/tool-rules").json()["modules"]
    status = {(m["application_key"], m["module_key"]): m["application_status"]
              for m in modules}
    assert status[("engineering", "hapext")] == "live"
    assert status[("projects", "app")] == "coming_soon"
