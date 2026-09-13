"""Screens 001 and 002: the role scheme, and the per-organisation overrides.

These are integration tests through the real HTTP stack — the guard, the
Global Admin dependency and the CSRF check all run, because those are the
things that must not be bypassable.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from backend.identity import permissions as perms
from backend.identity.config import CSRF_HEADER
from backend.identity.models import (
    Permission, Role, ToolRule, User, UserRole,
)
from backend.identity.permissions import can

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

ROLES = "/api/admin/roles"
TOOLS = "/api/admin/tool-rules"


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
    assert body["modules"] == ["airsizer", "hapaudit", "hapext", "rebadge"]
    assert body["actions"] == ["configure", "convert", "export", "view"]
    assert len(body["permissions"]) == 16
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
    assert role_named(body, "global_admin")["summary"]["hapext"] == "full"
    # the employee is allowed view/convert/export but denied configure
    assert role_named(body, "employee")["summary"]["hapext"] == "partial"
    # and on hapaudit only view is allowed
    assert role_named(body, "employee")["summary"]["hapaudit"] == "view"


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


# --------------------------------------------------- 002: the two rules
def test_the_api_reports_which_rules_hide_and_which_block(admin_client, db):
    """The contract a navigation would have to read.

    `hides_from_nav` and `blocks_api` are what make the two levels
    distinguishable to a consumer. Asserting them here — rather than that a
    constant contains a string — is the difference between testing the
    behaviour and testing the spelling.

    Core draws no module navigation, so the reader of this contract is the
    product's own. Under the token design the product receives the tool
    rules and applies HIDES_FROM_NAV itself. See OPEN-DECISIONS #3.
    """
    employee = db_role(db, "employee")
    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapaudit",
        "role_id": str(employee.id), "access_level": "hidden"}]})

    cell = admin_client.get(TOOLS).json()["rules"]["engineering:hapaudit"][str(employee.id)]
    assert cell["access_level"] == "hidden"
    assert cell["hides_from_nav"] is True
    assert cell["blocks_api"] is False           # hidden is not a boundary

    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapaudit",
        "role_id": str(employee.id), "access_level": "no_access"}]})
    cell = admin_client.get(TOOLS).json()["rules"]["engineering:hapaudit"][str(employee.id)]
    assert cell["hides_from_nav"] is True
    assert cell["blocks_api"] is True            # no_access is


def test_hidden_and_no_access_are_stored_and_enforced_differently(db):
    """The distinction this screen exists to preserve.

    hidden  -> gone from the navigation, API still answers (decluttering)
    no_access -> API refuses (the boundary)
    """
    engineer = db_user(db, ENGINEER_EMAIL)
    app_id = db.scalar(select(Permission.application_id).where(
        Permission.key == "engineering:hapext:convert"))
    employee = db_role(db, "employee")

    rule = ToolRule(org_id=engineer.org_id, application_id=app_id,
                    module_key="hapext", role_id=employee.id, access_level="hidden")
    db.add(rule)
    db.commit()
    assert can(db, engineer, "engineering:hapext:convert") is True     # still permitted
    assert "hidden" in perms.HIDES_FROM_NAV                           # but not shown

    rule.access_level = "no_access"
    db.commit()
    assert can(db, engineer, "engineering:hapext:convert") is False    # now refused
    assert "no_access" in perms.HIDES_FROM_NAV


def test_a_view_rule_narrows_to_view_only(db):
    engineer = db_user(db, ENGINEER_EMAIL)
    app_id = db.scalar(select(Permission.application_id).where(
        Permission.key == "engineering:hapext:view"))
    db.add(ToolRule(org_id=engineer.org_id, application_id=app_id, module_key="hapext",
                    role_id=db_role(db, "employee").id, access_level="view"))
    db.commit()
    assert can(db, engineer, "engineering:hapext:view") is True
    assert can(db, engineer, "engineering:hapext:convert") is False


def test_a_tool_rule_cannot_grant_what_the_role_denies(admin_client, db):
    """The employee is denied configure on hapext. 'full' implies configure,
    so the write is refused rather than stored as a rule that does nothing."""
    employee = db_role(db, "employee")
    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": "full"}]})
    assert r.status_code == 409
    assert "can only take access away" in r.json()["detail"]
    assert db.scalar(select(ToolRule)) is None            # nothing was written


def test_a_narrower_level_is_accepted(admin_client, db):
    employee = db_role(db, "employee")
    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": "view"}]})
    assert r.status_code == 200, r.text
    assert r.json()["users_affected"] == 1
    stored = db.scalar(select(ToolRule))
    assert stored.access_level == "view" and stored.status == "active"


def test_an_edit_rule_is_accepted_and_removes_configuration(admin_client, db):
    """The administrator's intent, end to end: the write goes through because
    the role grants everything `edit` implies, and configuration is then gone
    rather than silently kept."""
    lead = db_role(db, "business_admin")
    engineer = db_user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.role_id = lead.id
    db.commit()

    r = admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(lead.id), "access_level": "edit"}]})
    assert r.status_code == 200, r.text

    db.expire_all()
    engineer = db_user(db, ENGINEER_EMAIL)
    assert can(db, engineer, "engineering:hapext:convert") is True
    assert can(db, engineer, "engineering:hapext:configure") is False


def test_the_blocked_write_is_audited(admin_client, db):
    from backend.identity.models import AuditLog
    employee = db_role(db, "employee")
    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": "full"}]})
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "tool_rule.set",
                                             AuditLog.result == "blocked")).all()
    assert rows and rows[0].actor_email == ADMIN_EMAIL


def test_a_rule_can_be_cleared(admin_client, db):
    employee = db_role(db, "employee")
    admin_client.put(TOOLS, headers=headers(admin_client), json={"changes": [{
        "application_key": "engineering", "module_key": "hapext",
        "role_id": str(employee.id), "access_level": "view"}]})
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
        "role_id": str(db_role(db, "employee").id), "access_level": "view"}]})
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version > before


def test_the_matrix_lists_the_real_modules(admin_client):
    body = admin_client.get(TOOLS).json()
    assert [m["module_key"] for m in body["modules"]] == [
        "airsizer", "hapaudit", "hapext", "rebadge"]
    assert all(m["application_key"] == "engineering" for m in body["modules"])
    levels = {lvl["key"] for lvl in body["levels"]}
    assert levels == {"full", "edit", "view", "hidden", "no_access"}


@pytest.mark.parametrize("bad", [
    {"application_key": "nope", "module_key": "hapext", "access_level": "view"},
    {"application_key": "engineering", "module_key": "ghost", "access_level": "view"},
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
