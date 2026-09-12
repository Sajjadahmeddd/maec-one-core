"""Screen 003 — provisioning rules, and cards that tell the truth.

The two things worth the most attention: the Identity Provider card must not
claim a federation that does not exist, and authoring a rule must run the
same grant check as handing the role over by hand.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from backend.identity import accounts, admin_provisioning
from backend.identity.config import CSRF_HEADER
from backend.identity.models import (
    Application, AuditLog, ProvisioningMap, Role, User, UserLicense, UserRole,
)

from conftest import ADMIN_EMAIL

PROV = "/api/admin/provisioning"


def headers(client):
    return {CSRF_HEADER: client.csrf}


def db_user(db, email):
    return db.scalar(select(User).where(User.email == email))


def db_role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def make_rule(client, db, group="MAEC-Engineering", role="employee", **over):
    body = {"directory_group": group, "role_id": str(db_role(db, role).id),
            "default_modules": ["engineering"], "approval_type": "manual",
            "status": "active"}
    body.update(over)
    return client.post(PROV, headers=headers(client), json=body)


# ------------------------------------------------------- honest cards
def test_the_identity_provider_card_says_not_connected(admin_client):
    """Entra federation is not built. The card must not claim otherwise."""
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    idp = cards["identity_provider"]
    assert idp["value"] == "Not connected"
    assert idp["state"] == "inactive"
    assert idp["action"] == "Configure"
    # and nothing invented
    assert "142" not in str(idp)
    assert "SCIM" not in str(idp)


def test_the_card_is_derived_from_configuration_not_asserted(admin_client, monkeypatch):
    """It says Not connected because the settings are absent — so it will say
    otherwise when they are present, without this file being edited."""
    for name in admin_provisioning.IDP_SETTINGS:
        monkeypatch.setenv(name, "something")
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    assert cards["identity_provider"]["value"] == "Microsoft Entra ID"
    assert cards["identity_provider"]["state"] == "granted"


def test_a_partly_configured_provider_is_still_not_connected(admin_client, monkeypatch):
    monkeypatch.setenv(admin_provisioning.IDP_SETTINGS[0], "half")
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    assert cards["identity_provider"]["value"] == "Not connected"


def test_provisioning_mode_follows_from_the_provider(admin_client, monkeypatch):
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    assert cards["provisioning_mode"]["value"] == "Manual"
    assert "nothing is provisioned automatically" in \
        cards["provisioning_mode"]["detail"].lower()

    for name in admin_provisioning.IDP_SETTINGS:
        monkeypatch.setenv(name, "x")
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    assert cards["provisioning_mode"]["value"] == "Automatic"


def test_the_default_policy_is_least_privilege_and_names_the_real_role(admin_client):
    cards = {c["key"]: c for c in admin_client.get(PROV).json()["cards"]}
    policy = cards["default_access_policy"]
    assert policy["value"] == "Least Privilege"
    # the lowest-privilege seeded role, read from the database
    assert "Normal User / Engineer" in policy["detail"]
    assert "no application seats" in policy["detail"]


def test_there_are_exactly_three_cards(admin_client):
    cards = admin_client.get(PROV).json()["cards"]
    assert [c["key"] for c in cards] == [
        "identity_provider", "provisioning_mode", "default_access_policy"]


# ------------------------------------------------------------- the rules
def test_a_rule_can_be_authored_and_read_back(admin_client, db):
    created = make_rule(admin_client, db)
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["directory_group"] == "MAEC-Engineering"
    assert rule["role_key"] == "employee"
    assert rule["default_modules"] == ["engineering"]
    assert rule["module_names"] == ["Engineering Tools"]

    listed = admin_client.get(PROV).json()["rules"]
    assert len(listed) == 1 and listed[0]["id"] == rule["id"]


def test_a_rule_can_be_edited(admin_client, db):
    rule = make_rule(admin_client, db).json()
    r = admin_client.patch(f"{PROV}/{rule['id']}", headers=headers(admin_client),
                           json={"status": "disabled", "approval_type": "automatic"})
    assert r.status_code == 200
    assert r.json()["status"] == "disabled"
    assert r.json()["approval_type"] == "automatic"


def test_one_rule_per_group(admin_client, db):
    assert make_rule(admin_client, db).status_code == 201
    again = make_rule(admin_client, db)
    assert again.status_code == 409
    assert "already has a rule" in again.json()["detail"]


def test_a_module_the_organisation_does_not_subscribe_to_is_refused(admin_client, db):
    r = make_rule(admin_client, db, default_modules=["timesheet"])
    assert r.status_code == 422
    assert "does not subscribe" in r.json()["detail"]


def test_an_unknown_role_is_refused(admin_client, db):
    r = make_rule(admin_client, db)
    assert r.status_code == 201
    bad = admin_client.post(PROV, headers=headers(admin_client),
                            json={"directory_group": "Other",
                                  "role_id": str(uuid.uuid4()),
                                  "default_modules": []})
    assert bad.status_code == 422


@pytest.mark.parametrize("field,value", [
    ("approval_type", "telepathy"),
    ("status", "maybe"),
])
def test_unknown_enumerations_are_refused(admin_client, db, field, value):
    assert make_rule(admin_client, db, **{field: value}).status_code == 422


def test_authoring_a_rule_is_audited(admin_client, db):
    make_rule(admin_client, db)
    rows = db.scalars(select(AuditLog).where(
        AuditLog.action == "provisioning.rule")).all()
    assert rows and rows[0].actor_email == ADMIN_EMAIL
    assert rows[0].after["directory_group"] == "MAEC-Engineering"


# ----------------------------------------- a mapping is a deferred grant
def test_the_rule_runs_the_same_grant_check_as_a_manual_grant():
    """Not a second rule that agrees today — literally `accounts.may_grant`,
    the same function grant_role and the CSV import ask."""
    import inspect
    source = inspect.getsource(admin_provisioning._check_role)
    assert "accounts.may_grant" in source
    assert "accounts.placement_scope" in source


def test_an_author_cannot_write_a_rule_conferring_more_than_they_hold(db, identity):
    """A real Business Admin, genuinely lacking the grant — nothing mocked.

    The rule would not fire until federation exists, which is exactly why it
    has to be refused now: a rule nobody checks until it fires is a grant
    nobody reviewed.
    """
    from backend.identity import security

    admin = db_user(db, ADMIN_EMAIL)
    lead = User(org_id=admin.org_id, email="lead@mirageaec.com",
                display_name="Lead", status="active",
                password_hash=security.hash_password("Lead@2026"))
    db.add(lead)
    db.flush()
    db.add(UserRole(user_id=lead.id, role_id=db_role(db, "business_admin").id,
                    scope_type="application", scope_id="engineering"))
    db.add(UserLicense(user_id=lead.id, application_id=db.scalar(
        select(Application.id).where(Application.key == "engineering"))))
    # they need to be a Global Admin to reach the endpoint at all, so the
    # check is exercised where it lives rather than through a door they
    # cannot open
    db.commit()

    (scope_type, scope_id), problem = accounts.placement_scope(db, lead)
    assert problem is None and scope_type == "application"

    escalating = accounts.may_grant(
        db, actor=lead, target_org_id=lead.org_id,
        role=db_role(db, "global_admin"), scope_type=scope_type, scope_id=scope_id)
    assert escalating is not None          # refused

    ordinary = accounts.may_grant(
        db, actor=lead, target_org_id=lead.org_id,
        role=db_role(db, "employee"), scope_type=scope_type, scope_id=scope_id)
    assert ordinary is None                # permitted


def test_placement_scope_has_one_implementation():
    """The CSV import and a provisioning rule ask the same function."""
    import inspect

    from backend.identity import admin_import
    assert "accounts.placement_scope" in inspect.getsource(admin_import.plan)
    assert "accounts.placement_scope" in inspect.getsource(
        admin_provisioning._check_role)
    assert not hasattr(admin_import, "import_scope")   # no second copy left


# --------------------------------------------------------- the floor
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_an_engineer_is_refused(engineer_client, method):
    r = engineer_client.request(method, PROV, json={},
                                headers={CSRF_HEADER: engineer_client.csrf})
    assert r.status_code == 403


def test_a_stranger_is_refused(app_client):
    assert app_client.get(PROV).status_code == 401


def test_writing_without_csrf_is_refused(admin_client, db):
    r = admin_client.post(PROV, json={"directory_group": "X",
                                      "role_id": str(db_role(db, "employee").id)})
    assert r.status_code == 403


def test_a_rule_from_another_organisation_is_invisible(admin_client, db):
    from backend.identity.models import Organization
    other = Organization(name="Other", domain="other.example")
    db.add(other)
    db.flush()
    db.add(ProvisioningMap(org_id=other.id, directory_group="Theirs",
                           role_id=db_role(db, "employee").id, status="active"))
    db.commit()
    groups = [r["directory_group"] for r in admin_client.get(PROV).json()["rules"]]
    assert "Theirs" not in groups
