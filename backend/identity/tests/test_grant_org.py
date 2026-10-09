"""A role may only be granted inside the organisation it belongs to.

A custom role is one organisation's: its permissions were chosen there. The
grant route looked the role up by id and never asked whose it was, so a
Global Admin could hand a person in one tenant another tenant's custom role.
Built-in roles (no organisation) may be held anywhere.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from backend.identity import accounts
from backend.identity.config import CSRF_HEADER
from backend.identity.models import AuditLog, Organization, Role, User, UserRole

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

USERS = "/api/admin/users"


def _person(db, email) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == email))


def _foreign_role(db) -> Role:
    other = Organization(name="Other Firm", domain="other.example")
    db.add(other)
    db.flush()
    role = Role(key="their_reviewer", name="Their Reviewer", level=4,
                org_id=other.id, is_custom=True)
    db.add(role)
    db.commit()
    return role


def _grant(admin_client, person, role):
    return admin_client.post(f"{USERS}/{person.id}/roles",
                             headers={CSRF_HEADER: admin_client.csrf},
                             json={"role_id": str(role.id), "scope_type": "application",
                                   "scope_id": "engineering"})


def test_another_organisations_role_is_unknown_to_the_grant_route(admin_client, db):
    role = _foreign_role(db)
    engineer = _person(db, ENGINEER_EMAIL)
    r = _grant(admin_client, engineer, role)
    assert r.status_code == 422 and r.json()["detail"] == "Unknown role."
    assert db.scalar(select(UserRole).where(UserRole.role_id == role.id)) is None


def test_the_rule_itself_refuses_it_for_every_caller(identity, db):
    """may_grant is what the CSV import and provisioning ask too."""
    role = _foreign_role(db)
    admin, engineer = _person(db, ADMIN_EMAIL), _person(db, ENGINEER_EMAIL)
    why = accounts.may_grant(db, actor=admin, target_org_id=engineer.org_id, role=role,
                             scope_type="application", scope_id="engineering")
    assert why == "that role belongs to another organisation"

    with pytest.raises(accounts.EscalationError):
        accounts.grant_role(db, actor=admin, target=engineer, role=role,
                            scope_type="application", scope_id="engineering")
    db.expire_all()
    blocked = db.scalar(select(AuditLog).where(AuditLog.action == "role.grant",
                                               AuditLog.result == "blocked"))
    assert blocked.after["reason"] == "that role belongs to another organisation"


def test_this_organisations_custom_role_and_the_built_ins_still_grant(admin_client, db):
    made = admin_client.post("/api/admin/roles", headers={CSRF_HEADER: admin_client.csrf},
                             json={"name": "Site Reviewer"})
    assert made.status_code == 201
    engineer = _person(db, ENGINEER_EMAIL)
    ours = db.scalar(select(Role).where(Role.key == "site_reviewer"))
    lead = db.scalar(select(Role).where(Role.key == "project_lead", Role.org_id.is_(None)))
    assert _grant(admin_client, engineer, ours).status_code == 201
    assert _grant(admin_client, engineer, lead).status_code == 201
