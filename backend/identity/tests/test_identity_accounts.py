"""The rules a change to a person must obey: non-escalation and never
removing the last Global Admin. Plus the audit trail those produce."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from backend.identity import accounts
from backend.identity.models import AuditLog, Role, User, UserRole
from backend.identity.permissions import can, is_global_admin

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL


def user(db, email) -> User:
    return db.scalar(select(User).where(User.email == email))


def role(db, key) -> Role:
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def audit_rows(db, action, result=None):
    query = select(AuditLog).where(AuditLog.action == action)
    if result:
        query = query.where(AuditLog.result == result)
    return db.scalars(query).all()


# ------------------------------------------------------- the last admin
def test_the_last_global_admin_cannot_lose_the_role(db):
    admin = user(db, ADMIN_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == admin.id))
    with pytest.raises(accounts.LastGlobalAdminError, match="last Global Admin"):
        accounts.revoke_role(db, actor=admin, grant=grant)
    assert is_global_admin(db, user(db, ADMIN_EMAIL)) is True
    assert len(audit_rows(db, "role.revoke", "blocked")) == 1


def test_the_last_global_admin_cannot_be_suspended(db):
    admin = user(db, ADMIN_EMAIL)
    with pytest.raises(accounts.LastGlobalAdminError):
        accounts.set_user_status(db, actor=admin, target=admin, status="suspended")
    assert user(db, ADMIN_EMAIL).status == "active"


def test_the_last_global_admin_cannot_be_deleted(db):
    admin = user(db, ADMIN_EMAIL)
    with pytest.raises(accounts.LastGlobalAdminError):
        accounts.delete_user(db, actor=admin, target=admin)
    assert user(db, ADMIN_EMAIL) is not None


def test_with_a_second_admin_the_first_can_step_down(db):
    """The model supports a second Global Admin with no schema change."""
    admin, engineer = user(db, ADMIN_EMAIL), user(db, ENGINEER_EMAIL)
    accounts.grant_role(db, actor=admin, target=engineer, role=role(db, "global_admin"),
                        scope_type="platform", scope_id=None)
    assert is_global_admin(db, user(db, ENGINEER_EMAIL)) is True

    grant = db.scalar(select(UserRole).where(
        UserRole.user_id == admin.id, UserRole.scope_type == "platform"))
    accounts.revoke_role(db, actor=engineer, grant=grant)
    assert is_global_admin(db, user(db, ADMIN_EMAIL)) is False
    assert is_global_admin(db, user(db, ENGINEER_EMAIL)) is True


def test_an_ordinary_user_being_suspended_is_fine(db):
    admin, engineer = user(db, ADMIN_EMAIL), user(db, ENGINEER_EMAIL)
    accounts.set_user_status(db, actor=admin, target=engineer, status="suspended")
    assert user(db, ENGINEER_EMAIL).status == "suspended"
    assert can(db, user(db, ENGINEER_EMAIL), "engineering:hapext:convert") is False


# ------------------------------------------------------- non-escalation
def test_an_engineer_cannot_make_anyone_a_global_admin(db):
    engineer = user(db, ENGINEER_EMAIL)
    admin = user(db, ADMIN_EMAIL)
    with pytest.raises(accounts.EscalationError):
        accounts.grant_role(db, actor=engineer, target=admin,
                            role=role(db, "global_admin"),
                            scope_type="platform", scope_id=None)
    blocked = audit_rows(db, "role.grant", "blocked")
    assert len(blocked) == 1
    assert blocked[0].actor_email == ENGINEER_EMAIL


def test_an_engineer_cannot_hand_out_their_own_role_either(db):
    """Same level is not above; only someone above may place people."""
    engineer = user(db, ENGINEER_EMAIL)
    with pytest.raises(accounts.EscalationError):
        accounts.grant_role(db, actor=engineer, target=engineer,
                            role=role(db, "employee"),
                            scope_type="project", scope_id="P-1")


def test_a_lead_may_only_grant_what_they_themselves_hold(db):
    """A project lead placed on Engineering Tools can add an engineer to a
    project — but not grant a role carrying a permission the lead lacks."""
    admin, engineer = user(db, ADMIN_EMAIL), user(db, ENGINEER_EMAIL)
    lead = User(org_id=admin.org_id, email="lead@mirageaec.com", display_name="Lead",
                password_hash="x", status="active")
    db.add(lead)
    db.flush()
    from backend.identity.models import Application, UserLicense
    eng_app = db.scalar(select(Application).where(Application.key == "engineering"))
    db.add(UserLicense(user_id=lead.id, application_id=eng_app.id))
    db.add(UserRole(user_id=lead.id, role_id=role(db, "project_lead").id,
                    scope_type="application", scope_id="engineering"))
    db.commit()

    # employee is below project_lead and every employee permission is one
    # the lead holds: allowed
    accounts.grant_role(db, actor=lead, target=engineer, role=role(db, "employee"),
                        scope_type="project", scope_id="P-2291")

    # business_admin sits above the lead: refused, and recorded
    with pytest.raises(accounts.EscalationError):
        accounts.grant_role(db, actor=lead, target=engineer, role=role(db, "business_admin"),
                            scope_type="application", scope_id="engineering")
    assert audit_rows(db, "role.grant", "blocked")


def test_a_refused_grant_inside_a_callers_transaction_commits_nothing(db):
    """commit=False means the caller owns the unit of work — the CSV import
    creates a person and grants them a role together. A refusal inside it
    must not commit what the caller wrote before it.

    `_refuse` used to audit with its own commit whatever the caller asked, so
    the half-made person below was persisted by the very refusal meant to stop
    the import. Unreachable through the import today — only a Global Admin
    can run it, and may_grant never refuses one — but the shape was wrong.
    """
    admin, engineer = user(db, ADMIN_EMAIL), user(db, ENGINEER_EMAIL)
    person = accounts.create_user(db, actor=admin, email="half-made@mirageaec.com",
                                  display_name="Half Made", password="Pending@2026",
                                  commit=False)
    with pytest.raises(accounts.EscalationError):
        accounts.grant_role(db, actor=engineer, target=person,
                            role=role(db, "global_admin"),
                            scope_type="platform", scope_id=None, commit=False)
    db.rollback()                                        # what the caller does
    assert user(db, "half-made@mirageaec.com") is None


def test_a_successful_grant_bumps_the_target_and_is_recorded(db):
    admin, engineer = user(db, ADMIN_EMAIL), user(db, ENGINEER_EMAIL)
    before = engineer.permissions_version
    accounts.grant_role(db, actor=admin, target=engineer, role=role(db, "project_lead"),
                        scope_type="project", scope_id="P-2291")
    assert user(db, ENGINEER_EMAIL).permissions_version == before + 1
    rows = audit_rows(db, "role.grant", "success")
    assert rows and rows[0].actor_email == ADMIN_EMAIL
    assert rows[0].after == {"role": "project_lead", "scope_type": "project", "scope_id": "P-2291"}
