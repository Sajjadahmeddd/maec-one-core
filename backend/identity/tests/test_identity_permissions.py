"""The permission engine.

Every case the brief names, plus the fail-closed edges around them. These
run on the seeded database: a Global Admin at platform scope and an engineer
holding `employee` at application scope on Engineering Tools.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend.identity import permissions
from backend.identity.models import (
    Application, Permission, Role, RolePermission, Subscription, ToolRule,
    User, UserLicense, UserRole,
)
from backend.identity.permissions import bump_permissions_version, can, is_global_admin

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

CONVERT = "engineering:hapext:convert"
CONFIGURE = "engineering:hapext:configure"
AUDIT_VIEW = "engineering:hapaudit:view"
AUDIT_EXPORT = "engineering:hapaudit:export"


def user(db, email) -> User:
    return db.scalar(select(User).where(User.email == email))


def role(db, key) -> Role:
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def permission(db, key) -> Permission:
    return db.scalar(select(Permission).where(Permission.key == key))


def app(db, key="engineering") -> Application:
    return db.scalar(select(Application).where(Application.key == key))


# ------------------------------------------------------------- the key
def test_a_key_is_exactly_three_parts():
    assert permissions.split_key("engineering:hapext:convert") == ("engineering", "hapext", "convert")
    for bad in ("engineering:hapext", "a:b:c:d", "::", "engineering::convert", ""):
        with pytest.raises(ValueError):
            permissions.split_key(bad)


# ---------------------------------------------------------- the seeded state
def test_the_seed_gives_the_engineer_the_tools_but_not_configuration(db):
    engineer = user(db, ENGINEER_EMAIL)
    assert can(db, engineer, CONVERT) is True
    assert can(db, engineer, "engineering:airsizer:export") is True
    assert can(db, engineer, CONFIGURE) is False          # explicit deny row
    assert can(db, engineer, AUDIT_VIEW) is True
    assert can(db, engineer, AUDIT_EXPORT) is False


def test_the_global_admin_can_do_everything_seeded(db):
    admin = user(db, ADMIN_EMAIL)
    for key in (CONVERT, CONFIGURE, AUDIT_EXPORT, "engineering:rebadge:configure"):
        assert can(db, admin, key) is True
    assert is_global_admin(db, admin) is True
    assert is_global_admin(db, user(db, ENGINEER_EMAIL)) is False


# ----------------------------------------------------------- entitlement
def test_an_unentitled_app_is_refused_before_roles_are_even_read(db):
    """No seat, no access — whatever roles say."""
    engineer = user(db, ENGINEER_EMAIL)
    seat = db.scalar(select(UserLicense).where(UserLicense.user_id == engineer.id))
    db.delete(seat)
    db.commit()
    assert can(db, engineer, CONVERT) is False


def test_an_expired_subscription_refuses_everyone_including_the_admin(db):
    sub = db.scalar(select(Subscription))
    sub.valid_to = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()
    assert can(db, user(db, ADMIN_EMAIL), CONVERT) is False
    assert can(db, user(db, ENGINEER_EMAIL), CONVERT) is False


def test_a_subscription_that_has_not_started_refuses(db):
    sub = db.scalar(select(Subscription))
    sub.valid_from = datetime.now(timezone.utc) + timedelta(days=1)
    db.commit()
    assert can(db, user(db, ENGINEER_EMAIL), CONVERT) is False


def test_an_app_with_no_subscription_refuses(db):
    admin = user(db, ADMIN_EMAIL)
    timesheet = app(db, "timesheet")
    db.add(UserLicense(user_id=admin.id, application_id=timesheet.id))
    db.add(Permission(key="timesheet:sheet:view", application_id=timesheet.id,
                      module_key="sheet", action="view"))
    db.commit()
    assert can(db, admin, "timesheet:sheet:view") is False


# ----------------------------------------------------------------- roles
def test_an_expired_role_counts_for_nothing(db):
    engineer = user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    assert can(db, engineer, CONVERT) is False


def test_a_role_expiring_later_still_counts(db):
    engineer = user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()
    assert can(db, engineer, CONVERT) is True


def test_a_role_scoped_to_another_application_does_not_reach_this_one(db):
    engineer = user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.scope_id = "timesheet"
    db.commit()
    assert can(db, engineer, CONVERT) is False


def test_a_project_scoped_role_reaches_only_that_project(db):
    engineer = user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.scope_type, grant.scope_id = "project", "P-2291"
    db.commit()
    assert can(db, engineer, CONVERT, scope=("project", "P-2291")) is True
    assert can(db, engineer, CONVERT, scope=("project", "P-9999")) is False
    assert can(db, engineer, CONVERT) is False       # an application-level ask


def test_an_organization_scoped_role_reaches_its_own_organisation_only(db):
    engineer = user(db, ENGINEER_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == engineer.id))
    grant.scope_type, grant.scope_id = "organization", str(engineer.org_id)
    db.commit()
    assert can(db, engineer, CONVERT) is True
    grant.scope_id = "00000000-0000-0000-0000-000000000000"
    db.commit()
    assert can(db, engineer, CONVERT) is False


# --------------------------------------------------------------- resolve
def test_deny_beats_allow_at_equal_specificity(db):
    """Two roles at the same scope, one allowing and one denying: no."""
    engineer = user(db, ENGINEER_EMAIL)
    lead = role(db, "project_lead")               # allows convert
    db.add(UserRole(user_id=engineer.id, role_id=lead.id,
                    scope_type="application", scope_id="engineering"))
    db.commit()
    assert can(db, engineer, CONVERT) is True     # both allow so far

    denier = Role(key="no_convert", name="No Convert", level=4, org_id=engineer.org_id,
                  is_custom=True)
    db.add(denier)
    db.flush()
    db.add(RolePermission(role_id=denier.id, permission_id=permission(db, CONVERT).id,
                          effect="deny"))
    db.add(UserRole(user_id=engineer.id, role_id=denier.id,
                    scope_type="application", scope_id="engineering"))
    db.commit()
    assert can(db, engineer, CONVERT) is False


def test_a_project_scope_overrides_an_application_scope(db):
    """The more specific grant wins, whichever way round it goes."""
    engineer = user(db, ENGINEER_EMAIL)            # employee @ application: allow convert
    denier = Role(key="no_convert_here", name="No Convert Here", level=4,
                  org_id=engineer.org_id, is_custom=True)
    db.add(denier)
    db.flush()
    db.add(RolePermission(role_id=denier.id, permission_id=permission(db, CONVERT).id,
                          effect="deny"))
    db.add(UserRole(user_id=engineer.id, role_id=denier.id,
                    scope_type="project", scope_id="P-2291"))
    db.commit()

    # on that project the project-level deny beats the application-level allow
    assert can(db, engineer, CONVERT, scope=("project", "P-2291")) is False
    # on another project only the application-level allow applies
    assert can(db, engineer, CONVERT, scope=("project", "P-1000")) is True

    # and the other way: application denies, project allows -> allowed there
    app_grant = db.scalar(select(UserRole).where(
        UserRole.user_id == engineer.id, UserRole.scope_type == "application"))
    app_grant.role_id = denier.id
    proj_grant = db.scalar(select(UserRole).where(
        UserRole.user_id == engineer.id, UserRole.scope_type == "project"))
    proj_grant.role_id = role(db, "employee").id
    db.commit()
    assert can(db, engineer, CONVERT, scope=("project", "P-2291")) is True
    assert can(db, engineer, CONVERT, scope=("project", "P-1000")) is False


def test_a_permission_nobody_mentions_is_refused(db):
    engineer = user(db, ENGINEER_EMAIL)
    db.add(Permission(key="engineering:hapext:delete", application_id=app(db).id,
                      module_key="hapext", action="delete"))
    db.commit()
    assert can(db, engineer, "engineering:hapext:delete") is False


def test_an_unknown_permission_is_refused(db):
    assert can(db, user(db, ADMIN_EMAIL), "engineering:hapext:teleport") is False


# ------------------------------------------------------------ tool rules
def test_a_no_access_tool_rule_takes_a_module_away(db):
    """`no_access` is the security boundary: the API refuses.

    This test used to assert the same of `hidden`. It no longer does, because
    the two were deliberately split — see the test below, and screen 002.
    """
    engineer = user(db, ENGINEER_EMAIL)
    db.add(ToolRule(org_id=engineer.org_id, application_id=app(db).id, module_key="hapext",
                    role_id=role(db, "employee").id, access_level="no_access"))
    db.commit()
    assert can(db, engineer, CONVERT) is False
    assert can(db, engineer, "engineering:airsizer:convert") is True   # other modules untouched


def test_a_hidden_tool_rule_does_not_block_the_api(db):
    """`hidden` is navigation only, and that is the point of having both.

    A team that simply does not use a tool should not see it; a team that
    must not reach it needs `no_access`. Conflating them either clutters the
    navigation or ships a boundary that is not one.
    """
    engineer = user(db, ENGINEER_EMAIL)
    db.add(ToolRule(org_id=engineer.org_id, application_id=app(db).id, module_key="hapext",
                    role_id=role(db, "employee").id, access_level="hidden"))
    db.commit()
    assert can(db, engineer, CONVERT) is True
    assert "hidden" in permissions.HIDES_FROM_NAV       # gone from the nav all the same


def test_a_view_only_tool_rule_keeps_view_and_nothing_else(db):
    engineer = user(db, ENGINEER_EMAIL)
    db.add(ToolRule(org_id=engineer.org_id, application_id=app(db).id, module_key="hapext",
                    role_id=role(db, "employee").id, access_level="view"))
    db.commit()
    assert can(db, engineer, "engineering:hapext:view") is True
    assert can(db, engineer, CONVERT) is False


def test_a_tool_rule_cannot_grant_what_the_role_denies(db):
    """`full` on a module does not turn the employee's configure deny into an allow."""
    engineer = user(db, ENGINEER_EMAIL)
    db.add(ToolRule(org_id=engineer.org_id, application_id=app(db).id, module_key="hapext",
                    role_id=role(db, "employee").id, access_level="full"))
    db.commit()
    assert can(db, engineer, CONFIGURE) is False
    assert can(db, engineer, AUDIT_EXPORT) is False


def test_a_tool_rule_for_another_organisation_does_not_apply(db):
    engineer = user(db, ENGINEER_EMAIL)
    from backend.identity.models import Organization
    other = Organization(name="Other Co", domain="other.example")
    db.add(other)
    db.flush()
    db.add(ToolRule(org_id=other.id, application_id=app(db).id, module_key="hapext",
                    role_id=role(db, "employee").id, access_level="no_access"))
    db.commit()
    assert can(db, engineer, CONVERT) is True


# ------------------------------------------------------------ fail closed
def test_no_user_is_refused(db):
    assert can(db, None, CONVERT) is False


def test_a_suspended_user_is_refused(db):
    admin = user(db, ADMIN_EMAIL)
    admin.status = "suspended"
    db.commit()
    assert can(db, admin, CONVERT) is False


def test_a_database_failure_refuses_rather_than_raising(db):
    """Anything going wrong is a no, never an exception and never a yes.

    Every layer is checked separately: a failure inside the entitlement
    lookup, the role lookup or the resolution itself must each end in False.
    """
    admin = user(db, ADMIN_EMAIL)

    class Broken:
        """A session where every read fails, as one would mid-outage."""

        def scalar(self, *args, **kwargs):
            raise RuntimeError("database is gone")

        def scalars(self, *args, **kwargs):
            raise RuntimeError("database is gone")

        def get(self, *args, **kwargs):
            raise RuntimeError("database is gone")

    broken = Broken()
    assert permissions.entitled(broken, admin, "engineering") is False
    assert permissions.is_global_admin(broken, admin) is False
    assert can(broken, admin, CONVERT) is False


# --------------------------------------------------------------- the bump
def test_bumping_the_version_makes_the_session_stale(db):
    engineer = user(db, ENGINEER_EMAIL)
    before = engineer.permissions_version
    assert bump_permissions_version(db, engineer.id) == before + 1
    db.commit()
    assert user(db, ENGINEER_EMAIL).permissions_version == before + 1
