"""One engine, two sources (OPEN-DECISIONS #11).

`resolve()` is the five steps with no database. `can()` is `load()` then
`resolve()`. A product builds the same input from a token's claims. These
tests hold the two sources to one answer, and hold `resolve()` to its promise
of importing without a database driver at all.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

import backend.identity as _identity
from backend.identity.models import (
    Application, Permission, Role, RolePermission, Subscription, ToolRule,
    User, UserLicense, UserRole,
)
from backend.identity.permissions import can, load
from backend.identity.resolution import (
    Grant, ResolutionInput, from_claims, resolve, to_claims,
)

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

from pathlib import Path

REPO = Path(_identity.__file__).resolve().parents[2]
CONVERT = "engineering:hapext:convert"


# ------------------------------------------------- no database in sight
NO_DRIVER = r"""
import importlib.abc, sys

BLOCKED = {"sqlalchemy", "fastapi", "starlette", "pydantic", "psycopg",
           "argon2", "jwt", "cryptography", "dotenv"}

class Refuse(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(name + " is not available to this test")
        return None

sys.meta_path.insert(0, Refuse())

from backend.identity.resolution import Grant, ResolutionInput, from_claims, resolve, to_claims

data = ResolutionInput(
    app_key="engineering", org_id="org-1", entitled=True,
    grants=(Grant(role_id="r1", role_key="employee",
                  scope_type="application", scope_id="engineering"),),
    role_permissions={("r1", "engineering:hapext:convert"): "allow",
                      ("r1", "engineering:hapext:configure"): "deny"},
    tool_rules={("hapext", "r1"): "view"},
)
assert resolve(data, "engineering:hapext:convert") is False     # narrowed to view
assert resolve(data, "engineering:hapext:configure") is False
assert resolve(from_claims(to_claims(data)), "engineering:hapext:convert") is False
loaded = sorted(m.split(".")[0] for m in sys.modules)
assert not BLOCKED.intersection(loaded), BLOCKED.intersection(loaded)
print("resolved without a database")
"""


def test_resolve_imports_with_no_database_driver():
    """The test of whether the split is real. Every database, web and crypto
    package is made unimportable, then resolution is imported and run."""
    result = subprocess.run([sys.executable, "-c", NO_DRIVER], cwd=REPO,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "resolved without a database" in result.stdout


# ------------------------------------------------ the two sources agree
def _user(db, email) -> User:
    return db.scalar(select(User).where(User.email == email))


def _role(db, key) -> Role:
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def _app(db, key="engineering") -> Application:
    return db.scalar(select(Application).where(Application.key == key))


def _engineer_grant(db) -> UserRole:
    return db.scalar(select(UserRole).where(
        UserRole.user_id == _user(db, ENGINEER_EMAIL).id))


def seeded(db):
    pass


def project_scoped_deny(db):
    engineer = _user(db, ENGINEER_EMAIL)
    denier = Role(key="no_convert_here", name="No Convert Here", level=4,
                  org_id=engineer.org_id, is_custom=True)
    db.add(denier)
    db.flush()
    convert = db.scalar(select(Permission).where(Permission.key == CONVERT))
    db.add(RolePermission(role_id=denier.id, permission_id=convert.id, effect="deny"))
    db.add(UserRole(user_id=engineer.id, role_id=denier.id,
                    scope_type="project", scope_id="P-2291"))


def every_tool_rule_level(db):
    org_id = _user(db, ENGINEER_EMAIL).org_id
    employee = _role(db, "employee").id
    for module, level in (("hapext", "view"), ("airsizer", "edit"),
                          ("rebadge", "hidden"), ("hapaudit", "no_access")):
        db.add(ToolRule(org_id=org_id, application_id=_app(db).id,
                        module_key=module, role_id=employee, access_level=level))


def tied_roles_one_restricted(db):
    """OPEN-DECISIONS #12: a no_access on either tied role refuses for both."""
    engineer = _user(db, ENGINEER_EMAIL)
    lead = _role(db, "project_lead")
    db.add(UserRole(user_id=engineer.id, role_id=lead.id,
                    scope_type="application", scope_id="engineering"))
    db.add(ToolRule(org_id=engineer.org_id, application_id=_app(db).id,
                    module_key="hapext", role_id=lead.id, access_level="no_access"))


def edit_on_a_role_that_configures(db):
    """The derivation from LEVEL_IMPLIES: edit is everything except configure."""
    grant = _engineer_grant(db)
    grant.role_id = _role(db, "business_admin").id
    db.flush()
    db.add(ToolRule(org_id=_user(db, ENGINEER_EMAIL).org_id, application_id=_app(db).id,
                    module_key="hapext", role_id=grant.role_id, access_level="edit"))


def expired_grant(db):
    _engineer_grant(db).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)


def organization_scoped_grant(db):
    grant = _engineer_grant(db)
    grant.scope_type, grant.scope_id = "organization", str(_user(db, ENGINEER_EMAIL).org_id)


def suspended_organisation(db):
    _user(db, ENGINEER_EMAIL).org.status = "suspended"


def no_seat(db):
    engineer = _user(db, ENGINEER_EMAIL)
    db.delete(db.scalar(select(UserLicense).where(UserLicense.user_id == engineer.id)))


def lapsed_subscription(db):
    db.scalar(select(Subscription)).valid_to = datetime.now(timezone.utc) - timedelta(days=1)


SCENARIOS = [seeded, project_scoped_deny, every_tool_rule_level,
             tied_roles_one_restricted, edit_on_a_role_that_configures,
             expired_grant, organization_scoped_grant, suspended_organisation,
             no_seat, lapsed_subscription]

EXTRA_KEYS = ["engineering:hapext:teleport", "timesheet:sheet:view",
              "not-a-key", "engineering::view"]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.__name__)
def test_can_and_resolve_over_claims_agree(db, scenario):
    """Same question, two sources: rows through can(), and a serialised token
    body through from_claims() and resolve(). Every registered permission,
    plus keys that must be refused, across default, project and organisation
    scopes, for both seeded people."""
    scenario(db)
    db.commit()

    keys = [p.key for p in db.scalars(select(Permission)).all()] + EXTRA_KEYS
    engineer = _user(db, ENGINEER_EMAIL)
    scopes = [None, ("application", "engineering"), ("project", "P-2291"),
              ("project", "P-9999"), ("organization", str(engineer.org_id))]

    answers = []
    for email in (ENGINEER_EMAIL, ADMIN_EMAIL):
        person = _user(db, email)
        wire = json.loads(json.dumps(to_claims(load(db, person, "engineering"))))
        from_token = from_claims(wire)
        for key in keys:
            for scope in scopes:
                expected = can(db, person, key, scope)
                assert resolve(from_token, key, scope) is expected, (
                    f"{scenario.__name__}: {email} {key} {scope} — "
                    f"can() said {expected}")
                answers.append(expected)

    if scenario is seeded:
        assert True in answers and False in answers, "the matrix decided nothing"


# ---------------------------------------------------------- resolve() alone
def _input(**overrides) -> ResolutionInput:
    base = dict(
        app_key="engineering", org_id="org-1", entitled=True,
        grants=(Grant(role_id="r1", role_key="employee",
                      scope_type="application", scope_id="engineering"),),
        role_permissions={("r1", CONVERT): "allow"},
    )
    return ResolutionInput(**{**base, **overrides})


def test_an_input_answers_for_its_own_application_only():
    data = _input(role_permissions={("r1", CONVERT): "allow",
                                    ("r1", "timesheet:sheet:view"): "allow"})
    assert resolve(data, CONVERT) is True
    assert resolve(data, "timesheet:sheet:view") is False


def test_a_grant_that_ends_inside_a_token_stops_counting():
    at = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)
    data = _input(grants=(Grant(role_id="r1", role_key="employee",
                                scope_type="application", scope_id="engineering",
                                expires_at=at + timedelta(minutes=5)),))
    assert resolve(data, CONVERT, at=at) is True
    assert resolve(data, CONVERT, at=at + timedelta(minutes=6)) is False


def test_an_entitlement_that_ends_inside_a_token_stops_counting():
    at = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)
    data = _input(entitled_until=at + timedelta(minutes=5))
    assert resolve(data, CONVERT, at=at) is True
    assert resolve(data, CONVERT, at=at + timedelta(minutes=6)) is False


def test_resolve_fails_closed_and_names_itself(caplog):
    broken = _input(grants=(object(),))            # not a Grant: no in_force
    with caplog.at_level(logging.WARNING, logger="maec.identity"):
        assert resolve(broken, CONVERT) is False
    assert "resolve failed closed" in caplog.text


def test_the_claims_are_plain_json_and_read_back_identically(db):
    engineer = _user(db, ENGINEER_EMAIL)
    data = load(db, engineer, "engineering")
    wire = json.dumps(to_claims(data))
    assert from_claims(json.loads(wire)) == data
    claims = json.loads(wire)
    assert claims["aud"] == "engineering"
    assert {"role", "role_id", "scope_type", "scope_id"} <= set(claims["grants"][0])


def test_a_token_body_for_engineering_carries_nothing_about_another_application(db):
    """Scoped to the audience: no other application's rules travel."""
    timesheet = _app(db, "timesheet")
    engineer = _user(db, ENGINEER_EMAIL)
    db.add(Permission(key="timesheet:sheet:view", application_id=timesheet.id,
                      module_key="sheet", action="view"))
    db.flush()
    sheet = db.scalar(select(Permission).where(Permission.key == "timesheet:sheet:view"))
    db.add(RolePermission(role_id=_role(db, "employee").id, permission_id=sheet.id,
                          effect="allow"))
    db.add(ToolRule(org_id=engineer.org_id, application_id=timesheet.id,
                    module_key="sheet", role_id=_role(db, "employee").id,
                    access_level="view"))
    db.commit()

    claims = to_claims(load(db, engineer, "engineering"))
    keys = {k for effects in claims["role_permissions"].values() for k in effects}
    assert keys and all(k.startswith("engineering:") for k in keys)
    assert all(rule["module_key"] != "sheet" for rule in claims["tool_rules"])
