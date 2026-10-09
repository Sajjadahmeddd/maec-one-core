"""Built-in roles are recognised by what they are, not by what they are called.

A custom role's key is derived from the name typed for it, and the checks that
confer power compared keys only. So a custom "Global Admin" held at platform
scope was a Global Admin, and a "Business Admin" with no permissions at all
reached the audit log. These tests plant such roles directly — the panel now
refuses to make them — and show they confer nothing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity import accounts, permissions
from backend.identity.config import CSRF_HEADER
from backend.identity.models import Organization, Role, User, UserRole

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL, ENGINEER_PASSWORD

ROLES = "/api/admin/roles"


def _person(db, email):
    db.expire_all()
    return db.scalar(select(User).where(User.email == email))


def _plant(db, key, name, *, scope_type, scope_id):
    """A custom role imitating a built-in one, held by the engineer — written
    straight to the table, the way it could have been made before this fix."""
    org = db.scalar(select(Organization))
    impostor = Role(key=key, name=name, level=1, org_id=org.id, is_custom=True)
    db.add(impostor)
    db.flush()
    engineer = _person(db, ENGINEER_EMAIL)
    db.add(UserRole(user_id=engineer.id, role_id=impostor.id,
                    scope_type=scope_type, scope_id=scope_id))
    db.commit()
    return impostor


def _engineer_client():
    from backend.main import app
    client = TestClient(app)
    r = client.post("/api/auth/login",
                    json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    client.csrf = r.json()["csrf_token"]
    return client


# --------------------------------------------- an impostor confers nothing
def test_a_custom_global_admin_at_platform_scope_is_not_a_global_admin(identity, db):
    _plant(db, "global_admin", "Global Admin", scope_type="platform", scope_id=None)
    engineer = _person(db, ENGINEER_EMAIL)
    assert permissions.is_global_admin(db, engineer) is False

    client = _engineer_client()
    assert client.get("/api/auth/me").json()["is_global_admin"] is False
    r = client.get("/api/admin/whoami")
    assert r.status_code == 403 and r.json()["detail"] == "Global Admin only."


def test_a_custom_global_admin_does_not_count_towards_the_last_admin_rule(identity, db):
    """Otherwise the real last Global Admin could be removed, leaving only an
    impostor who holds nothing."""
    _plant(db, "global_admin", "Global Admin", scope_type="platform", scope_id=None)
    holders = {u.email for u in accounts.global_admin_holders(db)}
    assert holders == {ADMIN_EMAIL}
    admin = _person(db, ADMIN_EMAIL)
    with pytest.raises(accounts.LastGlobalAdminError):
        accounts.set_user_status(db, actor=admin, target=admin, status="suspended")


def test_a_custom_business_admin_with_no_permissions_gets_no_audit_access(identity, db):
    _plant(db, "business_admin", "Business Admin",
           scope_type="application", scope_id="engineering")
    engineer = _person(db, ENGINEER_EMAIL)
    assert permissions.holds_business_admin(db, engineer) is False

    client = _engineer_client()
    for path in ("/api/admin/audit", "/api/admin/audit/stats",
                 "/api/admin/audit/controls", "/api/admin/audit/export"):
        r = client.get(path)
        assert r.status_code == 403, (path, r.status_code)


def test_the_real_built_ins_still_work(identity, db):
    """The fix narrows the check; it must not stop recognising the genuine
    roles."""
    admin = _person(db, ADMIN_EMAIL)
    assert permissions.is_global_admin(db, admin) is True
    business = db.scalar(select(Role).where(Role.key == "business_admin",
                                            Role.org_id.is_(None)))
    engineer = _person(db, ENGINEER_EMAIL)
    db.add(UserRole(user_id=engineer.id, role_id=business.id,
                    scope_type="application", scope_id="engineering"))
    db.commit()
    assert permissions.holds_business_admin(db, _person(db, ENGINEER_EMAIL)) is True
    assert _engineer_client().get("/api/admin/audit").status_code == 200


# ------------------------------------------- the panel refuses look-alikes
@pytest.mark.parametrize("name", [
    "Global Admin", "  global   admin ", "GLOBAL_ADMIN", "global_admin",
    "Business Admin", "Business & Commercial Lead", "business_admin",
    "Project Lead", "employee", "Normal User / Engineer",
])
def test_a_custom_role_may_not_take_a_built_in_name_or_key(admin_client, name):
    r = admin_client.post(ROLES, headers={CSRF_HEADER: admin_client.csrf},
                          json={"name": name})
    assert r.status_code == 409, (name, r.status_code, r.text)
    assert "built-in role" in r.json()["detail"]


def test_a_custom_role_may_not_be_renamed_to_a_built_in_name(admin_client, db):
    made = admin_client.post(ROLES, headers={CSRF_HEADER: admin_client.csrf},
                             json={"name": "Site Engineer"})
    assert made.status_code == 201, made.text
    r = admin_client.patch(f"{ROLES}/{made.json()['id']}",
                           headers={CSRF_HEADER: admin_client.csrf},
                           json={"name": "Global Admin", "changes": []})
    assert r.status_code == 409
    db.expire_all()
    assert db.get(Role, __import__("uuid").UUID(made.json()["id"])).name == "Site Engineer"


def test_an_ordinary_custom_name_is_still_accepted(admin_client):
    r = admin_client.post(ROLES, headers={CSRF_HEADER: admin_client.csrf},
                          json={"name": "Senior  Engineer"})
    assert r.status_code == 201
    assert r.json()["key"] == "senior_engineer"
