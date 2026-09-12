"""User Management — the screen that makes the rest of the panel usable.

The test that matters most is `test_a_created_user_can_actually_sign_in`:
create someone, give them a role and a seat, and have them use the product.
Everything else is the rules that must hold while doing it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity.config import CSRF_HEADER
from backend.identity.models import (
    Application, AuditLog, Role, Subscription, User, UserRole,
)

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL

USERS = "/api/admin/users"
NEW_PASSWORD = "Newcomer@2026"
CHANGED = "Chosen-By-Me@2026"


def headers(client):
    return {CSRF_HEADER: client.csrf}


def db_user(db, email):
    return db.scalar(select(User).where(User.email == email))


def db_role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def audit_rows(db, action, result=None):
    q = select(AuditLog).where(AuditLog.action == action)
    if result:
        q = q.where(AuditLog.result == result)
    return db.scalars(q).all()


def make_user(client, email="newcomer@mirageaec.com", **over):
    body = {"email": email, "display_name": "New Comer",
            "password": NEW_PASSWORD, "department": "Mechanical"}
    body.update(over)
    return client.post(USERS, headers=headers(client), json=body)


# ------------------------------------------------------------- listing
def test_the_list_is_paged_and_filtered_in_the_database(admin_client):
    body = admin_client.get(USERS, params={"page_size": 1}).json()
    assert body["total"] == 2                 # admin + engineer
    assert len(body["users"]) == 1
    assert body["pages"] == 2 and body["page"] == 1

    hit = admin_client.get(USERS, params={"q": "engineer"}).json()
    assert hit["total"] == 1
    assert hit["users"][0]["email"] == ENGINEER_EMAIL


def test_the_page_size_is_capped(admin_client):
    assert admin_client.get(USERS, params={"page_size": 5000}).status_code == 422


def test_a_row_carries_roles_and_seats(admin_client):
    body = admin_client.get(USERS, params={"q": "engineer"}).json()
    row = body["users"][0]
    assert row["roles"][0]["role"] == "employee"
    assert row["licenses"][0]["application_key"] == "engineering"
    assert row["is_global_admin"] is False


def test_the_form_options_come_from_real_subscriptions(admin_client):
    body = admin_client.get(f"{USERS}/options").json()
    assert {r["key"] for r in body["roles"]} == {
        "global_admin", "business_admin", "project_lead", "employee"}
    apps = {a["key"]: a for a in body["applications"]}
    assert list(apps) == ["engineering"]      # the only one subscribed
    assert apps["engineering"]["seats"] is None          # uncapped in the seed
    assert apps["engineering"]["seats_in_use"] == 2
    assert body["password_rules"]["min_length"] == 8


# ---------------------------------------------------- the whole loop
def test_a_created_user_can_actually_sign_in(admin_client, db, identity):
    """Create, grant, license, sign in, change password, use the product.

    This is the definition-of-done line for the screen, end to end.
    """
    from backend.main import app

    created = make_user(admin_client)
    assert created.status_code == 201, created.text
    person = created.json()
    assert person["must_change_password"] is True
    assert person["status"] == "active"

    admin_client.post(f"{USERS}/{person['id']}/roles", headers=headers(admin_client),
                      json={"role_id": str(db_role(db, "employee").id),
                            "scope_type": "application", "scope_id": "engineering"})
    admin_client.post(f"{USERS}/{person['id']}/licenses", headers=headers(admin_client),
                      json={"application_key": "engineering"})

    # they can sign in...
    newcomer = TestClient(app)
    signed_in = newcomer.post("/api/auth/login",
                              json={"email": "newcomer@mirageaec.com",
                                    "password": NEW_PASSWORD})
    assert signed_in.status_code == 200
    assert signed_in.json()["must_change_password"] is True

    # ...but nothing else works until the password is theirs. Asked of a
    # guarded Core path: the original asked /api/airsizer/config, which is
    # Engineering Tools' and does not exist in this service.
    refused = newcomer.get("/api/admin/whoami")
    assert refused.status_code == 403
    assert refused.json()["detail"] == "Password change required."

    changed = newcomer.post("/api/auth/change-password", json={
        "current_password": NEW_PASSWORD, "new_password": CHANGED})
    assert changed.status_code == 200, changed.text
    assert changed.json()["must_change_password"] is False

    # the gate has lifted: they are refused now for being no administrator,
    # which is a different refusal and the correct one
    after = newcomer.get("/api/admin/whoami")
    assert after.status_code == 403
    assert after.json()["detail"] == "Global Admin only."
    assert newcomer.get("/api/auth/me").status_code == 200
    assert db_user(db, "newcomer@mirageaec.com").must_change_password is False


def test_the_old_password_stops_working_after_the_change(admin_client, db, identity):
    from backend.main import app
    person = make_user(admin_client).json()
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": person["email"], "password": NEW_PASSWORD})
    client.post("/api/auth/change-password", json={
        "current_password": NEW_PASSWORD, "new_password": CHANGED})
    client.post("/api/auth/logout")

    assert client.post("/api/auth/login", json={
        "email": person["email"], "password": NEW_PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={
        "email": person["email"], "password": CHANGED}).status_code == 200


# ------------------------------------------------------ change-password
def test_changing_a_password_needs_the_current_one(admin_client, db, identity):
    from backend.main import app
    person = make_user(admin_client).json()
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": person["email"], "password": NEW_PASSWORD})
    r = client.post("/api/auth/change-password", json={
        "current_password": "Wrong@12345", "new_password": CHANGED})
    assert r.status_code == 403
    assert "current password" in r.json()["detail"]
    assert audit_rows(db, "user.password.self", "warning")


def test_the_new_password_must_meet_the_policy(admin_client, db, identity):
    from backend.main import app
    person = make_user(admin_client).json()
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": person["email"], "password": NEW_PASSWORD})
    r = client.post("/api/auth/change-password", json={
        "current_password": NEW_PASSWORD, "new_password": "alllower1"})
    assert r.status_code == 422
    assert "uppercase" in r.json()["detail"]


def test_the_new_password_must_differ(admin_client, db, identity):
    from backend.main import app
    person = make_user(admin_client).json()
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": person["email"], "password": NEW_PASSWORD})
    r = client.post("/api/auth/change-password", json={
        "current_password": NEW_PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 422


def test_an_admin_reset_forces_another_change(admin_client, db, identity):
    engineer = db_user(db, ENGINEER_EMAIL)
    r = admin_client.post(f"{USERS}/{engineer.id}/reset-password",
                          headers=headers(admin_client),
                          json={"password": "Reset-By-Admin@1"})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).must_change_password is True
    assert audit_rows(db, "user.password", "success")


def test_a_weak_password_is_refused_at_creation(admin_client):
    r = make_user(admin_client, password="alllower1")
    assert r.status_code == 422
    assert "uppercase" in r.json()["detail"]


def test_a_duplicate_address_is_refused(admin_client):
    make_user(admin_client)
    assert make_user(admin_client).status_code == 422


@pytest.mark.parametrize("bad", ["nope", "no@domain", "a b@c.com"])
def test_a_malformed_address_is_refused(admin_client, bad):
    assert make_user(admin_client, email=bad).status_code == 422


# ----------------------------------------------------------- the seats
def test_a_seat_is_refused_when_the_subscription_is_exhausted(admin_client, db):
    sub = db.scalar(select(Subscription))
    sub.seats = 2                      # exactly the two already seeded
    db.commit()

    person = make_user(admin_client).json()
    r = admin_client.post(f"{USERS}/{person['id']}/licenses",
                          headers=headers(admin_client),
                          json={"application_key": "engineering"})
    assert r.status_code == 409
    assert "seats are in use" in r.json()["detail"]
    assert audit_rows(db, "license.assign", "blocked")


def test_a_seat_is_refused_without_a_subscription(admin_client, db):
    person = make_user(admin_client).json()
    r = admin_client.post(f"{USERS}/{person['id']}/licenses",
                          headers=headers(admin_client),
                          json={"application_key": "timesheet"})
    assert r.status_code == 409
    assert "subscription" in r.json()["detail"]


def test_removing_a_seat_takes_the_product_away_at_once(admin_client, db):
    """Core hosts no product, so entitlement is asserted where Core decides
    it rather than through a product endpoint.

    The original called /api/airsizer/config and watched it turn 403. That
    proved the guard's APP_PREFIXES table, which belongs to Engineering
    Tools — and it only worked because both ran in one process. What Core
    owns is the decision itself.
    """
    from backend.identity.permissions import can, entitled

    engineer = db_user(db, ENGINEER_EMAIL)
    assert entitled(db, engineer, "engineering") is True
    assert can(db, engineer, "engineering:hapext:convert") is True

    admin_client.delete(f"{USERS}/{engineer.id}/licenses/engineering",
                        headers=headers(admin_client))
    db.expire_all()
    engineer = db_user(db, ENGINEER_EMAIL)
    assert entitled(db, engineer, "engineering") is False
    assert can(db, engineer, "engineering:hapext:convert") is False


def test_seats_left_is_reported(admin_client, db):
    sub = db.scalar(select(Subscription))
    sub.seats = 5
    db.commit()
    apps = {a["key"]: a for a in admin_client.get(f"{USERS}/options").json()["applications"]}
    assert apps["engineering"]["seats_left"] == 3


# ---------------------------------------------------------- the rules
def test_the_last_global_admin_cannot_be_suspended_over_http(admin_client, db):
    admin = db_user(db, ADMIN_EMAIL)
    r = admin_client.patch(f"{USERS}/{admin.id}", headers=headers(admin_client),
                           json={"status": "suspended"})
    assert r.status_code == 409
    assert "last Global Admin" in r.json()["detail"]
    db.expire_all()
    assert db_user(db, ADMIN_EMAIL).status == "active"


def test_the_only_admin_cannot_delete_themselves(admin_client, db):
    """Honest about what this proves.

    Over HTTP the last-Global-Admin delete rule is unreachable: deleting the
    only admin can only be attempted by that admin (caught here by the
    self-delete rule) or by another Global Admin (in which case they are not
    the last). The rule in accounts.delete_user is belt and braces for any
    future caller — CSV import, directory sync — and is tested directly in
    test_identity_accounts.py.
    """
    admin = db_user(db, ADMIN_EMAIL)
    r = admin_client.delete(f"{USERS}/{admin.id}", headers=headers(admin_client))
    assert r.status_code == 409
    assert "your own account" in r.json()["detail"]
    assert db_user(db, ADMIN_EMAIL) is not None


def test_one_admin_can_delete_another_but_not_the_last(admin_client, engineer_client, db):
    """The chain the last-admin rule actually has to survive, over HTTP.

    Promote a second admin, have them delete the first, then watch the two
    separate guards stop them emptying the platform: the self-delete rule,
    and the last-admin rule on revoking their own grant.
    """
    admin = db_user(db, ADMIN_EMAIL)
    engineer = db_user(db, ENGINEER_EMAIL)

    # 1. promote the engineer to Global Admin, over HTTP
    promoted = admin_client.post(
        f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
        json={"role_id": str(db_role(db, "global_admin").id),
              "scope_type": "platform", "scope_id": None})
    assert promoted.status_code == 201, promoted.text
    assert promoted.json()["is_global_admin"] is True

    # the engineer's session picks the new role up without signing in again
    assert engineer_client.get("/api/admin/whoami").status_code == 200

    # 2. the new admin deletes the original — allowed, because two exist
    deleted = engineer_client.delete(f"{USERS}/{admin.id}",
                                     headers={CSRF_HEADER: engineer_client.csrf})
    assert deleted.status_code == 200, deleted.text
    assert db_user(db, ADMIN_EMAIL) is None

    # 3. now they are the last one. Deleting themselves is refused...
    refused = engineer_client.delete(f"{USERS}/{engineer.id}",
                                     headers={CSRF_HEADER: engineer_client.csrf})
    assert refused.status_code == 409
    assert "your own account" in refused.json()["detail"]

    # ...and so is giving up the role that makes them an admin
    db.expire_all()
    grant = db.scalar(select(UserRole).join(Role).where(
        UserRole.user_id == engineer.id, Role.key == "global_admin"))
    stripped = engineer_client.delete(
        f"{USERS}/{engineer.id}/roles/{grant.id}",
        headers={CSRF_HEADER: engineer_client.csrf})
    assert stripped.status_code == 409
    assert "last Global Admin" in stripped.json()["detail"]

    # the platform still has exactly one administrator
    from backend.identity.accounts import global_admin_holders
    db.expire_all()
    assert [u.email for u in global_admin_holders(db)] == [ENGINEER_EMAIL]


def test_the_last_global_admin_grant_cannot_be_revoked_over_http(admin_client, db):
    admin = db_user(db, ADMIN_EMAIL)
    grant = db.scalar(select(UserRole).where(UserRole.user_id == admin.id))
    r = admin_client.delete(f"{USERS}/{admin.id}/roles/{grant.id}",
                            headers=headers(admin_client))
    assert r.status_code == 409
    assert "last Global Admin" in r.json()["detail"]


def test_suspending_someone_cuts_them_off_on_the_next_call(admin_client, db, identity):
    from backend.main import app
    engineer = db_user(db, ENGINEER_EMAIL)
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": ENGINEER_EMAIL,
                                         "password": "Purple-Monkey-Dishwasher-2"})
    # any guarded Core path; /api/auth/me is public, so it would not show this
    assert client.get("/api/admin/whoami").status_code == 403   # signed in, not admin

    admin_client.patch(f"{USERS}/{engineer.id}", headers=headers(admin_client),
                       json={"status": "suspended"})
    # 403 -> 401: no longer merely un-privileged, no longer signed in at all
    assert client.get("/api/admin/whoami").status_code == 401


def test_a_grant_bumps_the_target(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    before = engineer.permissions_version
    admin_client.post(f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
                      json={"role_id": str(db_role(db, "project_lead").id),
                            "scope_type": "project", "scope_id": "P-2291"})
    db.expire_all()
    assert db_user(db, ENGINEER_EMAIL).permissions_version > before


def test_scope_shape_is_validated(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    role_id = str(db_role(db, "employee").id)
    # platform takes no id
    assert admin_client.post(f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
                             json={"role_id": role_id, "scope_type": "platform",
                                   "scope_id": "x"}).status_code == 422
    # everything else needs one
    assert admin_client.post(f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
                             json={"role_id": role_id, "scope_type": "project",
                                   "scope_id": None}).status_code == 422
    # and the scope type must exist
    assert admin_client.post(f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
                             json={"role_id": role_id, "scope_type": "galaxy",
                                   "scope_id": "x"}).status_code == 422


def test_an_unknown_role_is_refused(admin_client, db):
    engineer = db_user(db, ENGINEER_EMAIL)
    assert admin_client.post(
        f"{USERS}/{engineer.id}/roles", headers=headers(admin_client),
        json={"role_id": str(uuid.uuid4()), "scope_type": "application",
              "scope_id": "engineering"}).status_code == 422


def test_you_cannot_delete_yourself(admin_client, db):
    admin = db_user(db, ADMIN_EMAIL)
    r = admin_client.delete(f"{USERS}/{admin.id}", headers=headers(admin_client))
    assert r.status_code == 409


# ------------------------------------------------- authorization floor
@pytest.mark.parametrize("method,path", [
    ("GET", USERS), ("POST", USERS), ("GET", f"{USERS}/options"),
])
def test_an_engineer_is_refused(engineer_client, method, path):
    r = engineer_client.request(method, path, json={},
                                headers={CSRF_HEADER: engineer_client.csrf})
    assert r.status_code == 403


@pytest.mark.parametrize("method,path", [("GET", USERS), ("POST", USERS)])
def test_a_stranger_is_refused(app_client, method, path):
    assert app_client.request(method, path, json={}).status_code == 401


def test_creating_a_user_without_csrf_is_refused(admin_client):
    r = admin_client.post(USERS, json={"email": "x@mirageaec.com",
                                       "display_name": "X", "password": NEW_PASSWORD})
    assert r.status_code == 403
    assert "CSRF" in r.json()["detail"]


def test_every_action_is_audited(admin_client, db):
    person = make_user(admin_client).json()
    admin_client.post(f"{USERS}/{person['id']}/roles", headers=headers(admin_client),
                      json={"role_id": str(db_role(db, "employee").id),
                            "scope_type": "application", "scope_id": "engineering"})
    admin_client.post(f"{USERS}/{person['id']}/licenses", headers=headers(admin_client),
                      json={"application_key": "engineering"})
    admin_client.patch(f"{USERS}/{person['id']}", headers=headers(admin_client),
                       json={"department": "Electrical"})

    for action in ("user.create", "role.grant", "license.assign", "user.update"):
        rows = audit_rows(db, action, "success")
        assert rows, f"no audit row for {action}"
        assert rows[0].actor_email == ADMIN_EMAIL


def test_a_licence_event_records_which_application(admin_client, db):
    """So a Business Admin can later be shown only their own application."""
    person = make_user(admin_client).json()
    admin_client.post(f"{USERS}/{person['id']}/licenses", headers=headers(admin_client),
                      json={"application_key": "engineering"})
    row = audit_rows(db, "license.assign", "success")[0]
    app = db.scalar(select(Application).where(Application.key == "engineering"))
    assert row.application_id == app.id
