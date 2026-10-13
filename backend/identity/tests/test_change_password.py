"""Changing your own password because you want to, not because you must.

Every app links to Core's /change-password for everyone, so it has to work
for anyone signed in, not only for someone an administrator gave a password.
The server side is the same route either way, POST /api/auth/change-password;
these tests hold it to the same rules for both: the current password, a CSRF
token, the password policy, every other session signed out, an audit row.

Not signed in, the page sends the browser to sign in first and back after;
that decision is signInFirst() in frontend/src/maecone/next.js, tested by
next.test.js, which test_next_allowlist.py runs as part of this suite.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity.config import CSRF_HEADER
from backend.identity.guard import Access, access_for
from backend.identity.models import AuditLog, User

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ENGINEER_EMAIL, ENGINEER_PASSWORD

CHANGE = "/api/auth/change-password"
ME = "/api/auth/me"
NEW = "Chosen-By-Me@2026"


def _browser(email=ENGINEER_EMAIL, password=ENGINEER_PASSWORD):
    from backend.main import app
    client = TestClient(app)
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    client.csrf = r.json()["csrf_token"]
    return client


def _signed_in(client) -> bool:
    return client.get(ME).json()["authenticated"] is True


def _can_sign_in(email, password) -> bool:
    from backend.main import app
    return TestClient(app).post("/api/auth/login", json={
        "email": email, "password": password}).status_code == 200


def _self_changes(db, result):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == "user.password.self",
                                             AuditLog.result == result)).all()


def _change(client, current=ENGINEER_PASSWORD, new=NEW, csrf=True):
    headers = {CSRF_HEADER: client.csrf} if csrf else {}
    return client.post(CHANGE, headers=headers,
                       json={"current_password": current, "new_password": new})


# ------------------------------------------------------------- voluntary
def test_anyone_signed_in_may_change_their_password(identity, db):
    laptop, phone = _browser(), _browser()
    me = laptop.get(ME).json()
    assert me["must_change_password"] is False, "a voluntary change, not a required one"

    r = _change(laptop)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authenticated"] is True and body["must_change_password"] is False
    assert body["csrf_token"] and body["csrf_token"] != laptop.csrf, "a new session, a new token"

    assert _signed_in(laptop), "this browser stays signed in"
    assert not _signed_in(phone), "every other session is signed out"
    assert _can_sign_in(ENGINEER_EMAIL, NEW)
    assert not _can_sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD)

    [row] = _self_changes(db, "success")
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    assert row.actor_id == person.id and row.target_id == str(person.id)
    assert row.after == {"must_change_password": False, "sessions_revoked": 2}


def test_a_global_admin_may_change_theirs_too(identity):
    admin = _browser(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert _change(admin, current=ADMIN_PASSWORD).status_code == 200
    assert _signed_in(admin)
    assert _can_sign_in(ADMIN_EMAIL, NEW)


def test_the_new_session_token_works_and_the_old_one_does_not(identity):
    """The browser carries on with the token it was handed back."""
    client = _browser()
    old = client.csrf
    client.csrf = _change(client).json()["csrf_token"]
    assert client.post("/api/auth/logout", headers={CSRF_HEADER: old}).status_code == 403
    assert client.post("/api/auth/logout", headers={CSRF_HEADER: client.csrf}).status_code == 200


# ------------------------------------------------------------- refusals
def test_a_wrong_current_password_is_refused_and_changes_nothing(identity, db):
    laptop, phone = _browser(), _browser()
    r = _change(laptop, current="Not-My-Password@1")
    assert r.status_code == 403
    assert r.json() == {"detail": "That is not your current password."}

    assert _signed_in(laptop) and _signed_in(phone), "no session was revoked"
    assert _can_sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD)
    assert not _can_sign_in(ENGINEER_EMAIL, NEW)
    assert len(_self_changes(db, "warning")) == 1
    assert not _self_changes(db, "success")


def test_no_csrf_token_is_refused_and_changes_nothing(identity, db):
    laptop, phone = _browser(), _browser()
    r = _change(laptop, csrf=False)
    assert r.status_code == 403
    assert r.json() == {"detail": "Missing or invalid CSRF token."}

    assert _signed_in(laptop) and _signed_in(phone)
    assert _can_sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD)
    assert not _can_sign_in(ENGINEER_EMAIL, NEW)
    assert not _self_changes(db, "success")


def test_the_password_rules_apply_to_a_voluntary_change(identity):
    client = _browser()
    weak = _change(client, new="alllower1")
    assert weak.status_code == 422 and "uppercase" in weak.json()["detail"]
    same = _change(client, new=ENGINEER_PASSWORD)
    assert same.status_code == 422
    assert _can_sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD)


def test_not_signed_in_the_change_is_refused(app_client):
    r = app_client.post(CHANGE, json={"current_password": ENGINEER_PASSWORD,
                                      "new_password": NEW})
    assert r.status_code == 401
    assert _can_sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD)


def test_the_page_itself_is_open_so_it_can_send_you_to_sign_in():
    """/change-password is the SPA shell: the server serves it to anyone, and
    the page sends someone not signed in to /?next=%2Fchange-password."""
    assert access_for("/change-password") is Access.PUBLIC


# ------------------------------------------------------------- required
def test_the_required_change_is_as_before(admin_client, db):
    """An administrator-set password: nothing opens until it is changed, and
    the change clears the requirement. Same route, same rules."""
    created = admin_client.post("/api/admin/users", headers={CSRF_HEADER: admin_client.csrf},
                                json={"email": "newcomer@mirageaec.com",
                                      "display_name": "New Comer",
                                      "password": "Newcomer@2026"})
    assert created.status_code == 201, created.text

    newcomer = _browser("newcomer@mirageaec.com", "Newcomer@2026")
    assert newcomer.get(ME).json()["must_change_password"] is True
    held = newcomer.get("/api/admin/whoami")
    assert held.status_code == 403 and held.json()["detail"] == "Password change required."

    assert _change(newcomer, current="Newcomer@2026", csrf=False).status_code == 403
    r = _change(newcomer, current="Newcomer@2026")
    assert r.status_code == 200, r.text
    assert r.json()["must_change_password"] is False
    assert newcomer.get("/api/admin/whoami").json()["detail"] == "Global Admin only."
    assert _self_changes(db, "success")[0].after["must_change_password"] is False
