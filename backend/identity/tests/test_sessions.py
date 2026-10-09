"""Server-side sessions: the row is the authority. OPEN-DECISIONS #5.

Before Prompt 9a a session was a signed cookie with no record behind it: a
copy taken before sign-out stayed valid until it expired, and nothing could
revoke one. Every test here would have passed a cookie that should not have
worked.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta

import itsdangerous
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity import config, sessions
from backend.identity.config import CSRF_HEADER, SESSION_COOKIE
from backend.identity.models import AuditLog, LoginSession, User
from backend.identity.resolution import now

from conftest import ADMIN_EMAIL, ENGINEER_EMAIL, ENGINEER_PASSWORD

WHOAMI = "/api/admin/whoami"
ME = "/api/auth/me"
USERS = "/api/admin/users"


def _client():
    from backend.main import app
    return TestClient(app)


def _sign_in(email=ENGINEER_EMAIL, password=ENGINEER_PASSWORD, client=None):
    client = client or _client()
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    client.csrf = r.json()["csrf_token"]
    return client


def _cookie_payload(client) -> dict:
    """What the signed cookie carries, read the way SessionMiddleware reads it."""
    signer = itsdangerous.TimestampSigner(config.session_secret())
    raw = signer.unsign(client.cookies.get(SESSION_COOKIE).encode())
    return json.loads(base64.b64decode(raw))


def _forge_cookie(payload: dict) -> str:
    """A correctly signed cookie with whatever payload we like — what someone
    holding SESSION_SECRET, or a stale copy, could present."""
    signer = itsdangerous.TimestampSigner(config.session_secret())
    return signer.sign(base64.b64encode(json.dumps(payload).encode())).decode()


def _rows(db, email):
    db.expire_all()
    person = db.scalar(select(User).where(User.email == email))
    return db.scalars(select(LoginSession).where(LoginSession.user_id == person.id)
                      .order_by(LoginSession.created_at)).all()


def _signed_in(client) -> bool:
    return client.get(ME).json()["authenticated"] is True


# ------------------------------------------------------ what is stored
def test_a_sign_in_writes_a_row_holding_only_the_hash_of_the_id(identity, db):
    client = _sign_in()
    payload = _cookie_payload(client)

    # the cookie names a session and nothing else: not who, not what version
    assert set(payload) == {"sid", "csrf"}
    assert len(payload["sid"]) >= 43                     # 256 bits, url-safe

    [row] = _rows(db, ENGINEER_EMAIL)
    assert row.session_hash == sessions.hash_id(payload["sid"])
    assert row.session_hash != payload["sid"]
    assert db.scalar(select(LoginSession).where(
        LoginSession.session_hash == payload["sid"])) is None
    assert row.revoked_at is None
    absolute = row.absolute_expires_at - row.created_at
    idle = row.idle_expires_at - row.created_at
    assert absolute == timedelta(hours=10)
    assert idle == timedelta(minutes=120)


def test_a_validly_signed_cookie_with_no_row_is_not_signed_in(identity):
    """The signature is not the authority. A cookie that verifies, naming a
    session the table does not know, is refused — and cleared."""
    client = _client()
    client.cookies.set(SESSION_COOKIE, _forge_cookie({"sid": "x" * 43, "csrf": "c"}))
    assert client.get(WHOAMI).status_code == 401
    assert client.get(ME).json()["authenticated"] is False


def test_an_old_style_cookie_naming_a_user_is_not_signed_in(identity, db):
    """The cookie format before 9a carried the user id. One still in a
    browser — or one minted by anyone holding the secret — opens nothing."""
    admin = db.scalar(select(User).where(User.email == ADMIN_EMAIL))
    client = _client()
    client.cookies.set(SESSION_COOKIE, _forge_cookie(
        {"uid": str(admin.id), "pv": 1, "sid": "old", "csrf": "c"}))
    assert client.get(WHOAMI).status_code == 401


# ---------------------------------------------------------- revocation
def test_sign_out_revokes_the_session_so_a_copied_cookie_is_dead(identity, db):
    """The #5 defect: a cookie copied before sign-out stayed valid for its
    whole lifetime."""
    client = _sign_in()
    stolen = client.cookies.get(SESSION_COOKIE)

    r = client.post("/api/auth/logout", headers={CSRF_HEADER: client.csrf})
    assert r.status_code == 200 and r.json() == {"authenticated": False}
    [row] = _rows(db, ENGINEER_EMAIL)
    assert row.revoked_at is not None

    replay = _client()
    replay.cookies.set(SESSION_COOKIE, stolen)
    assert replay.get(ME).json()["authenticated"] is False


def test_changing_your_password_signs_out_every_other_session(identity, db):
    laptop, phone = _sign_in(), _sign_in()
    assert _signed_in(laptop) and _signed_in(phone)

    r = laptop.post("/api/auth/change-password", headers={CSRF_HEADER: laptop.csrf},
                    json={"current_password": ENGINEER_PASSWORD,
                          "new_password": "Brand-New-Secret-9"})
    assert r.status_code == 200, r.text

    assert _signed_in(laptop), "the browser that changed it keeps a session"
    assert not _signed_in(phone), "every other session is gone"
    live = [row for row in _rows(db, ENGINEER_EMAIL) if row.revoked_at is None]
    assert len(live) == 1, "the one survivor is a new session, not the old one"
    assert live[0].session_hash == sessions.hash_id(_cookie_payload(laptop)["sid"])


def test_an_admin_password_reset_signs_out_every_session(admin_client, db):
    engineer = _sign_in()
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    r = admin_client.post(f"{USERS}/{person.id}/reset-password",
                          headers={CSRF_HEADER: admin_client.csrf},
                          json={"password": "Reset-By-Admin@1"})
    assert r.status_code == 200
    assert not _signed_in(engineer)
    assert all(row.revoked_at is not None for row in _rows(db, ENGINEER_EMAIL))


def test_suspending_someone_revokes_their_sessions_for_good(admin_client, db):
    """Revoked, not merely refused while suspended: reactivating them must
    not bring yesterday's cookie back to life."""
    engineer = _sign_in()
    cookie = engineer.cookies.get(SESSION_COOKIE)
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    patch = lambda status: admin_client.patch(          # noqa: E731
        f"{USERS}/{person.id}", headers={CSRF_HEADER: admin_client.csrf},
        json={"status": status})

    assert patch("suspended").status_code == 200
    assert all(row.revoked_at is not None for row in _rows(db, ENGINEER_EMAIL))
    assert patch("active").status_code == 200

    replay = _client()
    replay.cookies.set(SESSION_COOKIE, cookie)
    assert not _signed_in(replay)


def test_deleting_someone_deletes_their_sessions(admin_client, db):
    engineer = _sign_in()
    person_id = db.scalar(select(User).where(User.email == ENGINEER_EMAIL)).id
    r = admin_client.delete(f"{USERS}/{person_id}",
                            headers={CSRF_HEADER: admin_client.csrf})
    assert r.status_code == 200
    db.expire_all()
    assert db.scalars(select(LoginSession).where(
        LoginSession.user_id == person_id)).all() == []
    assert not _signed_in(engineer)


# --------------------------------------------- sign out everywhere (admin)
def test_sign_out_everywhere_ends_every_session_and_is_audited(admin_client, db):
    laptop, phone = _sign_in(), _sign_in()
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))

    r = admin_client.post(f"{USERS}/{person.id}/sessions/revoke",
                          headers={CSRF_HEADER: admin_client.csrf})
    assert r.status_code == 200, r.text
    assert r.json() == {"id": str(person.id), "sessions_revoked": 2}
    assert not _signed_in(laptop) and not _signed_in(phone)

    db.expire_all()
    row = db.scalar(select(AuditLog).where(AuditLog.action == "user.sessions.revoke"))
    assert row.result == "success" and row.actor_email == ADMIN_EMAIL
    assert row.target_id == str(person.id)
    assert row.after == {"sessions_revoked": 2}

    # the account itself is untouched: they can sign straight back in
    assert _signed_in(_sign_in())


def test_sign_out_everywhere_is_global_admin_only(identity, db):
    engineer = _sign_in()
    admin = db.scalar(select(User).where(User.email == ADMIN_EMAIL))
    r = engineer.post(f"{USERS}/{admin.id}/sessions/revoke",
                      headers={CSRF_HEADER: engineer.csrf})
    assert r.status_code == 403
    assert r.json()["detail"] == "Global Admin only."


def test_sign_out_everywhere_needs_the_csrf_header(admin_client, db):
    engineer = _sign_in()
    person = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    r = admin_client.post(f"{USERS}/{person.id}/sessions/revoke")
    assert r.status_code == 403
    assert r.json()["detail"] == "Missing or invalid CSRF token."
    assert _signed_in(engineer)


# ------------------------------------------------------ the two windows
def _age(db, email, **fields):
    for row in _rows(db, email):
        for name, value in fields.items():
            setattr(row, name, value)
    db.commit()


def test_a_session_idle_too_long_is_refused(identity, db):
    client = _sign_in()
    moment = now()
    _age(db, ENGINEER_EMAIL, last_seen_at=moment - timedelta(hours=3),
         idle_expires_at=moment - timedelta(hours=1))
    assert client.get(WHOAMI).status_code == 401
    assert not _signed_in(client)


def test_a_session_past_its_absolute_end_is_refused_however_busy(identity, db):
    client = _sign_in()
    moment = now()
    _age(db, ENGINEER_EMAIL, created_at=moment - timedelta(hours=11),
         absolute_expires_at=moment - timedelta(seconds=1),
         idle_expires_at=moment - timedelta(seconds=1))
    assert not _signed_in(client)


def test_use_pushes_the_idle_window_at_most_once_a_minute(identity, db):
    client = _sign_in()
    [row] = _rows(db, ENGINEER_EMAIL)
    first_seen, first_idle = row.last_seen_at, row.idle_expires_at

    assert _signed_in(client)                    # within the minute: no write
    [row] = _rows(db, ENGINEER_EMAIL)
    assert (row.last_seen_at, row.idle_expires_at) == (first_seen, first_idle)

    _age(db, ENGINEER_EMAIL, last_seen_at=first_seen - timedelta(minutes=2))
    assert _signed_in(client)                    # a minute on: one write
    [row] = _rows(db, ENGINEER_EMAIL)
    assert row.last_seen_at > first_seen - timedelta(minutes=2)
    assert row.idle_expires_at >= first_idle


def test_the_idle_window_never_passes_the_absolute_end(identity, db):
    moment = now()
    client = _sign_in()
    _age(db, ENGINEER_EMAIL, last_seen_at=moment - timedelta(minutes=5),
         absolute_expires_at=moment + timedelta(minutes=30),
         idle_expires_at=moment + timedelta(minutes=10))
    assert _signed_in(client)
    [row] = _rows(db, ENGINEER_EMAIL)
    assert row.idle_expires_at == row.absolute_expires_at


def test_both_windows_come_from_the_environment(identity, db, monkeypatch):
    monkeypatch.setenv("SESSION_ABSOLUTE_HOURS", "4")
    monkeypatch.setenv("SESSION_IDLE_MINUTES", "15")
    _sign_in()
    [row] = _rows(db, ENGINEER_EMAIL)
    assert row.absolute_expires_at - row.created_at == timedelta(hours=4)
    assert row.idle_expires_at - row.created_at == timedelta(minutes=15)


def test_an_unusable_lifetime_refuses_rather_than_defaulting(monkeypatch):
    import pytest
    for bad in ("0", "-3", "ten"):
        monkeypatch.setenv("SESSION_IDLE_MINUTES", bad)
        with pytest.raises(RuntimeError, match="SESSION_IDLE_MINUTES"):
            config.session_idle_minutes()


# ------------------------------------------ sign-in, fixation and sweep
def test_signing_in_revokes_whatever_session_the_browser_held(identity, db):
    """The fixation defence, now on the server: the previous session in this
    browser is revoked, not just forgotten by the cookie."""
    from conftest import ADMIN_PASSWORD
    client = _sign_in()
    before = client.cookies.get(SESSION_COOKIE)
    _sign_in(ADMIN_EMAIL, ADMIN_PASSWORD, client=client)

    assert all(row.revoked_at is not None for row in _rows(db, ENGINEER_EMAIL))
    replay = _client()
    replay.cookies.set(SESSION_COOKIE, before)
    assert not _signed_in(replay)


def test_a_sign_in_sweeps_rows_that_ended_over_a_day_ago(identity, db):
    _sign_in()
    _sign_in()
    old, recent = _rows(db, ENGINEER_EMAIL)
    moment = now()
    old.revoked_at = moment - timedelta(days=2)
    recent.revoked_at = moment - timedelta(hours=1)
    db.commit()
    old_id, recent_id = old.id, recent.id

    _sign_in()
    ids = {row.id for row in _rows(db, ENGINEER_EMAIL)}
    assert old_id not in ids, "ended more than a day ago: swept"
    assert recent_id in ids, "ended within the day: kept, so a refusal can say 'expired'"


def test_check_says_why_a_session_is_refused(identity, db):
    client = _sign_in()
    sid = _cookie_payload(client)["sid"]
    assert sessions.check(db, sid)[1] == sessions.OK
    assert sessions.check(db, None) == (None, sessions.NOT_SIGNED_IN)
    assert sessions.check(db, "unknown") == (None, sessions.NOT_SIGNED_IN)

    client.post("/api/auth/logout", headers={CSRF_HEADER: client.csrf})
    db.expire_all()
    assert sessions.check(db, sid) == (None, sessions.SESSION_EXPIRED)
