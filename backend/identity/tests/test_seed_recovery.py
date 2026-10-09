"""SEED_RESET_PASSWORDS=1 — the recovery path for an administrator locked out.

It re-applied the bootstrap password and left the lock in place, so the
"recovered" account still refused every sign-in for up to half an hour.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity import seed
from backend.identity.models import LoginSession, User
from backend.identity.resolution import now

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD

RECOVERED = "Recovered-Admin-Pass-1"


def _admin(db) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == ADMIN_EMAIL))


def _lock(db):
    admin = _admin(db)
    admin.failed_login_count = 9
    admin.locked_until = now() + timedelta(minutes=30)
    db.commit()


def _sign_in(password):
    from backend.main import app
    return TestClient(app).post("/api/auth/login",
                                json={"email": ADMIN_EMAIL, "password": password})


def test_the_recovery_switch_clears_the_lock_and_the_count(identity, db):
    _lock(db)
    created = seed.run(db, admin_email=ADMIN_EMAIL, admin_password=RECOVERED,
                       reset_passwords=True)
    assert created.get("password resets") == 1
    assert created.get("lockouts cleared") == 1
    admin = _admin(db)
    assert admin.failed_login_count == 0 and admin.locked_until is None
    assert _sign_in(RECOVERED).status_code == 200


def test_it_clears_a_lock_even_when_the_password_is_already_right(identity, db):
    """Locked out by someone else's guesses, password never forgotten."""
    _lock(db)
    created = seed.run(db, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD,
                       reset_passwords=True)
    assert "password resets" not in created
    assert created.get("lockouts cleared") == 1
    assert _sign_in(ADMIN_PASSWORD).status_code == 200


def test_a_re_applied_password_ends_the_sessions_minted_under_the_old_one(identity, db):
    assert _sign_in(ADMIN_PASSWORD).status_code == 200
    seed.run(db, admin_email=ADMIN_EMAIL, admin_password=RECOVERED, reset_passwords=True)
    db.expire_all()
    rows = db.scalars(select(LoginSession).where(
        LoginSession.user_id == _admin(db).id)).all()
    assert rows and all(row.revoked_at is not None for row in rows)


def test_without_the_switch_nothing_is_touched(identity, db):
    """It runs on every boot: a restart must never undo a password or a lock."""
    _lock(db)
    created = seed.run(db, admin_email=ADMIN_EMAIL, admin_password=RECOVERED)
    assert created == {}
    admin = _admin(db)
    assert admin.failed_login_count == 9 and admin.locked_until is not None
