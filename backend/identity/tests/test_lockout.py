"""The sign-in lockout: per account and client address. OPEN-DECISIONS #20.

Five failures from one address lock the account for that address, for a
minute, doubling with each further lock from the same address up to thirty.
Failures during a lock are counted and audited but never extend it. A lock
that expires starts the count again from zero.

Before Prompt 11 the count was per account and reset only on a successful
sign-in: once anyone had failed five times, one failure after each lock ended
locked the account again — about two requests an hour held anyone out, from
anywhere.

Each test signs in from explicit addresses: the test client's peer, which
client_ip() reads as it would a visitor's.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import lockout
from backend.identity.config import CSRF_HEADER
from backend.identity.models import AuditLog, LoginLock, User
from backend.identity.resolution import _utc, now

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

WRONG = "Wrong-Password-1"
A, B = "203.0.113.10", "198.51.100.20"


def _try(address, password=WRONG):
    from backend.main import app
    return TestClient(app, client=(address, 40000)).post(
        "/api/auth/login", json={"email": ENGINEER_EMAIL, "password": password}).status_code


def _fail(address, times):
    return [_try(address) for _ in range(times)]


def _lock(db, address) -> LoginLock | None:
    db.expire_all()
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    return db.scalar(select(LoginLock).where(LoginLock.user_id == engineer.id,
                                             LoginLock.address == address))


def _expire(db, address):
    row = _lock(db, address)
    row.locked_until = now() - timedelta(seconds=1)
    db.commit()


def _count(db, action) -> int:
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(
        AuditLog.action == action, AuditLog.actor_email == ENGINEER_EMAIL))


# ------------------------------------------------------------ locking
def test_five_failures_lock_the_account_for_that_address(identity, db):
    assert _fail(A, 5) == [401] * 5
    row = _lock(db, A)
    assert row.failed_count == 5 and row.strikes == 1
    assert timedelta(seconds=50) < _utc(row.locked_until) - now() <= lockout.LOCK_BASE
    assert _count(db, "login.locked") == 1
    assert _try(A, ENGINEER_PASSWORD) == 401, "the right password does not open it"


def test_failures_from_one_address_do_not_lock_the_account_for_another(identity, db):
    """The owner is not locked out by someone guessing somewhere else."""
    _fail(A, 9)
    assert _lock(db, A).locked_until is not None
    assert _try(B, ENGINEER_PASSWORD) == 200
    assert _lock(db, B) is None


def test_failures_during_a_lock_are_counted_but_never_extend_it(identity, db):
    _fail(A, 5)
    locked_until = _lock(db, A).locked_until
    assert _fail(A, 4) == [401] * 4
    row = _lock(db, A)
    assert row.locked_until == locked_until, "the window moved"
    assert row.failed_count == 9, "attempts during the lock still count"
    assert _count(db, "login.failed") == 9, "and are still audited"
    assert _count(db, "login.locked") == 1


# -------------------------------------------------------- when it expires
def test_a_lock_does_not_re_arm_on_one_failure_after_it_expires(identity, db):
    """The hole this replaces: one failure after the window, locked again."""
    _fail(A, 7)
    _expire(db, A)
    assert _try(A) == 401
    row = _lock(db, A)
    assert row.failed_count == 1, "the count started again from zero"
    assert row.locked_until is None, "one failure did not lock it"
    assert _try(A, ENGINEER_PASSWORD) == 200


def test_after_an_expired_lock_it_takes_five_more_and_the_next_lock_is_longer(identity, db):
    _fail(A, 5)
    _expire(db, A)
    assert _fail(A, 4) == [401] * 4
    assert _lock(db, A).locked_until is None
    _fail(A, 1)
    row = _lock(db, A)
    assert row.strikes == 2
    remaining = _utc(row.locked_until) - now()
    assert lockout.LOCK_BASE < remaining <= lockout.lock_length(1)
    assert _count(db, "login.locked") == 2


def test_lock_lengths_double_up_to_the_cap():
    assert [lockout.lock_length(n).total_seconds() / 60 for n in range(7)] == [
        1, 2, 4, 8, 16, 30, 30]


# ------------------------------------------------------------ unlocking
def test_a_successful_sign_in_forgets_that_address_only(identity, db):
    _fail(A, 3)
    _fail(B, 9)
    assert _try(A, ENGINEER_PASSWORD) == 200
    assert _lock(db, A) is None
    assert _lock(db, B).locked_until is not None, "B's lock is B's"


def test_an_admin_password_reset_unlocks_every_address(admin_client, db):
    _fail(A, 5)
    _fail(B, 5)
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    r = admin_client.post(f"/api/admin/users/{engineer.id}/reset-password",
                          headers={CSRF_HEADER: admin_client.csrf},
                          json={"password": "Reset-By-Admin@1"})
    assert r.status_code == 200
    assert _lock(db, A) is None and _lock(db, B) is None
    assert _try(A, "Reset-By-Admin@1") == 200


def test_quiet_rows_without_a_lock_are_swept(identity, db):
    _fail(A, 2)
    row = _lock(db, A)
    row.updated_at = now() - timedelta(days=2)
    db.commit()
    _fail(B, 1)                       # any failure sweeps
    assert _lock(db, A) is None
    assert _lock(db, B) is not None
