"""The account lockout: escalating, and a fixed window.

Five failures lock an account for a minute, doubling with each further
failure up to thirty. A failure while the account is already locked is
counted and audited but never moves the end of the lock — before Prompt 9a
each one re-armed it, so anyone who knew an address could hold the account
shut indefinitely with one guess every half hour. OPEN-DECISIONS #20 records
what a fixed window still allows.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import router_auth
from backend.identity.models import AuditLog, User
from backend.identity.resolution import _utc, now

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

WRONG = "Wrong-Password-1"


def _client():
    from backend.main import app
    return TestClient(app)


def _try(client, password=WRONG):
    return client.post("/api/auth/login",
                       json={"email": ENGINEER_EMAIL, "password": password}).status_code


def _engineer(db) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == ENGINEER_EMAIL))


def _count(db, action) -> int:
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(
        AuditLog.action == action, AuditLog.actor_email == ENGINEER_EMAIL))


def test_five_failures_lock_the_account_for_a_minute(identity, db):
    client = _client()
    assert [_try(client) for _ in range(5)] == [401] * 5
    engineer = _engineer(db)
    assert engineer.failed_login_count == 5
    remaining = _utc(engineer.locked_until) - now()
    assert timedelta(seconds=50) < remaining <= router_auth.LOCK_BASE
    assert _count(db, "login.locked") == 1
    # and the right password does not open it while it is locked
    assert _try(client, ENGINEER_PASSWORD) == 401


def test_failures_during_a_lock_are_counted_but_never_extend_it(identity, db):
    client = _client()
    for _ in range(5):
        _try(client)
    locked_until = _engineer(db).locked_until

    for _ in range(4):
        assert _try(client) == 401
    engineer = _engineer(db)
    assert engineer.locked_until == locked_until, "the window moved"
    assert engineer.failed_login_count == 9, "attempts during the lock still count"
    assert _count(db, "login.failed") == 9, "and are still audited"
    assert _count(db, "login.locked") == 1, "no second lock was started"


def test_when_the_window_ends_the_right_password_works_and_clears_the_count(identity, db):
    client = _client()
    for _ in range(5):
        _try(client)
    engineer = _engineer(db)
    engineer.locked_until = now() - timedelta(seconds=1)
    db.commit()

    assert _try(client, ENGINEER_PASSWORD) == 200
    engineer = _engineer(db)
    assert engineer.failed_login_count == 0 and engineer.locked_until is None


def test_a_failure_after_the_window_starts_a_longer_lock(identity, db):
    """Escalation is unchanged: the count carries across, so the next lock is
    longer — up to the cap."""
    client = _client()
    for _ in range(7):
        _try(client)                   # 5 lock it; 2 more are counted, not extending
    engineer = _engineer(db)
    engineer.locked_until = now() - timedelta(seconds=1)
    db.commit()

    assert _try(client) == 401         # the 8th failure, with no lock in force
    engineer = _engineer(db)
    assert engineer.failed_login_count == 8
    expected = router_auth._lock_for(8)
    assert expected == timedelta(minutes=8)
    remaining = _utc(engineer.locked_until) - now()
    assert expected - timedelta(seconds=10) < remaining <= expected
    assert _count(db, "login.locked") == 2
