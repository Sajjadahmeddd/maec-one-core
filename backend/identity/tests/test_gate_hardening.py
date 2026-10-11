"""The gate, against a caller that is not the app.

Found in review: every anonymous call with a wrong secret wrote one audit row,
and the log is append-only — 200 calls, 200 permanent rows, and nothing to
stop a script doing it forever. And a malformed GATE_SECRETS failed every
check with a 500 instead of stopping Core at start.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from backend.identity import router_auth, router_gate
from backend.identity.models import AuditLog
from backend.identity.resolution import now

from test_gate import ET, SECRET, _browser, gate  # noqa: F401  (fixture)

GATE = "/api/gate/check"
PROXY = ("127.0.0.1", 40000)          # trusted: X-Forwarded-For names the caller
REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def limited():
    router_auth.limiter.reset()
    router_auth.limiter.enabled = True
    yield
    router_auth.limiter.enabled = False
    router_auth.limiter.reset()


def _call(address="203.0.113.50", *, secret="x" * 43, method="GET", origin=None,
          cookie=None):
    from backend.main import app
    caller = TestClient(app, client=PROXY)
    headers = {"X-Forwarded-For": address, "X-MAEC-App": "engineering",
               "X-MAEC-Gate-Secret": secret, "X-Original-URL": f"{ET}/x",
               "X-Original-Method": method}
    if origin:
        headers["X-Original-Origin"] = origin
    if cookie:
        headers["Cookie"] = f"maec_session={cookie}"
    return caller.get(GATE, headers=headers)


def _rows(db, action) -> int:
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == action))


# ----------------------------------------------------- the audit-log flood
def test_two_hundred_bad_calls_write_at_most_one_row(gate, db, limited):
    statuses = [_call().status_code for _ in range(200)]
    assert _rows(db, "gate.bad_secret") <= 1
    assert _rows(db, "gate.bad_secret") == 1, "the first is still recorded"
    assert statuses[:30] == [403] * 30
    assert set(statuses[30:]) == {429}


def test_the_audit_cap_holds_with_the_limiter_off(gate, db):
    """The cap is in the database, not the limiter: it holds after a restart,
    across instances, and when the limiter is switched off."""
    for _ in range(50):
        assert _call().status_code == 403
    assert _rows(db, "gate.bad_secret") == 1


def test_each_address_gets_its_own_row(gate, db):
    for address in ("203.0.113.50", "203.0.113.51", "203.0.113.50"):
        _call(address)
    assert _rows(db, "gate.bad_secret") == 2


def test_ten_minutes_on_the_same_address_is_recorded_again(gate, db):
    _call()
    db.execute(update(AuditLog).where(AuditLog.action == "gate.bad_secret")
               .values(created_at=now() - timedelta(minutes=11)))
    db.commit()
    _call()
    assert _rows(db, "gate.bad_secret") == 2


def test_bad_origin_is_capped_the_same_way(gate, db):
    cookie = _browser()
    for origin in ("http://evil.maec.local", "null", None, "http://evil.maec.local"):
        r = _call(secret=SECRET, method="POST", origin=origin, cookie=cookie)
        assert r.status_code == 403 and r.json()["reason"] == "bad_origin"
    assert _rows(db, "gate.bad_origin") == 1


# --------------------------------------------------------- the rate limit
def test_a_429_says_why_and_writes_nothing(gate, db, limited):
    for _ in range(30):
        _call()
    r = _call()
    assert r.status_code == 429
    assert r.json() == {"reason": "too_many_failures"}
    assert r.headers["retry-after"] == "60"
    assert r.headers["cache-control"] == "no-store"
    assert _rows(db, "gate.bad_secret") == 1


def test_a_successful_check_is_never_limited(gate, db, limited):
    """Every request of every signed-in user goes through the gate, from the
    app's one server address. Failures from that address must not stop it."""
    cookie = _browser()
    for _ in range(40):
        _call(address="198.51.100.7")                 # the app's address, failing
    assert _call(address="198.51.100.7").status_code == 429
    for _ in range(40):                               # and still: right secret, right answer
        r = _call(address="198.51.100.7", secret=SECRET, cookie=cookie)
        assert r.status_code == 200, r.text


def test_refusals_of_people_do_not_count_against_the_app(gate, db, limited):
    """Not signed in, no seat, a forged form: these arrive from the app's own
    address. Were they counted, anyone could throttle the app for everyone."""
    cookie = _browser()
    for _ in range(40):
        assert _call(secret=SECRET).json()["reason"] == "not_signed_in"
        assert _call(secret=SECRET, method="POST", origin="http://evil.example",
                     cookie=cookie).json()["reason"] == "bad_origin"
    assert _call(secret=SECRET, cookie=cookie).status_code == 200
    assert router_gate.GATE_FAILURES_PER_ADDRESS == "30/minute"


# ------------------------------------------------- a short secret at start
_START = "import backend.main  # noqa\nprint('started')\n"


def _start(gate_secrets: str):
    env = {**os.environ, "DATABASE_URL": "sqlite+pysqlite:///:memory:",
           "SESSION_SECRET": "test-only-session-secret", "GATE_SECRETS": gate_secrets}
    return subprocess.run([sys.executable, "-c", _START], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=120)


def test_a_too_short_secret_stops_core_at_start():
    done = _start("engineering=short")
    assert done.returncode != 0
    assert "started" not in done.stdout
    assert "GATE_SECRETS" in done.stderr and "shorter than 32" in done.stderr


def test_a_malformed_entry_stops_core_at_start():
    done = _start("engineering")
    assert done.returncode != 0
    assert "app_key=secret" in done.stderr


def test_a_good_secret_starts():
    done = _start("engineering=" + "s" * 43)
    assert done.returncode == 0, done.stderr[-2000:]
    assert "started" in done.stdout
