"""POST /oauth/token is rate limited — per IP, and per proven client.

Every call verifies a client secret with argon2, on purpose: a refusal must
cost what a success costs. Unthrottled, that made it the cheapest way to burn
Core's CPU. OPEN-DECISIONS #20.

The limits are lowered here so a test needs a handful of calls, not hundreds.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import oauth, router_auth, router_oidc
from backend.identity.models import AuditLog

TOKEN = "/oauth/token"
PROXY = ("127.0.0.1", 40000)          # trusted, so X-Forwarded-For picks the visitor


@pytest.fixture
def limited(monkeypatch):
    monkeypatch.setattr(router_oidc, "TOKEN_RATE_PER_IP", "3/minute", raising=False)
    monkeypatch.setattr(router_oidc, "TOKEN_RATE_PER_CLIENT", "2/minute", raising=False)
    router_auth.limiter.reset()
    router_auth.limiter.enabled = True
    yield
    router_auth.limiter.enabled = False
    router_auth.limiter.reset()


def _server(visitor="198.51.100.1"):
    from backend.main import app
    server = TestClient(app, client=PROXY)
    server.headers["X-Forwarded-For"] = visitor
    return server


def _call(server, client_id="made-up", secret="wrong"):
    return server.post(TOKEN, data={"grant_type": "authorization_code", "code": "nope",
                                    "redirect_uri": "http://et.maec.local:8080/cb",
                                    "client_id": client_id, "client_secret": secret})


def _token_audit_rows(db) -> int:
    db.expire_all()
    return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "oauth.token"))


def test_one_address_is_stopped_before_any_secret_is_checked(identity, db, limited):
    server = _server()
    statuses = [_call(server).status_code for _ in range(4)]
    assert statuses == [401, 401, 401, 429]

    refused = _call(server)
    assert refused.status_code == 429
    assert refused.json() == {"error": "too_many_requests"}
    assert refused.headers["retry-after"] == "60"
    assert refused.headers["cache-control"] == "no-store"
    # the three that were judged are audited; the throttled ones are not
    assert _token_audit_rows(db) == 3


def test_another_address_has_its_own_allowance(identity, limited):
    first, second = _server("198.51.100.1"), _server("198.51.100.2")
    for _ in range(3):
        _call(first)
    assert _call(first).status_code == 429
    assert _call(second).status_code == 401


def test_a_proven_client_is_limited_per_client(identity, db, limited, monkeypatch):
    monkeypatch.setattr(router_oidc, "TOKEN_RATE_PER_IP", "100/minute", raising=False)
    client, secret = oauth.register_client(
        db, application_key="engineering", name="Engineering Tools",
        redirect_uris=["http://et.maec.local:8080/cb"])
    statuses = [_call(_server(f"198.51.100.{n}"), client.client_id, secret).status_code
                for n in range(3)]
    # two judged on their merits (a bad code: invalid_grant), the third throttled,
    # though each came from a different address
    assert statuses == [400, 400, 429]


def test_claiming_a_clients_id_does_not_spend_its_allowance(identity, db, limited, monkeypatch):
    """Keyed on a client_id merely claimed, the per-client limit would let
    anyone throttle a real application by sending its id."""
    monkeypatch.setattr(router_oidc, "TOKEN_RATE_PER_IP", "100/minute", raising=False)
    client, secret = oauth.register_client(
        db, application_key="engineering", name="Engineering Tools",
        redirect_uris=["http://et.maec.local:8080/cb"])
    attacker = _server("203.0.113.66")
    for _ in range(5):
        assert _call(attacker, client.client_id, "not-the-secret").status_code == 401
    assert _call(_server("198.51.100.9"), client.client_id, secret).status_code == 400


def test_with_the_limiter_off_nothing_is_throttled(identity, monkeypatch):
    monkeypatch.setattr(router_oidc, "TOKEN_RATE_PER_IP", "1/minute", raising=False)
    router_auth.limiter.enabled = False
    server = _server()
    assert {_call(server).status_code for _ in range(3)} == {401}
