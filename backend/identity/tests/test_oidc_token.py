"""POST /oauth/token.

Server-to-server: no browser, no cookie, no CSRF. A client proves who it is
with its secret, redeems a code once, and receives a signed token carrying
the inputs to the permission decision for its own application. Most of these
tests are about the exchanges that must yield nothing.

The concurrency guarantees — two exchanges racing for one code — are proven
in test_postgres_integrity.py, not here. This suite runs on SQLite through a
single shared connection, and two request threads interleaving on it fail
inside the driver ("bad parameter or other API misuse"), which says nothing
about the endpoint.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, urlsplit

import jwt
import pytest
from sqlalchemy import select

from backend.identity import config, oauth, security
from backend.identity.models import (
    AuditLog, AuthorizationCode, OAuthClient, Subscription, User, UserLicense,
)
from backend.identity.permissions import can
from backend.identity.resolution import from_claims, resolve

from conftest import ENGINEER_EMAIL

TOKEN = "/oauth/token"
REDIRECT = "http://et.maec.local:8080/auth/callback"


@pytest.fixture
def et(db):
    """Engineering Tools, registered: (client, secret)."""
    return oauth.register_client(db, application_key="engineering",
                                 name="Engineering Tools", redirect_uris=[REDIRECT])


def _code(browser, client, nonce="n-456") -> str:
    r = browser.get("/oauth/authorize", follow_redirects=False, params={
        "client_id": client.client_id, "redirect_uri": REDIRECT, "state": "s-1",
        "nonce": nonce, "response_type": "code"})
    assert r.status_code == 302, r.text
    return parse_qs(urlsplit(r.headers["location"]).query)["code"][0]


def exchange(server, client_id, secret, code, *, redirect_uri=REDIRECT,
             grant_type="authorization_code"):
    form = {"grant_type": grant_type, "code": code, "redirect_uri": redirect_uri}
    if client_id is not None:
        form["client_id"] = client_id
    if secret is not None:
        form["client_secret"] = secret
    return server.post(TOKEN, data=form)


def verify(server, token, audience="engineering") -> dict:
    """Verify exactly as a product would: key from the published JWKS by kid,
    signature, audience, issuer and expiry."""
    kid = jwt.get_unverified_header(token)["kid"]
    [key] = [k for k in server.get("/.well-known/jwks.json").json()["keys"] if k["kid"] == kid]
    return jwt.decode(token, jwt.PyJWK(key).key, algorithms=["RS256"],
                      audience=audience, issuer=config.oidc_issuer())


def _engineer(db) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == ENGINEER_EMAIL))


def _refused(response, error="invalid_grant", status=400) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"] == error
    assert "access_token" not in response.json()


# ------------------------------------------------------------- the success
def test_a_code_exchanges_for_a_token_that_verifies_against_the_jwks(
        engineer_client, app_client, db, et):
    client, secret = et
    r = exchange(app_client, client.client_id, secret, _code(engineer_client, client))
    assert r.status_code == 200, r.text
    assert "no-store" in r.headers["cache-control"]
    body = r.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 900

    claims = verify(app_client, body["access_token"])
    engineer = _engineer(db)
    assert (claims["sub"], claims["email"], claims["name"]) == (
        str(engineer.id), engineer.email, engineer.display_name)
    assert (claims["aud"], claims["org"], claims["nonce"]) == (
        "engineering", str(engineer.org_id), "n-456")
    assert claims["pv"] == engineer.permissions_version
    assert claims["entitled"] is True
    assert claims["exp"] - claims["iat"] == 900
    assert [g["role"] for g in claims["grants"]] == ["employee"]
    assert all(k.startswith("engineering:")
               for effects in claims["role_permissions"].values() for k in effects)


def test_a_token_for_engineering_fails_verification_as_timesheet(
        engineer_client, app_client, et):
    client, secret = et
    token = exchange(app_client, client.client_id, secret,
                     _code(engineer_client, client)).json()["access_token"]
    with pytest.raises(jwt.InvalidAudienceError):
        verify(app_client, token, audience="timesheet")


def test_the_claims_resolve_to_what_can_decides(engineer_client, app_client, db, et):
    """One engine, two sources, end to end: the token a product receives
    answers every question the way Core does."""
    client, secret = et
    token = exchange(app_client, client.client_id, secret,
                     _code(engineer_client, client)).json()["access_token"]
    from_token = from_claims(verify(app_client, token))
    engineer = _engineer(db)
    for action in ("view", "convert", "export", "configure"):
        for module in ("hapext", "airsizer", "hapaudit", "rebadge"):
            key = f"engineering:{module}:{action}"
            assert resolve(from_token, key) is can(db, engineer, key), key


def test_basic_authentication_is_accepted(engineer_client, app_client, et):
    client, secret = et
    credentials = base64.b64encode(
        f"{quote(client.client_id, safe='')}:{quote(secret, safe='')}".encode()).decode()
    r = app_client.post(TOKEN, headers={"Authorization": f"Basic {credentials}"}, data={
        "grant_type": "authorization_code", "code": _code(engineer_client, client),
        "redirect_uri": REDIRECT})
    assert r.status_code == 200, r.text


def test_a_successful_exchange_is_audited_and_marks_the_client_used(
        engineer_client, app_client, db, et):
    client, secret = et
    assert exchange(app_client, client.client_id, secret,
                    _code(engineer_client, client)).status_code == 200
    db.expire_all()
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "oauth.token")).all()
    assert [(r.result, r.actor_email) for r in rows] == [("success", ENGINEER_EMAIL)]
    assert db.get(OAuthClient, client.id).last_used_at is not None


# --------------------------------------------------------------- the code
def test_a_code_is_single_use(engineer_client, app_client, et):
    client, secret = et
    code = _code(engineer_client, client)
    assert exchange(app_client, client.client_id, secret, code).status_code == 200
    _refused(exchange(app_client, client.client_id, secret, code))


def test_a_code_expires_at_thirty_seconds(engineer_client, app_client, et, monkeypatch):
    client, secret = et
    code = _code(engineer_client, client)
    later = datetime.now(timezone.utc) + timedelta(seconds=31)
    monkeypatch.setattr(oauth, "now", lambda: later)
    _refused(exchange(app_client, client.client_id, secret, code))


def test_a_code_is_still_good_just_inside_thirty_seconds(
        engineer_client, app_client, et, monkeypatch):
    client, secret = et
    code = _code(engineer_client, client)
    almost = datetime.now(timezone.utc) + timedelta(seconds=25)
    monkeypatch.setattr(oauth, "now", lambda: almost)
    assert exchange(app_client, client.client_id, secret, code).status_code == 200


def test_the_redirect_uri_must_match_the_one_used_at_authorize(engineer_client, app_client, et):
    client, secret = et
    code = _code(engineer_client, client)
    _refused(exchange(app_client, client.client_id, secret, code,
                      redirect_uri=REDIRECT + "/other"))


def test_a_code_minted_for_one_client_is_not_redeemable_by_another(
        engineer_client, app_client, db, et):
    """Bound inside the consume itself, so the attempt does not spend the code:
    a client holding valid credentials cannot burn another client's codes."""
    client_a, secret_a = et
    client_b, secret_b = oauth.register_client(
        db, application_key="engineering", name="Another client", redirect_uris=[REDIRECT])
    code = _code(engineer_client, client_a)
    _refused(exchange(app_client, client_b.client_id, secret_b, code))
    assert exchange(app_client, client_a.client_id, secret_a, code).status_code == 200


def test_an_unknown_code_is_refused(app_client, et):
    client, secret = et
    _refused(exchange(app_client, client.client_id, secret, "not-a-code"))


# --------------------------------------------------- client authentication
@pytest.mark.parametrize("who", ["wrong secret", "no secret", "unknown client", "no client"])
def test_a_client_that_cannot_prove_itself_is_refused_in_constant_work(
        engineer_client, app_client, et, monkeypatch, who):
    client, secret = et
    code = _code(engineer_client, client)
    client_id, given = {
        "wrong secret": (client.client_id, secret + "x"),
        "no secret": (client.client_id, None),
        "unknown client": ("engineering-nobody", secret),
        "no client": (None, None),
    }[who]

    calls = []
    real = security.verify_password
    monkeypatch.setattr(security, "verify_password",
                        lambda password, stored: calls.append(stored) or real(password, stored))
    _refused(exchange(app_client, client_id, given, code), error="invalid_client", status=401)
    assert len(calls) == 1, "every refusal must cost exactly one argon2 verification"


def test_a_disabled_client_is_refused(engineer_client, app_client, db, et):
    client, secret = et
    code = _code(engineer_client, client)
    row = db.get(OAuthClient, client.id)
    row.status = "disabled"
    db.commit()
    _refused(exchange(app_client, client.client_id, secret, code), error="invalid_client", status=401)


def test_a_grant_type_other_than_authorization_code_is_refused(app_client, et):
    client, secret = et
    _refused(exchange(app_client, client.client_id, secret, "x", grant_type="password"),
             error="unsupported_grant_type")


# ------------------------------------------------ re-checked at exchange
def test_a_seat_revoked_between_authorize_and_token_yields_no_token(
        engineer_client, app_client, db, et):
    client, secret = et
    code = _code(engineer_client, client)
    engineer = _engineer(db)
    db.delete(db.scalar(select(UserLicense).where(UserLicense.user_id == engineer.id)))
    db.commit()
    _refused(exchange(app_client, client.client_id, secret, code))
    db.expire_all()
    blocked = db.scalars(select(AuditLog).where(AuditLog.action == "oauth.token",
                                                AuditLog.result == "blocked")).all()
    assert len(blocked) == 1


def test_an_account_suspended_between_authorize_and_token_yields_no_token(
        engineer_client, app_client, db, et):
    client, secret = et
    code = _code(engineer_client, client)
    _engineer(db).status = "suspended"
    db.commit()
    _refused(exchange(app_client, client.client_id, secret, code))


def test_a_password_reset_between_authorize_and_token_yields_no_token(
        engineer_client, app_client, db, et):
    client, secret = et
    code = _code(engineer_client, client)
    _engineer(db).must_change_password = True
    db.commit()
    _refused(exchange(app_client, client.client_id, secret, code))


# ------------------------------------------------------------ lifetime
def test_a_token_never_outlives_the_subscription(engineer_client, app_client, db, et):
    client, secret = et
    ends = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.scalar(select(Subscription)).valid_to = ends
    db.commit()
    body = exchange(app_client, client.client_id, secret, _code(engineer_client, client)).json()
    claims = verify(app_client, body["access_token"])
    assert claims["exp"] <= int(ends.timestamp())
    assert body["expires_in"] <= 300


def test_the_endpoint_needs_no_session(app_client, engineer_client, et):
    """app_client has never signed in, and sends no CSRF header."""
    client, secret = et
    assert "maec_session" not in app_client.cookies
    assert exchange(app_client, client.client_id, secret,
                    _code(engineer_client, client)).status_code == 200


def test_no_code_row_ever_holds_the_code(engineer_client, db, et):
    client, _ = et
    code = _code(engineer_client, client)
    db.expire_all()
    [row] = db.scalars(select(AuthorizationCode)).all()
    assert code not in (row.code_hash, row.nonce, row.state_echo, row.redirect_uri)
