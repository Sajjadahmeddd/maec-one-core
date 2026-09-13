"""GET /oauth/authorize.

The endpoint that decides whether a person leaves Core carrying a code. Most
of these tests are about the ways they must not: no session, a password
change outstanding, no seat, a suspended organisation, a client nobody
registered, and a redirect target that is almost — but not exactly — the one
registered.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import pytest
from sqlalchemy import select

from backend.identity import oauth
from backend.identity.models import (
    Application, AuditLog, AuthorizationCode, User, UserLicense,
)

from conftest import ENGINEER_EMAIL

AUTHORIZE = "/oauth/authorize"
REDIRECT = "http://et.maec.local:8080/auth/callback"


@pytest.fixture
def et(db):
    """Engineering Tools, registered as a client."""
    client, _secret = oauth.register_client(
        db, application_key="engineering", name="Engineering Tools",
        redirect_uris=[REDIRECT])
    return client


def _params(client, **overrides) -> dict:
    params = {"client_id": client.client_id, "redirect_uri": REDIRECT,
              "state": "s-123", "nonce": "n-456", "response_type": "code"}
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


def authorize(browser, client, **overrides):
    return browser.get(AUTHORIZE, params=_params(client, **overrides), follow_redirects=False)


def _codes(db) -> list[AuthorizationCode]:
    db.expire_all()
    return db.scalars(select(AuthorizationCode)).all()


def _engineer(db) -> User:
    db.expire_all()
    return db.scalar(select(User).where(User.email == ENGINEER_EMAIL))


def _redirected_to_client(response) -> dict:
    assert response.status_code == 302, response.text
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    return {k: v[0] for k, v in parse_qs(location.query).items()}


def _sent_to_sign_in(response, client) -> None:
    """The guard's answer for a browser page: back to Core's sign-in, with the
    exact authorize request to return to."""
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith("/?next=")
    # compared as parameters, not as a string: how the query was
    # percent-encoded on the way in is the HTTP client's business
    returned = urlsplit(unquote(location[len("/?next="):]))
    assert returned.path == AUTHORIZE
    assert {k: v[0] for k, v in parse_qs(returned.query).items()} == _params(client)


# --------------------------------------------------------------- the success
def test_a_signed_in_engineer_with_a_seat_gets_a_code(engineer_client, db, et):
    r = authorize(engineer_client, et)
    params = _redirected_to_client(r)
    assert params["state"] == "s-123"
    assert "no-store" in r.headers["cache-control"]

    [row] = _codes(db)
    assert row.code_hash == oauth.hash_code(params["code"])     # only the hash is kept
    assert params["code"] not in (row.code_hash, row.nonce, row.state_echo)
    assert (row.oauth_client_id, row.user_id, row.application_id) == (
        et.id, _engineer(db).id, et.application_id)
    assert (row.redirect_uri, row.nonce, row.consumed_at) == (REDIRECT, "n-456", None)

    audit = db.scalars(select(AuditLog).where(AuditLog.action == "oauth.authorize")).all()
    assert [(a.result, a.application_id, a.actor_email) for a in audit] == [
        ("success", et.application_id, ENGINEER_EMAIL)]


def test_a_code_lives_thirty_seconds_and_carries_256_bits(engineer_client, db, et):
    code = _redirected_to_client(authorize(engineer_client, et))["code"]
    assert len(code) >= 43
    [row] = _codes(db)
    assert row.expires_at - row.created_at == timedelta(seconds=30)


def test_the_state_comes_back_unchanged(engineer_client, et):
    state = "a b&c=d/é?x#y"
    assert _redirected_to_client(authorize(engineer_client, et, state=state))["state"] == state


# ------------------------------------------- trap 2: the interstitial checks
def test_a_stranger_is_sent_to_sign_in_and_back_not_given_a_code(app_client, db, et):
    _sent_to_sign_in(authorize(app_client, et), et)
    assert _codes(db) == []


def test_a_person_who_must_change_their_password_cannot_obtain_a_code(engineer_client, db, et):
    """Trap 2. /api/auth/* skips the guard; /oauth/authorize must not, and the
    must_change_password gate applies to it exactly as to the API."""
    engineer = _engineer(db)
    engineer.must_change_password = True
    db.commit()
    _sent_to_sign_in(authorize(engineer_client, et), et)
    assert _codes(db) == []


def test_a_suspended_account_cannot_obtain_a_code_and_is_signed_out(engineer_client, db, et):
    engineer = _engineer(db)
    engineer.status = "suspended"
    db.commit()
    _sent_to_sign_in(authorize(engineer_client, et), et)
    assert _codes(db) == []
    assert engineer_client.get("/api/auth/me").json()["authenticated"] is False


# ------------------------------------------------- entitlement, re-checked
def test_a_person_without_a_seat_is_refused_and_no_code_is_created(engineer_client, db, et):
    engineer = _engineer(db)
    db.delete(db.scalar(select(UserLicense).where(UserLicense.user_id == engineer.id)))
    db.commit()
    params = _redirected_to_client(authorize(engineer_client, et))
    assert params == {"error": "access_denied", "state": "s-123"}
    assert _codes(db) == []
    blocked = db.scalars(select(AuditLog).where(AuditLog.action == "oauth.authorize",
                                                AuditLog.result == "blocked")).all()
    assert len(blocked) == 1


def test_a_member_of_a_suspended_organisation_cannot_obtain_a_code(engineer_client, db, et):
    _engineer(db).org.status = "suspended"
    db.commit()
    assert _redirected_to_client(authorize(engineer_client, et))["error"] == "access_denied"
    assert _codes(db) == []


# ---------------------------------------- the client, and where it returns
def _error_page(response) -> None:
    """An error Core shows itself. Never a redirect: until the client and its
    redirect URI are proven, there is nowhere safe to send the browser."""
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/html")
    assert "location" not in response.headers


def test_an_unknown_client_gets_an_error_page_not_a_redirect(engineer_client, db, et):
    _error_page(authorize(engineer_client, et, client_id="engineering-nobody"))
    assert _codes(db) == []


def test_a_disabled_client_gets_an_error_page(engineer_client, db, et):
    et.status = "disabled"
    db.commit()
    _error_page(authorize(engineer_client, et))
    assert _codes(db) == []


@pytest.mark.parametrize("near_miss", [
    REDIRECT + "/",                                   # a trailing slash
    REDIRECT + "/evil",                               # a longer path
    REDIRECT + ".evil.example",                       # the prefix-match open redirect
    REDIRECT + "?next=https://evil.example",          # an added query
    "http://ET.MAEC.LOCAL:8080/auth/callback",        # case
    "https://et.maec.local:8080/auth/callback",       # scheme
    "http://et.maec.local:8081/auth/callback",        # port
    "http://evil.example/auth/callback",              # host
    "",                                               # none at all
])
def test_a_redirect_uri_that_is_not_exactly_registered_gets_an_error_page(
        engineer_client, db, et, near_miss):
    _error_page(authorize(engineer_client, et, redirect_uri=near_miss))
    assert _codes(db) == []


# ----------------------- once the target is proven safe, errors redirect
def test_a_response_type_other_than_code_is_refused_by_redirect(engineer_client, db, et):
    params = _redirected_to_client(authorize(engineer_client, et, response_type="token"))
    assert params == {"error": "unsupported_response_type", "state": "s-123"}
    assert _codes(db) == []


@pytest.mark.parametrize("missing", ["nonce", "state"])
def test_a_missing_nonce_or_state_is_an_invalid_request(engineer_client, db, et, missing):
    params = _redirected_to_client(authorize(engineer_client, et, **{missing: None}))
    assert params["error"] == "invalid_request"
    assert _codes(db) == []


# ------------------------------------------------------------ the sweep
def test_minting_sweeps_long_expired_codes_and_keeps_recent_ones(engineer_client, db, et):
    engineer = _engineer(db)
    moment = datetime.now(timezone.utc)
    for code_hash, expired in (("a" * 64, timedelta(minutes=11)),
                               ("b" * 64, timedelta(minutes=1))):
        db.add(AuthorizationCode(
            code_hash=code_hash, oauth_client_id=et.id, user_id=engineer.id,
            application_id=et.application_id, redirect_uri=REDIRECT, nonce="n",
            expires_at=moment - expired, created_at=moment - expired - timedelta(seconds=30)))
    db.commit()

    _redirected_to_client(authorize(engineer_client, et))
    kept = {row.code_hash for row in _codes(db)}
    assert "a" * 64 not in kept                      # past the keep window: swept
    assert "b" * 64 in kept                          # recently expired: kept for audit
    assert len(kept) == 2                            # and the new one


# ------------------------------------------------------- registration
def test_registration_stores_only_a_hash_of_the_secret(db):
    client, secret = oauth.register_client(
        db, application_key="engineering", name="Probe", redirect_uris=[REDIRECT])
    assert len(secret) >= 43
    assert secret not in client.client_secret_hash
    assert oauth.authenticate_client(db, client.client_id, secret).id == client.id


@pytest.mark.parametrize("uri, reason", [
    ("http://engineering.example.com/cb", "https"),
    ("https://app.example.com/*", "wildcard"),
    ("https://app.example.com/cb#frag", "fragment"),
    ("/relative/cb", "absolute"),
])
def test_registration_refuses_an_unsafe_redirect_uri(db, uri, reason):
    with pytest.raises(oauth.ClientRegistrationError, match=reason):
        oauth.register_client(db, application_key="engineering", name="Probe",
                              redirect_uris=[uri])


def test_registration_needs_a_real_application(db):
    with pytest.raises(oauth.ClientRegistrationError, match="No application"):
        oauth.register_client(db, application_key="nope", name="Probe",
                              redirect_uris=[REDIRECT])
    assert db.scalar(select(Application).where(Application.key == "nope")) is None
