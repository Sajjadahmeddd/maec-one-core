"""CSRF on every mutation that rides on the session — not only /api/admin.

Sibling subdomains are same-site, so once the cookie is shared across
*.mirageaec.com, SameSite=Lax no longer stops a page on another host from
posting with it attached (OPEN-DECISIONS #19). The header is the defence: a
cross-site page cannot read the token, so it cannot send it.

The walk below covers every mutating route the application registers, so a
route added later without the header fails here rather than in production.
"""

from __future__ import annotations

import re
import uuid

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend.identity import guard
from backend.identity.config import CSRF_HEADER

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# The only mutations that take credentials instead of a session.
EXEMPT = {("POST", "/api/auth/login"), ("POST", "/oauth/token")}

# Values that satisfy each path parameter's type, so the request reaches the
# guard's verdict rather than a 422 for a malformed id.
PARAMETERS = {"application_key": "engineering"}


def _mutations():
    """Every (method, path) that changes something, included routers walked
    into the way test_guard_table walks them: FastAPI 0.141+ keeps an included
    router behind a wrapper whose routes sit on `original_router`."""
    from backend.main import app

    def walk(routes):
        for route in routes:
            inner = getattr(route, "original_router", None)
            if inner is not None:
                yield from walk(inner.routes)
            elif isinstance(route, APIRoute):
                for method in sorted(route.methods & MUTATING):
                    yield method, route.path

    found = list(walk(app.routes))
    assert found, "the walk found no routes: it is testing nothing"
    return found


def _concrete(path: str) -> str:
    return re.sub(r"\{(\w+)\}",
                  lambda m: PARAMETERS.get(m.group(1), str(uuid.uuid4())), path)


def test_the_exemptions_are_exactly_the_two_credential_routes():
    """Sign-in takes a password and the token endpoint a client secret; a
    cross-site page has neither. Anything else on this list is a hole."""
    mutations = set(_mutations())
    assert EXEMPT <= mutations
    assert guard.CREDENTIAL_ROUTES == {"/api/auth/login"}
    assert guard.access_for("/oauth/token") is guard.Access.CLIENT_CREDENTIALS


@pytest.mark.parametrize("method,path", sorted(set(_mutations()) - EXEMPT))
def test_every_session_mutation_refuses_a_request_with_the_cookie_but_no_token(
        admin_client, method, path):
    """Signed in — as a Global Admin, so no other check refuses first — with
    the cookie attached and no header: refused, before the route runs."""
    r = admin_client.request(method, _concrete(path), json={})
    assert r.status_code == 403, (method, path, r.status_code, r.text)
    assert r.json() == {"detail": "Missing or invalid CSRF token."}


@pytest.mark.parametrize("path", ["/api/auth/logout", "/api/auth/change-password"])
def test_a_wrong_token_is_refused_as_surely_as_none(identity, path):
    from backend.main import app
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    r = client.post(path, headers={CSRF_HEADER: "guessed"},
                    json={"current_password": ENGINEER_PASSWORD,
                          "new_password": "Something-Else-7"})
    assert r.status_code == 403
    assert r.json() == {"detail": "Missing or invalid CSRF token."}
    # and it changed nothing: still signed in, old password still the password
    assert client.get("/api/auth/me").json()["authenticated"] is True


def test_a_forged_sign_out_leaves_the_session_alone(identity):
    """What a sibling page would try: post to sign-out with the shared cookie."""
    from backend.main import app
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    assert client.post("/api/auth/logout").status_code == 403
    assert client.get("/api/auth/me").json()["authenticated"] is True


def test_signing_out_with_no_session_needs_no_token(app_client):
    """No cookie, nothing to forge: a signed-out browser may still call it."""
    r = app_client.post("/api/auth/logout")
    assert r.status_code == 200
    assert r.json() == {"authenticated": False}


def test_signing_in_needs_no_token(app_client):
    r = app_client.post("/api/auth/login",
                        json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    assert r.status_code == 200
