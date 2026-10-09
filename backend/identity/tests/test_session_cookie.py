"""The session cookie's attributes: Domain, Secure, HttpOnly, SameSite.

Asserted on the Set-Cookie header itself, because that is what a browser acts
on. The Domain case runs in a subprocess: SessionMiddleware is built once, at
import, so a different SESSION_COOKIE_DOMAIN needs a fresh interpreter rather
than a reload that would disturb every other test's app.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.identity import config

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

REPO = Path(__file__).resolve().parents[3]


def _set_cookie(response) -> str:
    [header] = [v for v in response.headers.get_list("set-cookie")
                if v.startswith(config.SESSION_COOKIE + "=")]
    return header


def _attributes(header: str) -> dict[str, str]:
    parts = [p.strip() for p in header.split(";")][1:]
    return {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "")
            for p in parts}


def _login(client):
    return client.post("/api/auth/login",
                       json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})


def test_unset_the_cookie_is_host_only_httponly_and_lax(identity):
    from backend.main import app
    attributes = _attributes(_set_cookie(_login(TestClient(app))))
    assert "domain" not in attributes
    assert "httponly" in attributes
    assert attributes["samesite"] == "lax"
    assert attributes["path"] == "/"
    assert attributes["max-age"] == str(10 * 60 * 60)


def test_over_plain_http_the_cookie_is_not_secure(identity):
    """A Secure cookie over http would never come back, and nobody could sign
    in on a developer's machine."""
    from backend.main import app
    assert "secure" not in _attributes(_set_cookie(_login(TestClient(app))))


def test_over_https_the_cookie_is_secure_wherever_core_runs(identity, monkeypatch):
    """Not only on Render. Core runs behind nginx on a VPS now, where the old
    on_render() test is false; there the cookie went out without Secure."""
    monkeypatch.delenv("RENDER", raising=False)
    from backend.main import app
    client = TestClient(app, base_url="https://auth.test.invalid")
    login = _login(client)
    assert "secure" in _attributes(_set_cookie(login))
    # and the cookie still works over https
    assert client.get("/api/auth/me").json()["authenticated"] is True


def test_the_app_builds_its_session_middleware_from_the_one_function():
    from starlette.middleware.sessions import SessionMiddleware

    from backend.main import app
    [middleware] = [m for m in app.user_middleware if m.cls is SessionMiddleware]
    options = {k: v for k, v in middleware.kwargs.items() if k != "secret_key"}
    assert options == config.session_cookie_options()


@pytest.mark.parametrize("bad", ["https://mirageaec.com", "mirageaec.com/", "auth:8000",
                                 "two words.com", "localhost", "."])
def test_a_malformed_cookie_domain_refuses_to_start(monkeypatch, bad):
    monkeypatch.setenv("SESSION_COOKIE_DOMAIN", bad)
    with pytest.raises(RuntimeError, match="SESSION_COOKIE_DOMAIN"):
        config.session_cookie_domain()


@pytest.mark.parametrize("good", [".mirageaec.com", "mirageaec.com", ".maec.local"])
def test_a_bare_domain_is_accepted(monkeypatch, good):
    monkeypatch.setenv("SESSION_COOKIE_DOMAIN", good)
    assert config.session_cookie_domain() == good


# The whole sign-in and sign-out, in a fresh interpreter with the domain set.
_WITH_DOMAIN = r'''
import json, os
from backend.identity import db as identity_db, seed
from backend.identity.models import Base
from fastapi.testclient import TestClient

engine = identity_db.engine()
Base.metadata.create_all(engine)
with identity_db.session_factory()() as s:
    seed.run(s, admin_email="admin@mirageaec.com", admin_password="Correct-Horse-Battery-1",
             test_email="engineer@mirageaec.com", test_password="Purple-Monkey-Dishwasher-2")
from backend.identity import router_auth
router_auth.limiter.enabled = False
from backend.main import app

client = TestClient(app, base_url="http://auth.maec.local")
login = client.post("/api/auth/login", json={"email": "engineer@mirageaec.com",
                                             "password": "Purple-Monkey-Dishwasher-2"})
csrf = login.json()["csrf_token"]
logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
pick = lambda r: [v for v in r.headers.get_list("set-cookie") if v.startswith("maec_session=")]
print(json.dumps({"login": pick(login), "logout": pick(logout)}))
'''


def test_with_a_domain_set_sign_in_and_sign_out_both_carry_it():
    """Sign-out must clear the cookie *for the same domain*. A clearing header
    without it would leave the shared cookie in place for every app."""
    env = {**os.environ,
           "DATABASE_URL": "sqlite+pysqlite:///:memory:",
           "SESSION_SECRET": "test-only-session-secret",
           "SESSION_COOKIE_DOMAIN": ".maec.local"}
    env.pop("RENDER", None)
    done = subprocess.run([sys.executable, "-c", _WITH_DOMAIN], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    headers = json.loads(done.stdout.strip().splitlines()[-1])

    [signed_in] = headers["login"]
    assert _attributes(signed_in)["domain"] == ".maec.local"
    assert "httponly" in _attributes(signed_in)
    assert _attributes(signed_in)["samesite"] == "lax"

    [signed_out] = headers["logout"]
    assert signed_out.startswith("maec_session=null")
    assert _attributes(signed_out)["domain"] == ".maec.local"
    assert "1970" in _attributes(signed_out)["expires"]
