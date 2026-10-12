"""MAEC_ENV, and the protections that used to hang on Render's RENDER variable.

Four protections were keyed on RENDER: refusing to start without
SESSION_SECRET or OIDC_PRIVATE_KEY, the cookie's Secure flag and HSTS. A VPS
never sets RENDER, so on the VPS all four were silently off — and a missing
SESSION_SECRET would have given each worker its own random secret, signing
people out at random. Now only MAEC_ENV=development allows the fallbacks;
unset, or anything else, is production. Secure and HSTS follow the request's
scheme, never the platform.

Start-up is tested in a fresh interpreter, because both refusals happen when
backend.main is imported. Every variable that matters is set explicitly —
an empty value wins over the developer's .env, which load_dotenv would
otherwise fill in.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[3]
_START = "import backend.main  # noqa\nprint('started')\n"
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()).decode()


def _start(**settings):
    env = {**os.environ, "DATABASE_URL": "sqlite+pysqlite:///:memory:",
           "MAEC_ENV": "", "SESSION_SECRET": "", "MAEC_SECRET_KEY": "",
           "OIDC_PRIVATE_KEY": "", "OIDC_KEY_ID": "", "RENDER": "",
           "GATE_SECRETS": "", "CORE_PUBLIC_URL": ""}
    env.update(settings)
    return subprocess.run([sys.executable, "-c", _START], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=120)


# ----------------------------------------------------------- start-up
@pytest.mark.parametrize("environment", ["", "production", "staging"])
def test_outside_development_core_will_not_start_without_a_session_secret(environment):
    done = _start(MAEC_ENV=environment, OIDC_PRIVATE_KEY=_KEY)
    assert done.returncode != 0 and "started" not in done.stdout
    assert "SESSION_SECRET is not set" in done.stderr


@pytest.mark.parametrize("environment", ["", "production"])
def test_outside_development_core_will_not_start_without_a_signing_key(environment):
    done = _start(MAEC_ENV=environment, SESSION_SECRET="a-real-secret-for-this-test")
    assert done.returncode != 0 and "started" not in done.stdout
    assert "OIDC_PRIVATE_KEY is not set" in done.stderr


def test_in_production_with_both_core_starts():
    done = _start(MAEC_ENV="production", SESSION_SECRET="a-real-secret-for-this-test",
                  OIDC_PRIVATE_KEY=_KEY)
    assert done.returncode == 0, done.stderr[-2000:]
    assert "started" in done.stdout


def test_in_development_core_starts_with_neither():
    done = _start(MAEC_ENV="development")
    assert done.returncode == 0, done.stderr[-2000:]
    assert "started" in done.stdout


def test_render_no_longer_switches_anything():
    """RENDER set and MAEC_ENV=development: still the development fallbacks.
    The platform decides nothing."""
    done = _start(MAEC_ENV="development", RENDER="true")
    assert done.returncode == 0, done.stderr[-2000:]


# --------------------------------------------------------------- HSTS
HSTS = "strict-transport-security"


def _health(client):
    return client.get("/api/health")


def test_hsts_over_https(identity):
    from backend.main import app
    r = _health(TestClient(app, base_url="https://auth.test.invalid"))
    assert r.headers[HSTS] == "max-age=31536000; includeSubDomains"


def test_hsts_when_a_trusted_proxy_says_https(identity):
    from backend.main import app
    client = TestClient(app, client=("127.0.0.1", 40000))
    r = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert HSTS in r.headers


def test_no_hsts_over_plain_http(identity):
    from backend.main import app
    assert HSTS not in _health(TestClient(app)).headers


def test_no_hsts_when_an_untrusted_peer_claims_https(identity):
    from backend.main import app
    client = TestClient(app, client=("203.0.113.7", 40000))
    r = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert HSTS not in r.headers
