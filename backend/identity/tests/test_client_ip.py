"""Where a request came from — behind a proxy, and when someone lies about it.

One answer, `security.client_ip`, feeds the login rate limit, the audit log and
the sessions row. It is the socket peer as uvicorn's ProxyHeadersMiddleware
leaves it: rewritten from X-Forwarded-For only when that peer is one of
TRUSTED_PROXIES. OPEN-DECISIONS #6.

Two failures this replaces: behind a proxy the limiter saw only the proxy, so
the whole company shared one login limit; and the audit log believed the first
X-Forwarded-For value from anyone, so anyone could choose their address.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from backend.identity import config, router_auth, security
from backend.identity.models import AuditLog

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

PROXY = ("127.0.0.1", 40000)            # the default TRUSTED_PROXIES
STRANGER = ("203.0.113.7", 40000)       # anyone else on the internet


def _client(peer, **kwargs):
    from backend.main import app
    return TestClient(app, client=peer, **kwargs)


def _last_login_ip(db, email):
    db.expire_all()
    return db.scalars(select(AuditLog.ip).where(AuditLog.actor_email == email)
                      .order_by(AuditLog.created_at.desc())).first()


def _login(client, password=ENGINEER_PASSWORD, **headers):
    return client.post("/api/auth/login", headers=headers,
                       json={"email": ENGINEER_EMAIL, "password": password})


# ------------------------------------------------------ the audit log
def test_a_spoofed_header_from_an_untrusted_peer_is_ignored(identity, db):
    _login(_client(STRANGER), **{"X-Forwarded-For": "198.51.100.99"})
    assert _last_login_ip(db, ENGINEER_EMAIL) == "203.0.113.7"


def test_behind_a_trusted_proxy_the_visitor_is_recorded_not_the_proxy(identity, db):
    _login(_client(PROXY), **{"X-Forwarded-For": "198.51.100.4"})
    assert _last_login_ip(db, ENGINEER_EMAIL) == "198.51.100.4"


def test_the_sessions_row_records_the_same_address(identity, db):
    from backend.identity.models import LoginSession
    _login(_client(PROXY), **{"X-Forwarded-For": "198.51.100.4"})
    _login(_client(STRANGER), **{"X-Forwarded-For": "198.51.100.99"})
    db.expire_all()
    assert sorted(db.scalars(select(LoginSession.ip)).all()) == [
        "198.51.100.4", "203.0.113.7"]


def test_a_trusted_proxy_saying_https_makes_the_cookie_secure(identity):
    login = _login(_client(PROXY), **{"X-Forwarded-For": "198.51.100.4",
                                      "X-Forwarded-Proto": "https"})
    [cookie] = [v for v in login.headers.get_list("set-cookie")
                if v.startswith(config.SESSION_COOKIE + "=")]
    assert "; secure" in cookie.lower()


def test_an_untrusted_peer_saying_https_changes_nothing(identity):
    login = _login(_client(STRANGER), **{"X-Forwarded-Proto": "https"})
    [cookie] = [v for v in login.headers.get_list("set-cookie")
                if v.startswith(config.SESSION_COOKIE + "=")]
    assert "secure" not in cookie.lower()


# ------------------------------------------------------ the rate limit
@pytest.fixture
def limited():
    router_auth.limiter.reset()
    router_auth.limiter.enabled = True
    yield
    router_auth.limiter.enabled = False
    router_auth.limiter.reset()


def _burn(client, times, **headers):
    return [_login(client, password="Wrong-Password-1", **headers).status_code
            for _ in range(times)]


def test_behind_a_proxy_each_visitor_has_their_own_limit(identity, limited):
    """The 9am problem: every visitor arrives from the proxy's address, and
    one shared limit would lock the whole company out."""
    proxy = _client(PROXY)
    assert _burn(proxy, 11, **{"X-Forwarded-For": "198.51.100.1"})[-1] == 429
    # a colleague behind the same proxy is unaffected
    assert _burn(proxy, 1, **{"X-Forwarded-For": "198.51.100.2"}) == [401]


def test_rotating_a_spoofed_header_does_not_escape_the_limit(identity, limited):
    stranger = _client(STRANGER)
    statuses = [_login(stranger, password="Wrong-Password-1",
                       **{"X-Forwarded-For": f"198.51.100.{n}"}).status_code
                for n in range(11)]
    assert statuses[-1] == 429


# ----------------------------------------------------- the trusted list
def test_the_app_trusts_exactly_the_configured_proxies():
    from backend.main import app
    [middleware] = [m for m in app.user_middleware if m.cls is ProxyHeadersMiddleware]
    assert middleware.kwargs == {"trusted_hosts": config.trusted_proxies()}


def test_the_default_is_the_local_machine_only(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    assert config.trusted_proxies() == ["127.0.0.1"]


@pytest.mark.parametrize("bad", ["*", "not-an-ip", "10.0.0.0/33", "127.0.0.1, *"])
def test_an_unusable_trusted_list_refuses_to_start(monkeypatch, bad):
    monkeypatch.setenv("TRUSTED_PROXIES", bad)
    with pytest.raises(RuntimeError, match="TRUSTED_PROXIES"):
        config.trusted_proxies()


def test_the_installed_uvicorn_accepts_a_cidr_range(monkeypatch):
    """Docker gives nginx an address on a network, not a fixed one, so
    production names the range. Asked of the uvicorn actually installed."""
    monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1, 172.18.0.0/16")
    trusted = config.trusted_proxies()
    assert trusted == ["127.0.0.1", "172.18.0.0/16"]

    async def where(request):
        return JSONResponse({"ip": security.client_ip(request),
                             "scheme": request.url.scheme})

    app = ProxyHeadersMiddleware(Starlette(routes=[Route("/", where)]), trusted_hosts=trusted)
    headers = {"X-Forwarded-For": "198.51.100.4", "X-Forwarded-Proto": "https"}
    inside = TestClient(app, client=("172.18.0.5", 1)).get("/", headers=headers).json()
    outside = TestClient(app, client=("172.19.0.5", 1)).get("/", headers=headers).json()
    assert inside == {"ip": "198.51.100.4", "scheme": "https"}
    assert outside == {"ip": "172.19.0.5", "scheme": "http"}
