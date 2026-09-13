"""The guard's access table (OPEN-DECISIONS #9).

The table is the one place a route's requirement is written down, so these
tests are about the table itself: that it covers exactly the routes the
application serves, that an unlisted path is refused rather than guessed at,
and that rows able to match the same path cannot disagree.
"""

from __future__ import annotations

import re

import pytest
from starlette.routing import Mount

from backend.identity.guard import ROUTES, Access, access_for

SPA_CATCH_ALL = "/{full_path:path}"


def _registered_paths(app) -> set[str]:
    """Every path the application routes, included routers walked into.

    FastAPI 0.141 keeps an included router as a wrapper with no `.path`; its
    routes sit on `original_router` and already carry their full prefix. The
    SPA catch-all and the static mount are not rows: every path outside the
    reserved namespaces belongs to them by construction.
    """
    found: set[str] = set()

    def walk(routes):
        for route in routes:
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(inner.routes)
                continue
            if isinstance(route, Mount):
                continue
            path = getattr(route, "path", None)
            if path is not None and path != SPA_CATCH_ALL:
                found.add(path)

    walk(app.routes)
    return found


def test_every_row_names_a_route_the_application_serves():
    from backend.main import app
    stale = set(ROUTES) - _registered_paths(app)
    assert not stale, f"rows with no route behind them: {sorted(stale)}"


def test_every_route_the_application_serves_has_a_row():
    """The default-deny property, from the other side: a new route with no row
    would be refused in production, so the suite says so first."""
    from backend.main import app
    missing = _registered_paths(app) - set(ROUTES)
    assert not missing, f"routes with no row in guard.ROUTES: {sorted(missing)}"


@pytest.mark.parametrize("path", [
    "/api", "/api/nope", "/api/admin/nope", "/api/admin/audit/purge",
    "/api/admin/users/x/roles/y/extra", "/oauth/nope", "/.well-known/nope",
])
def test_an_unlisted_path_in_a_reserved_namespace_is_refused(path):
    assert access_for(path) is None


@pytest.mark.parametrize("path", [
    "/", "/admin", "/admin/users", "/assets/index-abc.js", "/favicon.png",
])
def test_every_other_path_is_the_spa(path):
    assert access_for(path) is Access.PUBLIC


def test_an_exact_row_wins_over_a_parameterised_one():
    assert access_for("/api/admin/users/options") is Access.ADMIN


def test_rows_that_could_match_the_same_path_agree():
    """Fill every parameter in and ask the table: each row must resolve to its
    own access, so no other row can shadow it with a different requirement."""
    for path, access in ROUTES.items():
        sample = re.sub(r"\{[^}]+\}", "sample", path)
        assert access_for(sample) is access, path


def test_a_trailing_slash_resolves_to_the_same_row():
    assert access_for("/api/admin/roles/") is Access.ADMIN
    assert access_for("/api/admin/audit/") is Access.ADMIN_AUDIT_READ


# ------------------------------------------------------- through the stack
def test_a_stranger_gets_not_found_for_an_unlisted_api_path(app_client):
    r = app_client.get("/api/admin/does-not-exist")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not found."}


def test_a_global_admin_is_refused_an_unlisted_path_too(admin_client):
    """Default-deny is not a Global Admin exemption."""
    assert admin_client.get("/api/admin/does-not-exist").status_code == 404


def test_the_generated_documentation_still_needs_a_session(app_client):
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert app_client.get(path).status_code == 401, path
