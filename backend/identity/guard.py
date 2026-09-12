"""The request-time gate.

`main.py`'s guard middleware calls `inspect()` for every request and returns
whatever it returns, so the rules are here in one place:

* the SPA shell and its assets are always served — a login screen has to
  load from somewhere;
* everything under /api/ needs a session that resolves to an active user,
  except the login exchange and the health probe;
* /docs, /redoc and /openapi.json are treated like the API;
* /api/admin/* additionally needs Global Admin, and a mutation there needs
  the CSRF header;
* each product's routes need entitlement to that product. A person without
  a seat gets a 403 from the API however they reached the URL.

The user is read from the database on every guarded call. That is a
primary-key lookup, and it is what makes a suspension or a revoked seat bite
on the very next request rather than at cookie expiry.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from . import security
from .db import session_factory
from .permissions import (
    audit, entitled, holds_business_admin, is_global_admin, load_user,
)

PUBLIC_PREFIXES = ("/api/auth/", "/api/health")
DOCS_PREFIXES = ("/docs", "/redoc", "/openapi.json")
ADMIN_PREFIX = "/api/admin"

# The one place under /api/admin a non-Global-Admin may reach, and only to
# read: a Business & Commercial Lead sees the audit trail for the
# applications they lead. The endpoint checks again and scopes the query, so
# this is a narrowing of who gets past the door, not a replacement for the
# lock behind it.
#
# Exact paths, not a prefix. A prefix would hand the exception to anything
# mounted under /api/admin/audit/ later — a retention endpoint, a purge, a
# per-actor drill-down — without anyone deciding it should have it. Adding a
# route here has to be a deliberate line in this file, which is the only form
# of "deliberate" that survives someone who has not read OPEN-DECISIONS #9.
ADMIN_READER_PATHS = frozenset({
    "/api/admin/audit",
    "/api/admin/audit/stats",
    "/api/admin/audit/controls",
    "/api/admin/audit/export",
})
SAFE_METHODS = frozenset({"GET", "HEAD"})


def may_read_audit(path: str, method: str) -> bool:
    """Is this exactly one of the audit reads, by a safe method?

    Separated out so it can be asserted against directly — the question
    "would a new sub-path inherit this?" should be answerable by a test, not
    by reading the middleware.
    """
    return (path.rstrip("/") or "/") in ADMIN_READER_PATHS and method in SAFE_METHODS
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Which product each API prefix belongs to. A request under one of these
# needs a seat on that product. Engineering Tools' own routers are not
# touched — the gate sits in front of them.
APP_PREFIXES: dict[str, str] = {
    "/api/hapext/": "engineering",
    "/api/airsizer/": "engineering",
    "/api/rebadge/": "engineering",
}


def requires_auth(path: str) -> bool:
    if path.startswith(DOCS_PREFIXES):
        return True
    if not path.startswith("/api/"):
        return False
    return not path.startswith(PUBLIC_PREFIXES)


def _app_for(path: str) -> str | None:
    for prefix, app_key in APP_PREFIXES.items():
        if path.startswith(prefix):
            return app_key
    return None


def _refuse(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def inspect(request: Request) -> JSONResponse | None:
    """A response to send instead, or None to let the request through.

    Synchronous on purpose — it does a database lookup, and the middleware
    runs it in a worker thread so the event loop is never blocked on it.
    """
    path = request.url.path
    if not requires_auth(path):
        return None

    user_id = security.session_user_id(request)
    if not user_id:
        return _refuse(401, "Sign in required.")

    db = session_factory()()
    request.state.identity_db = db          # released in release(), below
    try:
        user = load_user(db, user_id)
        # Held deliberately, not just left in the session. SQLAlchemy's
        # identity map keeps weak references, so once this function returns
        # its local goes out of scope, the entry is collected and the route
        # re-queries the same row. Keeping the object on the request is what
        # makes sharing the session actually save the round trip.
        request.state.identity_user = user
        if user is None:
            security.end_session(request)      # suspended or gone: forget them
            return _refuse(401, "Sign in required.")

        # An administrator set this password and therefore knows it. Until the
        # person replaces it, nothing else in the API answers — otherwise the
        # "must change" is a suggestion the UI makes and a script ignores.
        # /api/auth/* is already public-prefixed, so change-password, /me and
        # logout stay reachable: the way out is never blocked.
        if user.must_change_password:
            return _refuse(403, "Password change required.")

        if path.startswith(ADMIN_PREFIX):
            # resolved once and remembered: require_global_admin reads this
            # back rather than asking the same question a second time
            request.state.is_global_admin = is_global_admin(db, user)
            reading_audit = (may_read_audit(path, request.method)
                             and holds_business_admin(db, user))
            if not request.state.is_global_admin and not reading_audit:
                audit(db, actor=user, action="admin.access", target_type="route",
                      target_id=path, source="api", result="blocked", request=request)
                return _refuse(403, "Global Admin only.")
            if request.method in MUTATING and not security.csrf_ok(request):
                audit(db, actor=user, action="admin.csrf", target_type="route",
                      target_id=path, source="api", result="blocked", request=request)
                return _refuse(403, "Missing or invalid CSRF token.")

        app_key = _app_for(path)
        if app_key is not None and not entitled(db, user, app_key):
            audit(db, actor=user, action="app.access", target_type="application",
                  target_id=app_key, source="api", result="blocked", request=request)
            return _refuse(403, "Your account is not licensed for this application.")
        return None
    except Exception:
        # Whatever went wrong, the answer is no.
        return _refuse(401, "Sign in required.")


def release(request: Request) -> None:
    """Close the session `inspect` opened, once the response is made.

    Kept out of `inspect` so the route can share the same session: closing it
    there would have meant every guarded request opening a second one.
    """
    db = getattr(request.state, "identity_db", None)
    request.state.identity_user = None
    if db is not None:
        request.state.identity_db = None
        db.close()
