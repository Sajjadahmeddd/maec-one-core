"""The request-time gate.

`main.py`'s guard middleware calls `inspect()` for every request and returns
whatever it returns. What each route requires is declared once, in `ROUTES`,
and `inspect()` reads that table — it does not branch on path prefixes. The
table replaced four prefix constants when a second exception to "everything
under /api/admin needs Global Admin" came due; see OPEN-DECISIONS #9.

Three properties hold whatever is added to the table:

* **Default-deny.** A path under a namespace this service owns — /api,
  /oauth, /.well-known — with no row is refused, not guessed at. Every other
  path is the SPA shell and its assets, which have to load for a sign-in
  screen to exist at all.
* **One order of checks** for every route that needs a person: a session, an
  active account, no password change outstanding, then what the route
  requires, then the CSRF header on a mutation. A route cannot skip the
  interstitial checks by being mounted somewhere convenient.
* **CSRF on every mutation that rides on the session**, not only under
  /api/admin. Sibling subdomains are same-site, so SameSite=Lax does not stop
  a page on another *.mirageaec.com host from posting with the shared cookie
  attached (OPEN-DECISIONS #19). The only exemptions are the routes that take
  credentials instead of a session: signing in, and the token endpoint.
* **The table matches the application.** A test walks the registered routes
  and fails if a route has no row or a row has no route, so the table cannot
  drift into a second, stale copy of the routing table.

The session and the user are read from the database on every guarded call:
the `sessions` row for the cookie's id, then the account. Two indexed
lookups, and they are what make a sign-out, a revoked session, a suspension
or a revoked seat bite on the very next request rather than at cookie expiry.
"""

from __future__ import annotations

from enum import Enum
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.routing import compile_path

from . import security, sessions
from .db import session_factory
from .permissions import (
    audit, fail_closed, holds_business_admin, is_global_admin, load_user,
)


class Access(str, Enum):
    """What a route requires before a request reaches it."""

    # Anyone. No session is read and no CSRF header is asked for.
    PUBLIC = "public"
    # A calling service, not a person. No session is read — there is no browser
    # and no cookie — and no CSRF header; the route authenticates the service
    # by its client credentials, in constant work, before it does anything.
    CLIENT_CREDENTIALS = "client_credentials"
    # An app's front door asking about a browser's cookie (OPEN-DECISIONS #19).
    # The guard reads nothing and refuses nothing: the cookie belongs to the
    # person the question is *about*, not to the caller, and the route runs
    # its own checks in its own order — the app's secret first.
    GATE = "gate"
    # An active account that has cleared every interstitial check.
    SESSION = "session"
    # SESSION, for a page a browser navigates to rather than an API a script
    # calls. Every check is the same; a refusal is a redirect to Core's
    # sign-in, carrying the request to come back to, instead of JSON the
    # browser would show raw.
    SESSION_PAGE = "session_page"
    # SESSION, and Global Admin. A mutation also needs the CSRF header.
    ADMIN = "admin"
    # ADMIN — except that a Business Admin may read, by GET or HEAD only. The
    # endpoint checks again and scopes the query to the applications they lead.
    ADMIN_AUDIT_READ = "admin_audit_read"


# Every route this service serves, and what it requires. Paths are written
# exactly as the routes declare them, `{parameters}` included.
ROUTES: dict[str, Access] = {
    # Signing in, and the ways out. /me answers a signed-out browser too, and
    # change-password has to stay reachable while a password change is due.
    "/api/auth/login": Access.PUBLIC,
    "/api/auth/logout": Access.PUBLIC,
    "/api/auth/me": Access.PUBLIC,
    "/api/auth/change-password": Access.PUBLIC,
    "/api/health": Access.PUBLIC,

    # The OIDC provider. JWKS is public by design: public keys, nothing else.
    "/.well-known/jwks.json": Access.PUBLIC,
    # Deliberately not under /api/auth, whose rows are PUBLIC: mounted there,
    # someone who never replaced an administrator-set password could still
    # obtain a code. As a SESSION_PAGE it gets every interstitial check.
    "/oauth/authorize": Access.SESSION_PAGE,
    # Called by a product's backend with its client secret, never by a browser.
    "/oauth/token": Access.CLIENT_CREDENTIALS,

    # The gate: an app's server asking whether a browser may come in. Not under
    # /api/auth, whose rows are PUBLIC for a different reason.
    "/api/gate/check": Access.GATE,
    "/api/gate/features": Access.GATE,

    # FastAPI's generated documentation describes the admin API, so it is not
    # handed to strangers.
    "/openapi.json": Access.SESSION,
    "/docs": Access.SESSION,
    "/docs/oauth2-redirect": Access.SESSION,
    "/redoc": Access.SESSION,

    # The Global Admin panel.
    "/api/admin/whoami": Access.ADMIN,
    "/api/admin/roles": Access.ADMIN,
    "/api/admin/roles/{role_id}": Access.ADMIN,
    "/api/admin/tool-rules": Access.ADMIN,
    "/api/admin/tool-status": Access.ADMIN,
    "/api/admin/features/{application_key}/{feature_key}": Access.ADMIN,
    "/api/admin/users": Access.ADMIN,
    "/api/admin/users/options": Access.ADMIN,
    "/api/admin/users/{user_id}": Access.ADMIN,
    "/api/admin/users/{user_id}/roles": Access.ADMIN,
    "/api/admin/users/{user_id}/roles/{grant_id}": Access.ADMIN,
    "/api/admin/users/{user_id}/licenses": Access.ADMIN,
    "/api/admin/users/{user_id}/licenses/{application_key}": Access.ADMIN,
    "/api/admin/users/{user_id}/reset-password": Access.ADMIN,
    "/api/admin/users/{user_id}/sessions/revoke": Access.ADMIN,
    "/api/admin/import/validate": Access.ADMIN,
    "/api/admin/import/commit": Access.ADMIN,
    "/api/admin/import/batches": Access.ADMIN,
    "/api/admin/import/batches/{batch_id}": Access.ADMIN,
    "/api/admin/import/template": Access.ADMIN,
    "/api/admin/provisioning": Access.ADMIN,
    "/api/admin/provisioning/{rule_id}": Access.ADMIN,

    # The audit reads: the one place under /api/admin a non-Global-Admin may
    # reach. Exact rows, not a prefix — a retention endpoint or a purge mounted
    # under /api/admin/audit/ later has no row, so it is refused until someone
    # adds one deliberately.
    "/api/admin/audit": Access.ADMIN_AUDIT_READ,
    "/api/admin/audit/stats": Access.ADMIN_AUDIT_READ,
    "/api/admin/audit/controls": Access.ADMIN_AUDIT_READ,
    "/api/admin/audit/export": Access.ADMIN_AUDIT_READ,
}

# Namespaces this service owns. A path inside one with no row in ROUTES is
# refused. Every other path belongs to the SPA.
RESERVED = ("/api", "/oauth", "/.well-known")

# Routes the guard lets through without reading a session.
NO_SESSION = frozenset({Access.PUBLIC, Access.CLIENT_CREDENTIALS, Access.GATE})

SAFE_METHODS = frozenset({"GET", "HEAD"})
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Mutations that take credentials rather than a session, and so need no CSRF
# header: a cross-site page cannot make the request act as someone it has no
# password or client secret for. Every other mutation sent with a session
# cookie must carry the header. CLIENT_CREDENTIALS routes are exempt by kind.
CREDENTIAL_ROUTES = frozenset({"/api/auth/login"})

# Derived from the table rather than kept beside it, so the exception has one
# definition. may_read_audit reads this, and a test pins it to exactly four.
ADMIN_READER_PATHS = frozenset(
    path for path, access in ROUTES.items() if access is Access.ADMIN_AUDIT_READ)

_EXACT = {path: access for path, access in ROUTES.items() if "{" not in path}
_PATTERNS = [(compile_path(path)[0], access)
             for path, access in ROUTES.items() if "{" in path]


def _normal(path: str) -> str:
    return path.rstrip("/") or "/"


def _reserved(path: str) -> bool:
    return any(path == namespace or path.startswith(namespace + "/")
               for namespace in RESERVED)


def access_for(path: str) -> Access | None:
    """What this path requires, or None when it is refused unseen.

    An exact row wins over a parameterised one, so /api/admin/users/options is
    never read as a user id.
    """
    normal = _normal(path)
    if normal in _EXACT:
        return _EXACT[normal]
    for pattern, access in _PATTERNS:
        if pattern.match(normal):
            return access
    if _reserved(normal):
        return None
    return Access.PUBLIC            # the SPA shell and its assets


def may_read_audit(path: str, method: str) -> bool:
    """Is this exactly one of the audit reads, by a safe method?

    Separated out so it can be asserted against directly — the question
    "would a new sub-path inherit this?" should be answerable by a test, not
    by reading the middleware.
    """
    return _normal(path) in ADMIN_READER_PATHS and method in SAFE_METHODS


def _needs_csrf(request: Request, path: str, access: Access) -> bool:
    """Does this request change something on the strength of a session cookie?"""
    return (request.method in MUTATING
            and access is not Access.CLIENT_CREDENTIALS
            and _normal(path) not in CREDENTIAL_ROUTES
            and security.session_id(request) is not None)


def _refuse(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def _to_sign_in(request: Request) -> RedirectResponse:
    """Send a browser to Core's sign-in, to come back to exactly this request.

    `next` is built from this request's own path and query, never from a
    parameter anyone supplied. The SPA follows it only to /oauth/authorize on
    this origin, and the authorize endpoint re-checks everything on return.
    """
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse("/?next=" + quote(target, safe=""), status_code=302)


def inspect(request: Request) -> JSONResponse | RedirectResponse | None:
    """A response to send instead, or None to let the request through.

    Synchronous on purpose — it does a database lookup, and the middleware
    runs it in a worker thread so the event loop is never blocked on it.
    """
    path = request.url.path
    access = access_for(path)
    if access is None:
        return _refuse(404, "Not found.")
    if access in NO_SESSION:
        # A public route that changes something on behalf of whoever the
        # cookie names — sign-out, change-password — needs the header too.
        # No cookie, nothing to forge: sign-out with no session just answers.
        if _needs_csrf(request, path, access) and not security.csrf_ok(request):
            return _refuse(403, "Missing or invalid CSRF token.")
        return None
    page = access is Access.SESSION_PAGE

    if not security.session_id(request):
        return _to_sign_in(request) if page else _refuse(401, "Sign in required.")

    db = session_factory()()
    request.state.identity_db = db          # released in release(), below
    try:
        # The cookie names a session; only a valid row makes it one. Revoked,
        # past its absolute end or idle too long: not signed in, and resolve()
        # clears the cookie so the browser stops sending it.
        row = sessions.resolve(db, request)
        user = load_user(db, row.user_id) if row is not None else None
        # Held deliberately, not just left in the session. SQLAlchemy's
        # identity map keeps weak references, so once this function returns
        # its local goes out of scope, the entry is collected and the route
        # re-queries the same row. Keeping the object on the request is what
        # makes sharing the session actually save the round trip.
        request.state.identity_user = user
        if user is None:
            security.end_session(request)      # suspended or gone: forget them
            return _to_sign_in(request) if page else _refuse(401, "Sign in required.")

        # An administrator set this password and therefore knows it. Until the
        # person replaces it, no route that needs a session answers — otherwise
        # the "must change" is a suggestion the UI makes and a script ignores.
        # The way out, /api/auth/change-password, is a PUBLIC row, so it is
        # never blocked; a page is sent to sign-in, where the SPA shows it.
        if user.must_change_password:
            return _to_sign_in(request) if page else _refuse(403, "Password change required.")

        if access in (Access.ADMIN, Access.ADMIN_AUDIT_READ):
            # resolved once and remembered: require_global_admin reads this
            # back rather than asking the same question a second time
            request.state.is_global_admin = is_global_admin(db, user)
            reading_audit = (access is Access.ADMIN_AUDIT_READ
                             and may_read_audit(path, request.method)
                             and holds_business_admin(db, user))
            if not request.state.is_global_admin and not reading_audit:
                audit(db, actor=user, action="admin.access", target_type="route",
                      target_id=path, source="api", result="blocked", request=request)
                return _refuse(403, "Global Admin only.")
            if request.method in MUTATING and not security.csrf_ok(request):
                audit(db, actor=user, action="admin.csrf", target_type="route",
                      target_id=path, source="api", result="blocked", request=request)
                return _refuse(403, "Missing or invalid CSRF token.")
        elif _needs_csrf(request, path, access) and not security.csrf_ok(request):
            # any other session route that changes something
            return _refuse(403, "Missing or invalid CSRF token.")
        return None
    except Exception as exc:
        # Whatever went wrong, the answer is no — and is said out loud. This
        # is the outermost of the fail-closed handlers: if the database is
        # unreachable, every request in the service arrives here and every
        # user sees the same "Sign in required" they would see for an expired
        # cookie. Without this line a total outage and a routine logout are
        # the same event in the logs.
        fail_closed("guard.inspect", exc)
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
