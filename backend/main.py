"""MAEC One Core — identity, entitlement and the Global Admin panel.

One service: FastAPI serves the API under /api and the built React bundle at
everything else, so there is a single URL and no CORS in production. In
development the Vite dev server proxies /api here.

This is the Core half of what used to be a single application. Engineering
Tools is a separate deployment; it will become an OIDC client of this
service. Nothing here knows how to convert a HAP report, and nothing here
imports from that codebase.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

# Identity first: importing its config loads .env before anything below
# reads the environment. A real environment variable always wins over the
# file, so on Render — which has no .env — this changes nothing.
from .identity import config as identity_config  # noqa: I001  (must be first)

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from .identity import (
    admin_audit, admin_import, admin_provisioning, admin_roles, admin_tools,
    admin_users, guard, keys, router_admin, router_auth, router_oidc,
)

# Core's own version. The original read this from `hap_converter.__version__`,
# which was the product's number, not identity's — see EXTRACTION-LOG.md.
__version__ = "1.0.0"

FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"

# The key that signs tokens is read now, at import, for the same reason the
# session secret is: on Render a missing key refuses to start, before any
# request, rather than serving a JWKS nothing can be verified against.
keys.signing_key()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Signing in is always required. Say what the service is running on,
    without echoing anything secret, and publish the signing key."""
    where = "on Render" if identity_config.on_render() else "locally"
    print(f"MAEC One Core: per-user sign-in against the identity database ({where}).")
    if not os.environ.get("DATABASE_URL", "").strip():
        print("MAEC One Core: DATABASE_URL is not set — sign-in cannot work until it is.")
    if not identity_config.session_secret_configured():
        print("MAEC One Core: SESSION_SECRET unset — everyone is signed out on restart.")

    from .identity.db import session_factory
    try:
        with session_factory()() as session:
            published = keys.ensure_published(session)
        print(f"MAEC One Core: signing key {published.kid} published at /.well-known/jwks.json.")
    except keys.SigningKeyConflict:
        raise                   # two keys under one id: refuse to serve
    except Exception as exc:
        # The database may not be reachable yet. The token endpoint publishes
        # the key before it signs anything, so this is a delay, not a gap.
        print(f"MAEC One Core: signing key not published at startup ({type(exc).__name__}); "
              "it will be before the first token is signed.")
    yield


app = FastAPI(title="MAEC One Core", version=__version__, lifespan=lifespan)

# Login is rate limited per IP (see identity/router_auth.py). The reply on
# hitting it says nothing about whether the address exists.
app.state.limiter = router_auth.limiter


@app.exception_handler(RateLimitExceeded)
async def _too_many(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"detail": "Too many attempts. Try again in a minute."},
                        status_code=429)


# What the browser is allowed to do with a page we served. This is not an
# access rule — it gates nothing and no signed-in user can tell it is here.
# It limits the damage if a page ever ends up carrying something it should
# not, which is also why it blocks the "paste this CDN script in" advice
# that circulates for hiding devtools.
#
# frame-ancestors is 'self', not 'none': MAEC One may come to embed its
# modules, and 'none' would break that on the day it does. Other sites are
# still refused, which is what stops our sign-in form being framed over
# someone else's page.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'self'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",       # no guessing a file's type
    "X-Frame-Options": "SAMEORIGIN",           # for browsers predating CSP
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


# ORDER MATTERS. Starlette runs the *last* middleware added as the outermost
# one, so the guard is registered first and SessionMiddleware second — that
# way the session cookie is decoded before the guard tries to read it.
# Registered the other way round, request.session does not exist yet and
# every request looks signed out.
@app.middleware("http")
async def gate(request: Request, call_next):
    """Refuse requests from anyone who may not make them.

    The SPA itself is always served — it has to load in order to show a login
    screen. What every other route requires is declared in guard.ROUTES, and
    a path under /api, /oauth or /.well-known with no row there is refused.
    The guard reads the database, so it runs in a worker thread rather than
    on the event loop.
    """
    refusal = await run_in_threadpool(guard.inspect, request)
    try:
        if refusal is not None:
            return refusal
        return await call_next(request)
    finally:
        # the guard's session is the request's session; it lives exactly as
        # long as the request does
        await run_in_threadpool(guard.release, request)


# Signed-cookie sessions: no server-side store, so a restart or a second
# instance changes nothing. https_only is off in local development because
# there is no TLS on 127.0.0.1.
# No `domain` attribute, deliberately: the cookie is host-only. The company
# site shares the registrable domain (mirageaec.com), and a cookie scoped to
# .mirageaec.com would put our session inside its reach. This matters more
# now than it did: Core and the products are separate hosts, and the
# temptation to "just share the cookie" is exactly what this refuses.
app.add_middleware(
    SessionMiddleware,
    secret_key=identity_config.session_secret(),
    session_cookie=identity_config.SESSION_COOKIE,
    max_age=identity_config.SESSION_MAX_AGE,
    same_site="lax",
    https_only=identity_config.on_render(),
)


# Registered last, so it is the outermost layer and sees every response —
# including the guard's 401, which returns without calling through and so
# never reaches anything registered beneath it.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    # Only meaningful over TLS, and only true on Render — asserting it in
    # local development would pin a developer's browser to https://localhost.
    if os.environ.get("RENDER"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


if os.environ.get("MAEC_DEV"):
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(router_auth.router)
app.include_router(router_admin.router)
app.include_router(admin_roles.router)
app.include_router(admin_tools.router)
app.include_router(admin_users.router)
app.include_router(admin_audit.router)
app.include_router(admin_import.router)
app.include_router(admin_provisioning.router)
# The OIDC provider. Here with the others, before the SPA catch-all below: a
# route registered after the catch-all is answered with index.html and a 200.
app.include_router(router_oidc.router)


@app.get("/api/health")
async def health():
    """Readiness for THIS service.

    The original checked that the HAP mapping and the AirSizer catalogs
    parsed, which was Engineering Tools' readiness reported by a shared
    process. Core has no catalogs; what it needs is a reachable database,
    so that is what it reports. See EXTRACTION-LOG.md, finding 2.
    """
    from sqlalchemy import text

    from .identity.db import session_factory

    database = "unreachable"
    try:
        with session_factory()() as session:
            session.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        pass          # never leak a connection string through a health probe

    return {
        "status": "ok" if database == "ok" else "degraded",
        "version": __version__,
        "service": "maec-one-core",
        "database": database,
        "auth": "on",
    }


# ---------------------------------------------------------------- frontend
if FRONTEND_DIST.is_dir():
    app.mount(
        "/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets"
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """Serve the SPA, letting the client router own every non-API path.

        The candidate is resolved and checked to be inside the bundle before
        it is served. Without that, `full_path` is attacker-controlled and
        `dist / "../../.env"` resolves to a real file — the original still
        has that shape, and it is recorded in EXTRACTION-LOG.md rather than
        fixed there, because this extraction must not modify that repository.
        """
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)

        root = FRONTEND_DIST.resolve()
        if full_path:
            candidate = (root / full_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(root):
                return FileResponse(candidate)
        return FileResponse(root / "index.html")


def run() -> None:
    """Serve locally: `python -m backend.main`."""
    import uvicorn

    if not FRONTEND_DIST.is_dir():
        print("frontend/dist is missing — build it first:")
        print("    npm --prefix frontend install")
        print("    npm --prefix frontend run build")
        raise SystemExit(1)

    print("MAEC One Core is running at http://127.0.0.1:8000   (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=8000, timeout_keep_alive=120)


if __name__ == "__main__":
    run()
