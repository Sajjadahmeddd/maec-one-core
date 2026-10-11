"""GET /api/gate/check — "who does this cookie belong to, and may they use
this app?" OPEN-DECISIONS #19.

An app under the cookie's domain never signs anyone in. On every request its
server forwards the browser's cookie here, with its own gate secret, and acts
on the answer: 200 with who the person is and what they may do, 401 to send
them to sign in, 403 to tell them no.

The guard leaves this route alone (Access.GATE): the caller is an app's
server, not a signed-in browser, and the checks below are the whole of what
this route requires. They run in a fixed order and stop at the first failure.

    1  the app's secret, and the app exists and is live     403 bad_app
    2  a mutation's Origin is the app's own                 403 bad_origin
    3  the cookie names a valid session                     401 not_signed_in
    4  the person is active                                 401 not_signed_in
    5  no password change is outstanding                    401 password_change
    6  their organisation is active                         403 org_suspended
    7  they hold a seat on the app                          403 no_access

Nothing here writes to the browser's cookie: the response goes to the app's
server, and a Set-Cookie on it would be noise at best.
"""

from __future__ import annotations

import dataclasses
import hmac
import logging
from datetime import timedelta
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, security, sessions
from .db import get_db
from .models import Application, AuditLog, Permission, User
from .permissions import audit, entitled, load, load_user, organization_active
from .resolution import HIDES_FROM_NAV, now, resolve

router = APIRouter(tags=["gate"])
log = logging.getLogger("maec.identity")

APP_HEADER = "x-maec-app"
SECRET_HEADER = "x-maec-gate-secret"
URL_HEADER = "x-original-url"
METHOD_HEADER = "x-original-method"
ORIGIN_HEADER = "x-original-origin"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# A refused seat is audited at most once per person, per app, per hour: an
# app's every request reaches this check, and a person without a seat who
# keeps clicking must not become a row per click.
NO_ACCESS_AUDIT_EVERY = timedelta(hours=1)

# What an audit row names when the caller is an app's server that could not
# prove itself, or a request refused before any session was read. No "@", so
# it cannot be mistaken for a person.
GATE_ACTOR = "(gate)"

# Compared against when no secret is configured for the app named, so a
# refusal costs the same whichever reason it has.
_NO_SECRET = "-" * config.MIN_GATE_SECRET

NO_STORE = {"Cache-Control": "no-store"}


# ------------------------------------------------------------------ helpers
def origin_of(url: str | None) -> str | None:
    """scheme://host[:port] of an absolute http(s) URL, lower-cased; else None."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.hostname}" + (f":{port}" if port else "")


def _login_url(request: Request, reason: str) -> str:
    """Where to send the browser: Core's sign-in — or, when a password change
    is what stands in the way, the change-password screen — coming back to
    exactly the page the person asked for. Core builds it because the caller
    may be nginx, which cannot percent-encode."""
    base = config.core_public_url(fallback=str(request.base_url))
    path = "/change-password" if reason == "password_change" else "/"
    wanted = request.headers.get(URL_HEADER, "")
    return f"{base}{path}" + (f"?next={quote(wanted, safe='')}" if wanted else "")


def _refuse(request: Request, status: int, reason: str, app_key: str) -> JSONResponse:
    # INFO, and never the cookie: the app, the reason and the method.
    log.info("gate: %s refused for app %r (%s %s)", reason, app_key[:40],
             request.headers.get(METHOD_HEADER, "GET")[:10], status)
    return JSONResponse({"reason": reason, "login_url": _login_url(request, reason)},
                        status_code=status, headers=NO_STORE)


def _audit_no_access_once_an_hour(db: Session, request: Request, user: User,
                                  app: Application) -> None:
    since = now() - NO_ACCESS_AUDIT_EVERY
    recent = db.scalar(select(AuditLog.id).where(
        AuditLog.action == "gate.no_access", AuditLog.actor_id == user.id,
        AuditLog.application_id == app.id, AuditLog.created_at >= since).limit(1))
    if recent is None:
        audit(db, actor=user, action="gate.no_access", target_type="application",
              target_id=app.key, application_id=app.id, source="gate",
              result="blocked", request=request)


def permitted(data, app: Application, db: Session) -> tuple[list[str], list[str]]:
    """Every permission this person holds in the app, and the modules its
    navigation should leave out — from one load(), resolved in memory.

    `nav_hidden` asks the engine rather than re-deriving its tie-breaks
    (OPEN-DECISIONS #3, #12): a module is hidden when the roles allow
    `module:view` but the engine refuses it once every hiding level is read as
    no_access. That is "a hidden or no_access tool rule sits on a grant that
    wins module:view", decided by resolve() itself.
    """
    keys = sorted(db.scalars(select(Permission.key).where(
        Permission.application_id == app.id)).all())
    allowed = [key for key in keys if resolve(data, key)]

    no_rules = dataclasses.replace(data, tool_rules={})
    hiding_blocks = dataclasses.replace(data, tool_rules={
        target: ("no_access" if level in HIDES_FROM_NAV else level)
        for target, level in data.tool_rules.items()})
    modules = sorted({key.split(":")[1] for key in keys})
    nav_hidden = [
        module for module in modules
        if resolve(no_rules, f"{app.key}:{module}:view")
        and not resolve(hiding_blocks, f"{app.key}:{module}:view")
    ]
    return allowed, nav_hidden


# -------------------------------------------------------------------- route
@router.get("/api/gate/check")
def check(request: Request, db: Session = Depends(get_db)):
    app_key = request.headers.get(APP_HEADER, "").strip()

    # 1. The caller is that app's server: it knows the app's secret. Compared
    #    in constant time, against a stand-in when the app has none.
    expected = config.gate_secrets().get(app_key, _NO_SECRET)
    supplied = request.headers.get(SECRET_HEADER, "")
    secret_ok = (hmac.compare_digest(expected.encode(), supplied.encode())
                 and expected != _NO_SECRET)
    app = db.scalar(select(Application).where(Application.key == app_key)) if app_key else None
    if not secret_ok or app is None or app.status != "live":
        if not secret_ok:
            audit(db, actor_email=GATE_ACTOR, action="gate.bad_secret",
                  target_type="application", target_id=app_key[:120] or None,
                  application_id=app.id if app else None, source="gate",
                  result="blocked", request=request)
        return _refuse(request, 403, "bad_app", app_key)

    # 2. Request forgery. Sibling subdomains are same-site, so the cookie rides
    #    along on a form a page elsewhere under the domain posts to this app.
    #    Anything that may change something must come from the app's own pages.
    method = request.headers.get(METHOD_HEADER, "GET").strip().upper()
    if method not in SAFE_METHODS:
        own = origin_of(app.base_url)
        sent = request.headers.get(ORIGIN_HEADER, "").strip()
        if own is None or sent != own:
            audit(db, actor_email=GATE_ACTOR, action="gate.bad_origin",
                  target_type="application", target_id=app.key, application_id=app.id,
                  source="gate", result="blocked", request=request,
                  after={"method": method[:10], "origin": sent[:200] or None})
            return _refuse(request, 403, "bad_origin", app_key)

    # 3. The session — read, never cleared: this response goes to the app's
    #    server, not the browser that holds the cookie.
    row, _why = sessions.check(db, security.session_id(request))
    if row is None:
        return _refuse(request, 401, "not_signed_in", app_key)
    sessions.touch(db, row)            # using an app is activity, as using Core is

    # 4. An active account.
    user = load_user(db, row.user_id)
    if user is None:
        return _refuse(request, 401, "not_signed_in", app_key)

    # 5. An administrator-set password is not one that may open anything.
    if user.must_change_password:
        return _refuse(request, 401, "password_change", app_key)

    # 6. A suspended organisation holds nothing (OPEN-DECISIONS #14).
    if not organization_active(db, user):
        return _refuse(request, 403, "org_suspended", app_key)

    # 7. A seat on this app.
    if not entitled(db, user, app.key):
        _audit_no_access_once_an_hour(db, request, user, app)
        return _refuse(request, 403, "no_access", app_key)

    allowed, nav_hidden = permitted(load(db, user, app.key), app, db)
    return JSONResponse({
        "user": {"id": str(user.id), "email": user.email, "name": user.display_name},
        "org_id": str(user.org_id),
        "permissions": allowed,
        "nav_hidden": nav_hidden,
    }, headers=NO_STORE)
