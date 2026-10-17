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
    8  not shut out by Tool-Level Settings: every tool      403 no_access
       Inactive, or a role here left with nothing

Nothing here writes to the browser's cookie: the response goes to the app's
server, and a Set-Cookie on it would be noise at best.
"""

from __future__ import annotations

import hmac
import json
import logging
from datetime import timedelta
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from limits import parse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, features, security, sessions
from .db import get_db
from .models import Application, AuditLog, Permission, User, UserLicense
from .permissions import audit, entitled, load, load_user, organization_active
from .resolution import covers, now, resolve
from .router_auth import limiter

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

# A caller that cannot prove it is the app — a wrong or missing secret — is
# answered 429 once it has failed this often from one address, and is not
# audited while it is. Only those failures count. Every other refusal (not
# signed in, no seat, a bad origin) comes from the app's own server, the one
# address every user's request arrives from; counting them would let anyone
# throttle the app for everybody. A call with the right secret is never
# limited, so a successful check never is. OPEN-DECISIONS #20.
GATE_FAILURES_PER_ADDRESS = "30/minute"

# A refusal of a caller — a wrong secret, a bad origin — is audited at most once
# per client address, per app, per ten minutes. The log can never be cleaned
# (it is append-only), so a row per anonymous call would let a script grow it
# without end.
BAD_CALL_AUDIT_EVERY = timedelta(minutes=10)

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


def _too_many_failures(request: Request) -> bool:
    """Count one failed call from this address; True once over the limit."""
    if not limiter.enabled:
        return False
    address = security.client_ip(request) or "unknown"
    return not limiter.limiter.hit(parse(GATE_FAILURES_PER_ADDRESS), "gate.failure", address)


def _audit_bad_call(db: Session, request: Request, action: str, app_key: str,
                    app: Application | None, after: dict | None = None) -> None:
    """Record a refused caller — unless this address already has a row for
    this app and this refusal within the last ten minutes."""
    address = security.client_ip(request)
    target = app_key[:120] or None
    recent = db.scalar(select(AuditLog.id).where(
        AuditLog.action == action,
        AuditLog.target_id == target if target else AuditLog.target_id.is_(None),
        AuditLog.ip == address if address else AuditLog.ip.is_(None),
        AuditLog.created_at >= now() - BAD_CALL_AUDIT_EVERY).limit(1))
    if recent is None:
        audit(db, actor_email=GATE_ACTOR, action=action, target_type="application",
              target_id=target, application_id=app.id if app else None, source="gate",
              result="blocked", request=request, after=after)


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


def shut_out(data, app: Application, db: Session) -> bool:
    """Is an empty permission list the grid's doing, and so a refusal?

    Yes when every tool of the app is switched off (Inactive is for everyone),
    or when the person holds a role that reaches the app and the grid — or
    the role itself — leaves them nothing there: the grid shows No Access for
    them, and the door agrees.

    No when they hold a seat but no role reaches the app. Nothing in the grid
    speaks for them, and an app with its own roles (Project Management) decides
    from there — the seat lets them in, as it did before #22. The system test
    found the alternative: a tile that opened onto a refusal.
    """
    modules = set(db.scalars(select(Permission.module_key).where(
        Permission.application_id == app.id)).all())
    if modules and modules <= data.inactive_modules:
        return True
    moment = now()
    return any(grant.in_force(moment)
               and covers(grant, data.org_id, data.app_key, ("application", data.app_key))
               for grant in data.grants)


def permitted(data, app: Application, db: Session) -> tuple[list[str], list[str]]:
    """Every permission this person holds in the app, and the modules its
    navigation should leave out — from one load(), resolved in memory.

    A tool is all or nothing (OPEN-DECISIONS #22), so `nav_hidden` is simply
    every module of the app this person cannot use: No Access in the grid,
    switched off (Inactive), or never granted. It is read from the same
    resolve() answers as `permissions`, so the two cannot disagree.
    """
    keys = sorted(db.scalars(select(Permission.key).where(
        Permission.application_id == app.id)).all())
    allowed = [key for key in keys if resolve(data, key)]
    usable = {key.split(":")[1] for key in allowed}
    nav_hidden = sorted({key.split(":")[1] for key in keys} - usable)
    return allowed, nav_hidden


def _the_app(request: Request, db: Session, *, live: bool
             ) -> tuple[str, Application | None, JSONResponse | None]:
    """Step 1 of every gate route: the caller is that app's server, because it
    knows the app's secret — compared in constant time, against a stand-in
    when the app has none — and the app exists (and, for `live`, is live).
    Returns the app, or the refusal to send. A wrong secret counts towards the
    per-address limit and is audited; a right one never is."""
    app_key = request.headers.get(APP_HEADER, "").strip()
    expected = config.gate_secrets().get(app_key, _NO_SECRET)
    supplied = request.headers.get(SECRET_HEADER, "")
    secret_ok = (hmac.compare_digest(expected.encode(), supplied.encode())
                 and expected != _NO_SECRET)
    app = db.scalar(select(Application).where(Application.key == app_key)) if app_key else None
    if not secret_ok or app is None or (live and app.status != "live"):
        if not secret_ok:
            if _too_many_failures(request):
                log.info("gate: too many failed calls from one address (app %r)",
                         app_key[:40])
                return app_key, None, JSONResponse(
                    {"reason": "too_many_failures"}, status_code=429,
                    headers={**NO_STORE, "Retry-After": "60"})
            _audit_bad_call(db, request, "gate.bad_secret", app_key, app)
        return app_key, None, _refuse(request, 403, "bad_app", app_key)
    return app_key, app, None


# -------------------------------------------------------------------- route
@router.get("/api/gate/check")
def check(request: Request, db: Session = Depends(get_db)):
    # 1. The caller is that app's server, and the app is live.
    app_key, app, refused = _the_app(request, db, live=True)
    if refused is not None:
        return refused

    # 2. Request forgery. Sibling subdomains are same-site, so the cookie rides
    #    along on a form a page elsewhere under the domain posts to this app.
    #    Anything that may change something must come from the app's own pages.
    method = request.headers.get(METHOD_HEADER, "GET").strip().upper()
    if method not in SAFE_METHODS:
        own = origin_of(app.base_url)
        sent = request.headers.get(ORIGIN_HEADER, "").strip()
        if own is None or sent != own:
            _audit_bad_call(db, request, "gate.bad_origin", app.key, app,
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

    # 8. Not shut out by Tool-Level Settings (OPEN-DECISIONS #22).
    data = load(db, user, app.key)
    allowed, nav_hidden = permitted(data, app, db)
    if not allowed and shut_out(data, app, db):
        _audit_no_access_once_an_hour(db, request, user, app)
        return _refuse(request, 403, "no_access", app_key)

    return JSONResponse({
        "user": {"id": str(user.id), "email": user.email, "name": user.display_name},
        "org_id": str(user.org_id),
        "permissions": allowed,
        "nav_hidden": nav_hidden,
    }, headers=NO_STORE)


# ------------------------------------------------------- the app's features
@router.put("/api/gate/features")
async def register_features(request: Request, db: Session = Depends(get_db)):
    """An app tells Core its features, when it starts. OPEN-DECISIONS #23.

    Authenticated exactly as /api/gate/check — the app's key and its secret —
    except that the app need not be live yet: it reports before it opens.
    The body is read only after the caller has proved itself.

        PUT /api/gate/features
        X-MAEC-App: engineering
        X-MAEC-Gate-Secret: <the app's gate secret>
        {"app_version": "93e6aee",
         "features": [{"key": "<key>", "name": "<name>", "actions": ["use"]}]}

    200 {"registered": N, "new": M, "not_reported": K}; 422 {"detail": why}
    for a report refused as a whole; 403 {"reason": "bad_app"} for a caller
    that cannot prove it is the app.
    """
    app_key, app, refused = await run_in_threadpool(_the_app, request, db, live=False)
    if refused is not None:
        return refused
    raw = await request.body()
    return await run_in_threadpool(_register, request, db, app, raw)


def _register(request: Request, db: Session, app: Application, raw: bytes) -> JSONResponse:
    if len(raw) > features.MAX_BODY:
        return JSONResponse({"detail": f"The report is larger than {features.MAX_BODY} bytes."},
                            status_code=413, headers=NO_STORE)
    try:
        body = json.loads(raw or b"null")
    except ValueError:
        return JSONResponse({"detail": "The body is not valid JSON."}, status_code=422,
                            headers=NO_STORE)
    try:
        version, reported = features.parse(body, app.key)
        outcome = features.register(db, app, version, reported, now())
    except features.ReportError as exc:
        db.rollback()
        log.info("gate: feature report from %r refused: %s", app.key, str(exc)[:200])
        return JSONResponse({"detail": str(exc)}, status_code=422, headers=NO_STORE)

    if outcome.changed:
        audit(db, actor_email=f"({app.key} app)", action="features.register",
              target_type="application", target_id=app.key, application_id=app.id,
              source="gate", result="success", request=request,
              after={"app_version": app.features_version, "registered": outcome.registered,
                     "new": outcome.new[:50], "new_actions": outcome.new_actions[:50],
                     "renamed": outcome.renamed[:50], "reported_again": outcome.back[:50],
                     "not_reported": outcome.gone_quiet[:50],
                     "counts": app.features_report},
              commit=False)
    db.commit()
    return JSONResponse(outcome.response(), headers=NO_STORE)


# ------------------------------------------------- who holds one of its features
@router.get("/api/gate/holders")
def holders(request: Request, db: Session = Depends(get_db),
            key: str = Query(default="", max_length=120),
            action: str = Query(default="use", max_length=40)):
    """Who may use one of the asking app's own features — for an app's own
    pickers, such as Project Management's choice of a project's lead.

        GET /api/gate/holders?key=<feature key>&action=use
        X-MAEC-App: projects
        X-MAEC-Gate-Secret: <the app's gate secret>

    200 {"core_user_ids": [...]}: active people with a seat on this app whose
    roles — including roles scoped to this app — allow <app>:<key>:<action>,
    decided by the same engine as the gate. Ids only: no address, no name.
    422 for a key or action that is not one of this app's, 403 for a caller
    that cannot prove it is the app. Authenticated exactly as /api/gate/check.
    """
    app_key, app, refused = _the_app(request, db, live=True)
    if refused is not None:
        return refused

    # Only its own features: the key is a feature key, never a permission key
    # naming another app, and it must be one this app has registered.
    if not features.KEY.match(key) or action not in features.ACTIONS:
        return JSONResponse({"detail": "key must be one of this app's feature keys, and action "
                                       f"one of {list(features.ACTIONS)}."},
                            status_code=422, headers=NO_STORE)
    permission_key = f"{app.key}:{key}:{action}"
    if db.scalar(select(Permission.id).where(Permission.application_id == app.id,
                                             Permission.key == permission_key)) is None:
        return JSONResponse({"detail": f"{app.key} has no feature {key!r} with action "
                                       f"{action!r}."}, status_code=422, headers=NO_STORE)

    seated = db.scalars(select(User).join(UserLicense, UserLicense.user_id == User.id).where(
        UserLicense.application_id == app.id, User.status == "active")).all()
    ids = sorted(str(person.id) for person in seated
                 if resolve(load(db, person, app.key), permission_key))
    return JSONResponse({"core_user_ids": ids}, headers=NO_STORE)
