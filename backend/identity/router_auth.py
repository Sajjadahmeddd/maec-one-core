"""POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me.

Every outcome of a login attempt is recorded — success, failure, lockout —
with the address that tried and where from, so the audit screen has real
data from the first day.

One message for every failure. Unknown address, wrong password, suspended
account, locked account: the reply is the same and takes the same time, so
nothing about the account list leaks through the login form.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from . import accounts, lockout, security, sessions
from .db import get_db
from .models import (
    Application, Organization, Subscription, User, UserLicense,
)
from .permissions import (
    active_roles, audit, current_user, is_global_admin, now, organization_active,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

def _client_key(request: Request) -> str:
    """The rate limit's key: the client's address as security.client_ip
    resolves it — the real visitor behind a trusted proxy, never a header
    the visitor wrote."""
    return security.client_ip(request) or "unknown"


# Per-IP. The per-account limit is the lockout (lockout.py); the two together
# stop both a wide guess across many accounts and a deep guess at one.
limiter = Limiter(key_func=_client_key)
LOGIN_RATE = "10/minute"

GENERIC_FAILURE = "Incorrect email address or password."

# The lockout: per account and client address, a fixed window, and a count
# that starts again when a lock expires. lockout.py has the rules; the numbers
# are importable from here, where the audit screen's card reads them.
LOCK_AFTER = lockout.LOCK_AFTER
LOCK_BASE = lockout.LOCK_BASE
LOCK_CAP = lockout.LOCK_CAP


def _find_user(db: Session, email: str) -> User | None:
    """By (org, email). The org comes from the address's domain; if no
    organisation claims that domain, a unique match on the address alone
    still counts, so a contractor on another domain can be given a seat."""
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    org = db.scalar(select(Organization).where(Organization.domain == domain)) if domain else None
    if org is not None:
        found = db.scalar(select(User).where(User.org_id == org.id, User.email == email))
        if found is not None:
            return found
    candidates = db.scalars(select(User).where(User.email == email)).all()
    return candidates[0] if len(candidates) == 1 else None


def _apps_payload(db: Session, user: User | None) -> list[dict]:
    """The catalogue, and — for a signed-in person — what they may open.

    Computed here from subscriptions and seats, never from the client. The
    launcher renders exactly this list: a tile for every application that is
    not inactive (retired), which opens when it is live, `entitled` is true,
    and it has a base_url.

    One query for the catalogue, whatever the number of applications: each
    application with this organisation's subscription to it and this
    person's seat on it, outer-joined — at most one of each, by the unique
    constraints on (org_id, application_id) and (user_id, application_id).
    Calling `entitled()` once per app read the application, its subscription
    and the licence each time — twenty-two queries for eight apps, on the
    endpoint every page load hits. The organisation check is `entitled()`'s
    own, not a copy of it: this list and the engine must never disagree about
    what someone may open.
    """
    if user is None:
        apps = db.scalars(select(Application).where(Application.status != "inactive")
                          .order_by(Application.name)).all()
        return [{"key": a.key, "name": a.name, "description": a.description,
                 "status": a.status, "base_url": a.base_url} for a in apps]

    rows = db.execute(
        select(Application, Subscription.valid_from, Subscription.valid_to,
               UserLicense.id)
        .outerjoin(Subscription, and_(Subscription.application_id == Application.id,
                                      Subscription.org_id == user.org_id))
        .outerjoin(UserLicense, and_(UserLicense.application_id == Application.id,
                                     UserLicense.user_id == user.id))
        .where(Application.status != "inactive")
        .order_by(Application.name)
    ).all()

    # A suspended organisation holds nothing, whatever it has paid for.
    active = organization_active(db, user)
    moment = now()
    out = []
    for app, valid_from, valid_to, seat in rows:
        in_date = (valid_from is not None
                   and _as_utc(valid_from) <= moment
                   and (valid_to is None or _as_utc(valid_to) >= moment))
        out.append({"key": app.key, "name": app.name, "description": app.description,
                    "status": app.status, "base_url": app.base_url,
                    "entitled": bool(active and in_date and seat is not None)})
    return out


def _me_payload(request: Request, db: Session, user: User) -> dict:
    return {
        "authenticated": True,
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "org_id": str(user.org_id),
        "roles": [
            {"role": g.role.key, "scope_type": g.scope_type, "scope_id": g.scope_id}
            for g in active_roles(db, user)
        ],
        "is_global_admin": is_global_admin(db, user),
        "permissions_version": user.permissions_version,
        # The frontend routes to the change-password screen on this, and the
        # guard refuses everything else until it clears — the flag is not the
        # enforcement, it is the explanation for it.
        "must_change_password": user.must_change_password,
        # Explains an empty launcher. Not the enforcement — entitled() is —
        # and read from the same function, so the two cannot disagree.
        "organization_suspended": not organization_active(db, user),
        "apps": _apps_payload(db, user),
        "csrf_token": security.csrf_token(request),
    }


# ------------------------------------------------------------------ routes
@router.get("/me")
def me(request: Request, db: Session = Depends(get_db),
       user: User | None = Depends(current_user)):
    """Drives the frontend: who you are and what you may open — or, before
    signing in, just the catalogue the sign-in screen shows."""
    if user is None:
        return {"authenticated": False, "apps": _apps_payload(db, None)}
    return _me_payload(request, db, user)


@router.post("/login")
@limiter.limit(LOGIN_RATE)
def login(request: Request, payload: dict, db: Session = Depends(get_db)):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    # An address longer than the column can never match a stored user, so it
    # is a failed login by definition — but it must be a tidy one. Cap it here
    # so the lookup and the audit row it produces both stay inside their
    # widths rather than reaching the database oversized.
    if len(email) > 254 or len(password) > 1024:
        user = None
        email = email[:254]
    else:
        user = _find_user(db, email) if email else None
    moment = now()

    # Verify the hash even when there is no user or the account is locked:
    # every failure path must cost the same as a wrong password.
    hash_ok = security.verify_password(password, user.password_hash if user else None)

    # Locked for *this* address only: someone guessing elsewhere does not lock
    # the owner out. An expired lock is reset here, its count back to zero.
    address = security.client_ip(request)
    locked = user is not None and lockout.locked(db, user, address, at=moment)
    usable = user is not None and user.status == "active" and not locked

    if not (usable and hash_ok):
        if user is not None:
            row = lockout.record_failure(db, user, address, at=moment)
            newly_locked = (not locked and row.locked_until is not None
                            and _as_utc(row.locked_until) > moment)
            audit(db, actor=user, action="login.failed", target_type="user",
                  target_id=user.id, source="login", result="warning", request=request,
                  after={"failed_attempts": row.failed_count,
                         "locked": locked or newly_locked}, commit=False)
            if newly_locked:
                audit(db, actor=user, action="login.locked", target_type="user",
                      target_id=user.id, source="login", result="blocked",
                      request=request,
                      after={"locked_until": row.locked_until.isoformat(),
                             "lock_number": row.strikes}, commit=False)
            db.commit()
        else:
            audit(db, actor_email=email or None, action="login.failed",
                  target_type="user", target_id=None, source="login",
                  result="warning", request=request)
        raise HTTPException(status_code=401, detail=GENERIC_FAILURE)

    # success: this address's failures and strikes are forgotten; a lock
    # another address earned stays where it is
    lockout.clear(db, user.id, address)
    user.last_login_at = moment
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    # A new sessions row and a new cookie. Whatever this browser held before
    # is revoked: the fixation defence.
    sessions.start(db, request, user, at=moment)
    audit(db, actor=user, action="login.success", target_type="user", target_id=user.id,
          source="login", result="success", request=request, commit=False)
    db.commit()
    return _me_payload(request, db, user)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request,
                    db: Session = Depends(get_db),
                    user: User | None = Depends(current_user)):
    """Set your own password.

    Reachable while `must_change_password` is set — it is the one thing that
    is, because it is the way out. The current password is still required:
    an unattended session must not be enough to take an account over.
    """
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in required.")

    if not security.verify_password(body.current_password, user.password_hash):
        audit(db, actor=user, action="user.password.self", target_type="user",
              target_id=user.id, result="warning", request=request,
              after={"reason": "current password did not match"})
        raise HTTPException(status_code=403, detail="That is not your current password.")

    if body.new_password == body.current_password:
        raise HTTPException(status_code=422,
                            detail="The new password must be different.")

    try:
        # revokes every session this person holds, this one included
        accounts.set_password(db, actor=user, target=user, password=body.new_password,
                              by_admin=False, request=request)
    except security.WeakPasswordError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # ...and this browser, which just proved the password, gets a new one. The
    # net effect is "every other session signed out", with a fresh id here.
    sessions.start(db, request, user)
    db.commit()
    return _me_payload(request, db, user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db),
           user: User | None = Depends(current_user)):
    """Revoke this browser's session — on the server, so a copy of the cookie
    taken before now is worthless too — and clear the cookie."""
    sessions.end(db, request)
    if user is not None:
        audit(db, actor=user, action="logout", target_type="user", target_id=user.id,
              source="api", result="success", request=request, commit=False)
    db.commit()
    return {"authenticated": False}


def _as_utc(value):
    from datetime import timezone
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
