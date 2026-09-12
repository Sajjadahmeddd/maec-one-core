"""POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me.

Every outcome of a login attempt is recorded — success, failure, lockout —
with the address that tried and where from, so the audit screen has real
data from the first day.

One message for every failure. Unknown address, wrong password, suspended
account, locked account: the reply is the same and takes the same time, so
nothing about the account list leaks through the login form.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import accounts, security
from .db import get_db
from .models import (
    Application, Organization, Subscription, User, UserLicense,
)
from .permissions import (
    active_roles, audit, current_user, is_global_admin, now,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Per-IP. The per-account limit is the lockout below; the two together stop
# both a wide guess across many accounts and a deep guess at one.
limiter = Limiter(key_func=get_remote_address)
LOGIN_RATE = "10/minute"

GENERIC_FAILURE = "Incorrect email address or password."

# Escalating lockout. After this many failures the account locks for a
# minute, doubling with each further failure, up to the cap.
LOCK_AFTER = 5
LOCK_BASE = timedelta(minutes=1)
LOCK_CAP = timedelta(minutes=30)


def _lock_for(failures: int) -> timedelta:
    steps = max(0, failures - LOCK_AFTER)
    return min(LOCK_BASE * (2 ** steps), LOCK_CAP)


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
    launcher renders exactly this list.

    Three queries, whatever the number of applications. Calling `entitled()`
    once per app read the application, its subscription and the licence each
    time — twenty-two queries for eight apps, on the endpoint every page load
    hits. The three reads below answer the same question: what exists, what
    this organisation subscribes to, and which seats this person holds.
    """
    apps = db.scalars(select(Application).order_by(Application.name)).all()
    out = [{"key": a.key, "name": a.name, "description": a.description,
            "status": a.status, "base_url": a.base_url} for a in apps]
    if user is None:
        return out

    moment = now()
    subscriptions = {
        s.application_id: s for s in db.scalars(select(Subscription).where(
            Subscription.org_id == user.org_id)).all()
    }
    seats = {
        row for row in db.scalars(select(UserLicense.application_id).where(
            UserLicense.user_id == user.id)).all()
    }

    for app, item in zip(apps, out):
        sub = subscriptions.get(app.id)
        in_date = (sub is not None
                   and _as_utc(sub.valid_from) <= moment
                   and (sub.valid_to is None or _as_utc(sub.valid_to) >= moment))
        item["entitled"] = bool(in_date and app.id in seats)
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

    locked = (user is not None and user.locked_until is not None
              and _as_utc(user.locked_until) > moment)
    usable = user is not None and user.status == "active" and not locked

    if not (usable and hash_ok):
        if user is not None:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            newly_locked = False
            if user.failed_login_count >= LOCK_AFTER:
                user.locked_until = moment + _lock_for(user.failed_login_count)
                newly_locked = True
            audit(db, actor=user, action="login.failed", target_type="user",
                  target_id=user.id, source="login", result="warning", request=request,
                  after={"failed_login_count": user.failed_login_count,
                         "locked": locked or newly_locked}, commit=False)
            if newly_locked:
                audit(db, actor=user, action="login.locked", target_type="user",
                      target_id=user.id, source="login", result="blocked",
                      request=request,
                      after={"locked_until": user.locked_until.isoformat()}, commit=False)
            db.commit()
        else:
            audit(db, actor_email=email or None, action="login.failed",
                  target_type="user", target_id=None, source="login",
                  result="warning", request=request)
        raise HTTPException(status_code=401, detail=GENERIC_FAILURE)

    # success
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = moment
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    security.start_session(request, user_id=str(user.id),
                           permissions_version=user.permissions_version)
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
        accounts.set_password(db, actor=user, target=user, password=body.new_password,
                              by_admin=False, request=request)
    except security.WeakPasswordError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # a new password is a good moment for a new session identifier
    security.start_session(request, user_id=str(user.id),
                           permissions_version=user.permissions_version)
    return _me_payload(request, db, user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db),
           user: User | None = Depends(current_user)):
    if user is not None:
        audit(db, actor=user, action="logout", target_type="user", target_id=user.id,
              source="api", result="success", request=request)
    security.end_session(request)
    return {"authenticated": False}


def _as_utc(value):
    from datetime import timezone
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
