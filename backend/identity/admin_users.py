"""User Management — create people, give them roles and seats.

This is the screen that makes the rest of the panel usable: screen 001 says
what a role may do, but until someone can be given that role it says it to
nobody. Before this existed, onboarding meant editing seed.py or opening psql.

The router is deliberately thin. Every rule — non-escalation, the last Global
Admin, seat limits, the password policy — lives in accounts.py, so the same
rule holds whether the caller is this screen, a CSV import or a future
directory sync. What is here is the translation of HTTP to intent, and of a
refusal into the right status code.
"""

from __future__ import annotations

import uuid
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import accounts, security
from .db import get_db
from .models import (
    Application, Role, Subscription, User, UserLicense, UserRole,
)
from .permissions import is_global_admin, require_global_admin

router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

PAGE_SIZE_MAX = 100
STATUSES = ("active", "suspended", "invited")


# ------------------------------------------------------------------ shapes
class UserCreate(BaseModel):
    # A plain constrained string rather than pydantic's EmailStr, which needs
    # the email-validator package — one dependency for one field, when
    # accounts.create_user validates server-side anyway. The shape check here
    # is only so the caller gets 422 rather than a rule violation.
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1024)
    department: str | None = Field(default=None, max_length=120)
    status: str = "active"

    @field_validator("email")
    @classmethod
    def _looks_like_an_address(cls, value: str) -> str:
        value = value.strip().lower()
        local, _, domain = value.partition("@")
        if not local or not domain or "." not in domain or " " in value:
            raise ValueError("That is not a valid email address.")
        return value


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=200)
    department: str | None = Field(default=None, max_length=120)
    status: str | None = None


class RoleGrant(BaseModel):
    role_id: uuid.UUID
    scope_type: str
    scope_id: str | None = Field(default=None, max_length=120)


class LicenseGrant(BaseModel):
    application_key: str = Field(max_length=40)


class PasswordReset(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


# ----------------------------------------------------------------- helpers
def _user_json(db: Session, user: User) -> dict:
    grants = db.scalars(select(UserRole).where(UserRole.user_id == user.id)).all()
    seats = db.scalars(select(UserLicense).where(UserLicense.user_id == user.id)).all()
    apps = {a.id: a for a in db.scalars(select(Application)).all()}
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "department": user.department,
        "status": user.status,
        "must_change_password": user.must_change_password,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "is_global_admin": is_global_admin(db, user),
        "roles": [
            {"grant_id": str(g.id), "role_id": str(g.role_id), "role": g.role.key,
             "name": g.role.name, "scope_type": g.scope_type, "scope_id": g.scope_id,
             "expires_at": g.expires_at.isoformat() if g.expires_at else None}
            for g in grants
        ],
        "licenses": [
            {"application_id": str(s.application_id),
             "application_key": apps[s.application_id].key if s.application_id in apps else "?",
             "application_name": apps[s.application_id].name if s.application_id in apps else "?"}
            for s in seats
        ],
    }


def _target(db: Session, actor: User, user_id: uuid.UUID) -> User:
    """The person being acted on — and never someone in another tenant."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No such user.")
    if user.org_id != actor.org_id and not is_global_admin(db, actor):
        raise HTTPException(status_code=404, detail="No such user.")
    return user


def _application(db: Session, key: str) -> Application:
    app = db.scalar(select(Application).where(Application.key == key))
    if app is None:
        raise HTTPException(status_code=422, detail=f"Unknown application {key!r}.")
    return app


def _refusal(exc: Exception) -> HTTPException:
    """One place that decides what a broken rule looks like over HTTP."""
    if isinstance(exc, accounts.EscalationError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, accounts.LastGlobalAdminError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (accounts.SeatsExhaustedError, accounts.NotSubscribedError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, security.WeakPasswordError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    raise exc


# ------------------------------------------------------------------ routes
@router.get("/users")
def list_users(db: Session = Depends(get_db),
               actor: User = Depends(require_global_admin),
               q: str = Query(default="", max_length=200),
               status: str | None = Query(default=None),
               page: int = Query(default=1, ge=1),
               page_size: int = Query(default=25, ge=1, le=PAGE_SIZE_MAX)):
    """People in this organisation. Filtered and paged in the database — an
    unbounded user table is a response that grows without limit."""
    where = [User.org_id == actor.org_id]
    if q.strip():
        needle = f"%{q.strip().lower()}%"
        where.append(or_(func.lower(User.email).like(needle),
                         func.lower(User.display_name).like(needle),
                         func.lower(func.coalesce(User.department, "")).like(needle)))
    if status:
        if status not in STATUSES:
            raise HTTPException(status_code=422, detail=f"Unknown status {status!r}.")
        where.append(User.status == status)

    total = db.scalar(select(func.count(User.id)).where(*where)) or 0
    rows = db.scalars(
        select(User).where(*where)
        .order_by(User.display_name)
        .offset((page - 1) * page_size).limit(page_size)).all()

    return {
        "users": [_user_json(db, u) for u in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, ceil(total / page_size)),
    }


@router.get("/users/options")
def options(db: Session = Depends(get_db),
            actor: User = Depends(require_global_admin)):
    """What the create/edit form may offer: the roles that exist and the
    applications this organisation actually holds, with seats remaining."""
    roles = db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)
    ).order_by(Role.level, Role.name)).all()

    apps = []
    for sub in db.scalars(select(Subscription).where(
            Subscription.org_id == actor.org_id)).all():
        app = db.get(Application, sub.application_id)
        if app is None:
            continue
        used = accounts.seats_in_use(db, actor.org_id, app.id)
        apps.append({
            "key": app.key, "name": app.name,
            "seats": sub.seats,                       # None = uncapped
            "seats_in_use": used,
            "seats_left": None if sub.seats is None else max(0, sub.seats - used),
        })

    return {
        "roles": [{"id": str(r.id), "key": r.key, "name": r.name, "level": r.level,
                   "is_system": r.org_id is None} for r in roles],
        "applications": apps,
        "scope_types": ["platform", "organization", "application", "project"],
        "statuses": list(STATUSES),
        "password_rules": {
            "min_length": security.MIN_PASSWORD_LENGTH,
            "needs": ["an uppercase letter", "a lowercase letter", "a digit", "a symbol"],
        },
    }


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    try:
        user = accounts.create_user(
            db, actor=actor, email=str(body.email), display_name=body.display_name,
            password=body.password, department=body.department, status=body.status,
            request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return _user_json(db, user)


@router.patch("/users/{user_id}")
def patch_user(user_id: uuid.UUID, body: UserPatch, request: Request,
               db: Session = Depends(get_db),
               actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    try:
        if body.display_name is not None or body.department is not None:
            accounts.update_user(db, actor=actor, target=target,
                                 display_name=body.display_name,
                                 department=body.department, request=request)
        if body.status is not None and body.status != target.status:
            # goes through set_user_status, which carries the last-admin rule
            accounts.set_user_status(db, actor=actor, target=target,
                                     status=body.status, request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return _user_json(db, target)


@router.delete("/users/{user_id}")
def delete_user(user_id: uuid.UUID, request: Request, db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    if target.id == actor.id:
        raise HTTPException(status_code=409,
                            detail="You cannot delete your own account.")
    try:
        accounts.delete_user(db, actor=actor, target=target, request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return {"deleted": str(user_id)}


@router.post("/users/{user_id}/roles", status_code=201)
def grant_role(user_id: uuid.UUID, body: RoleGrant, request: Request,
               db: Session = Depends(get_db),
               actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    role = db.get(Role, body.role_id)
    if role is None:
        raise HTTPException(status_code=422, detail="Unknown role.")
    if body.scope_type not in ("platform", "organization", "application", "project"):
        raise HTTPException(status_code=422, detail="Unknown scope type.")
    # the schema's own rule, stated here so the error is readable
    if body.scope_type == "platform" and body.scope_id:
        raise HTTPException(status_code=422, detail="Platform scope takes no id.")
    if body.scope_type != "platform" and not body.scope_id:
        raise HTTPException(status_code=422,
                            detail=f"{body.scope_type} scope needs an id.")
    try:
        accounts.grant_role(db, actor=actor, target=target, role=role,
                            scope_type=body.scope_type, scope_id=body.scope_id,
                            request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return _user_json(db, target)


@router.delete("/users/{user_id}/roles/{grant_id}")
def revoke_role(user_id: uuid.UUID, grant_id: uuid.UUID, request: Request,
                db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    grant = db.get(UserRole, grant_id)
    if grant is None or grant.user_id != target.id:
        raise HTTPException(status_code=404, detail="No such grant.")
    try:
        accounts.revoke_role(db, actor=actor, grant=grant, request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return _user_json(db, target)


@router.post("/users/{user_id}/licenses", status_code=201)
def assign_license(user_id: uuid.UUID, body: LicenseGrant, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    app = _application(db, body.application_key)
    try:
        accounts.assign_license(db, actor=actor, target=target, app=app, request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return _user_json(db, target)


@router.delete("/users/{user_id}/licenses/{application_key}")
def remove_license(user_id: uuid.UUID, application_key: str, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    target = _target(db, actor, user_id)
    app = _application(db, application_key)
    accounts.remove_license(db, actor=actor, target=target, app=app, request=request)
    return _user_json(db, target)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: uuid.UUID, body: PasswordReset, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    """Set a new password. The person must change it before doing anything
    else — an administrator knows this one."""
    target = _target(db, actor, user_id)
    try:
        accounts.set_password(db, actor=actor, target=target, password=body.password,
                              by_admin=True, request=request)
    except Exception as exc:
        raise _refusal(exc) from exc
    return {"id": str(target.id), "must_change_password": True}
