"""The rules a change to a person must obey.

User Management calls all of these. They live here rather than in the router
so the rules hold whatever calls them — a screen, a CSV import, a future
directory sync — and so the router stays a thin translation of HTTP to intent.

Three things can never happen, and each is refused here:

  * an administrator handing out more than they hold;
  * the last Global Admin losing the role, being suspended or deleted;
  * a seat being assigned that the organisation has not paid for.
"""

from __future__ import annotations

import uuid

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import security
from .models import (
    Application, Role, RolePermission, Subscription, User, UserLicense, UserRole,
)
from .permissions import (
    GLOBAL_ADMIN, active_roles, audit, bump_permissions_version, can,
    is_global_admin, now,
)


class LastGlobalAdminError(Exception):
    """Refused: this would leave the platform with no Global Admin."""


class EscalationError(PermissionError):
    """Refused: the actor tried to grant more than they hold."""


class SeatsExhaustedError(Exception):
    """Refused: the organisation has no seat left on that application."""


class NotSubscribedError(Exception):
    """Refused: the organisation does not hold that application at all."""


# ----------------------------------------------------- the last admin
def global_admin_holders(db: Session) -> list[User]:
    """Every active account currently holding global_admin at platform."""
    rows = db.scalars(
        select(UserRole).join(Role).where(
            Role.key == GLOBAL_ADMIN, UserRole.scope_type == "platform")).all()
    holders: dict[uuid.UUID, User] = {}
    for grant in rows:
        if grant.expires_at is not None:
            continue
        user = db.get(User, grant.user_id)
        if user is not None and user.status == "active":
            holders[user.id] = user
    return list(holders.values())


def _is_global_admin_grant(grant: UserRole) -> bool:
    return grant.scope_type == "platform" and grant.role.key == GLOBAL_ADMIN


def _would_remove_last_admin(db: Session, user: User) -> bool:
    holders = global_admin_holders(db)
    return len(holders) == 1 and holders[0].id == user.id


# ---------------------------------------------------------------- grants
def _administers(db: Session, actor: User, role: Role,
                 scope_type: str, scope_id: str | None) -> bool:
    """May the actor hand out this role at this scope at all?

    Global Admin may, anywhere. Otherwise the actor needs a role that sits
    above the one being granted and whose own scope contains the target.
    """
    if is_global_admin(db, actor):
        return True
    for held in active_roles(db, actor):
        if held.role.level >= role.level:
            continue
        if held.scope_type == "platform":
            return True
        if held.scope_type == "organization" and held.scope_id == str(actor.org_id):
            return True
        if held.scope_type == "application" and scope_type in ("application", "project"):
            # a lead of an application places people within it; without a
            # project registry the app is the nearest container we can check
            if scope_type == "application" and held.scope_id == scope_id:
                return True
            if scope_type == "project":
                return True
        if held.scope_type == "project" and scope_type == "project" and held.scope_id == scope_id:
            return True
    return False


def may_grant(db: Session, *, actor: User, target_org_id, role: Role,
              scope_type: str, scope_id: str | None) -> str | None:
    """Why this grant would be refused, or None if it would go through.

    Asked, never acted on. `grant_role` calls it before writing, and the CSV
    import calls it to build its preview — which is the only way the preview
    can be guaranteed to match what the commit does. A second implementation
    that agreed today would be a screen showing one thing and doing another
    the first time the two drifted.
    """
    if target_org_id != actor.org_id and not is_global_admin(db, actor):
        return "actor and target are in different organisations"
    if not _administers(db, actor, role, scope_type, scope_id):
        return "actor does not administer that scope"
    if is_global_admin(db, actor):
        return None
    probe = (scope_type, scope_id) if scope_type != "platform" else None
    allowed = db.scalars(select(RolePermission).where(
        RolePermission.role_id == role.id, RolePermission.effect == "allow")).all()
    for rp in allowed:
        if not can(db, actor, rp.permission.key, probe):
            return f"actor does not hold {rp.permission.key}"
    return None


def grant_role(db: Session, *, actor: User, target: User, role: Role,
               scope_type: str, scope_id: str | None,
               request: Request | None = None,
               commit: bool = True) -> UserRole:
    """Give `target` `role` at a scope — if `actor` may.

    The rule lives in `may_grant`; this performs what that permits. A refusal
    is a 403 in the caller and a `blocked` audit row here.
    """
    why = may_grant(db, actor=actor, target_org_id=target.org_id, role=role,
                    scope_type=scope_type, scope_id=scope_id)
    if why is not None:
        _refuse(db, actor, target, role, scope_type, scope_id, request, why)

    grant = UserRole(user_id=target.id, role_id=role.id, scope_type=scope_type,
                     scope_id=scope_id, granted_by=actor.id)
    db.add(grant)
    db.flush()
    bump_permissions_version(db, target.id)
    audit(db, actor=actor, action="role.grant", target_type="user", target_id=target.id,
          result="success", request=request,
          after={"role": role.key, "scope_type": scope_type, "scope_id": scope_id},
          commit=False)
    if commit:
        db.commit()
    return grant


def _refuse(db, actor, target, role, scope_type, scope_id, request, why: str):
    audit(db, actor=actor, action="role.grant", target_type="user", target_id=target.id,
          result="blocked", request=request,
          after={"role": role.key, "scope_type": scope_type, "scope_id": scope_id,
                 "reason": why})
    raise EscalationError(f"Not permitted: {why}.")


def revoke_role(db: Session, *, actor: User, grant: UserRole,
                request: Request | None = None) -> None:
    """Take a grant away — unless it is the last Global Admin's."""
    target = db.get(User, grant.user_id)
    if target is None:
        raise LookupError("no such user")
    if _is_global_admin_grant(grant) and _would_remove_last_admin(db, target):
        audit(db, actor=actor, action="role.revoke", target_type="user",
              target_id=target.id, result="blocked", request=request,
              before={"role": GLOBAL_ADMIN, "scope_type": "platform",
                      "reason": "last global admin"})
        raise LastGlobalAdminError(
            "Cannot remove the last Global Admin. Assign another first.")
    before = {"role": grant.role.key, "scope_type": grant.scope_type,
              "scope_id": grant.scope_id}
    db.delete(grant)
    db.flush()
    bump_permissions_version(db, target.id)
    audit(db, actor=actor, action="role.revoke", target_type="user", target_id=target.id,
          result="success", request=request, before=before, commit=False)
    db.commit()


# ------------------------------------------------------------- the person
def set_user_status(db: Session, *, actor: User, target: User, status: str,
                    request: Request | None = None) -> None:
    if status not in ("active", "suspended", "invited"):
        raise ValueError(f"unknown status {status!r}")
    if status != "active" and _would_remove_last_admin(db, target):
        audit(db, actor=actor, action="user.status", target_type="user", target_id=target.id,
              result="blocked", request=request,
              before={"status": target.status},
              after={"status": status, "reason": "last global admin"})
        raise LastGlobalAdminError(
            "Cannot suspend the last Global Admin. Assign another first.")
    before = {"status": target.status}
    target.status = status
    db.flush()
    bump_permissions_version(db, target.id)
    audit(db, actor=actor, action="user.status", target_type="user", target_id=target.id,
          result="success", request=request, before=before, after={"status": status},
          commit=False)
    db.commit()


def delete_user(db: Session, *, actor: User, target: User,
                request: Request | None = None) -> None:
    if _would_remove_last_admin(db, target):
        audit(db, actor=actor, action="user.delete", target_type="user", target_id=target.id,
              result="blocked", request=request,
              before={"email": target.email, "reason": "last global admin"})
        raise LastGlobalAdminError(
            "Cannot delete the last Global Admin. Assign another first.")
    before = {"email": target.email, "display_name": target.display_name}
    db.delete(target)
    db.flush()
    audit(db, actor=actor, action="user.delete", target_type="user", target_id=target.id,
          result="success", request=request, before=before, commit=False)
    db.commit()


# ------------------------------------------------------------- the person
def create_user(db: Session, *, actor: User, email: str, display_name: str,
                password: str, department: str | None = None,
                status: str = "active", request: Request | None = None,
                commit: bool = True) -> User:
    """Create an account with a password the administrator chose.

    `must_change_password` is set, always. An administrator necessarily knows
    the password they just typed, so it cannot be the one that goes on
    guarding the account — the person changes it before they can do anything
    else, enforced in guard.py rather than merely asked for in the UI.
    """
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("A valid email address is required.")
    if not display_name.strip():
        raise ValueError("A name is required.")
    if status not in ("active", "invited"):
        raise ValueError("A new account is either active or invited.")

    security.check_password_policy(password, email=email)

    if db.scalar(select(User).where(User.org_id == actor.org_id, User.email == email)):
        raise ValueError(f"{email} already has an account.")

    user = User(org_id=actor.org_id, email=email, display_name=display_name.strip(),
                department=(department or None), status=status,
                password_hash=security.hash_password(password),
                must_change_password=True)
    db.add(user)
    db.flush()
    audit(db, actor=actor, action="user.create", target_type="user", target_id=user.id,
          result="success", request=request,
          after={"email": user.email, "display_name": user.display_name,
                 "department": user.department, "status": user.status},
          commit=False)
    if commit:
        db.commit()
    return user


def set_password(db: Session, *, actor: User, target: User, password: str,
                 by_admin: bool = True, request: Request | None = None) -> None:
    """Set a password. Never logged, never returned, never stored reversibly.

    An administrator's reset forces a change at next sign-in; a person setting
    their own does not, because they are then the only one who knows it.
    """
    security.check_password_policy(password, email=target.email)
    target.password_hash = security.hash_password(password)
    target.must_change_password = by_admin
    target.failed_login_count = 0
    target.locked_until = None
    db.flush()
    audit(db, actor=actor,
          action="user.password" if by_admin else "user.password.self",
          target_type="user", target_id=target.id, result="success", request=request,
          after={"must_change_password": target.must_change_password}, commit=False)
    db.commit()


def update_user(db: Session, *, actor: User, target: User,
                display_name: str | None = None, department: str | None = None,
                request: Request | None = None) -> None:
    """Name and department only. Status goes through set_user_status, which
    carries the last-admin rule."""
    before = {"display_name": target.display_name, "department": target.department}
    if display_name is not None:
        if not display_name.strip():
            raise ValueError("A name is required.")
        target.display_name = display_name.strip()
    if department is not None:
        target.department = department.strip() or None
    db.flush()
    audit(db, actor=actor, action="user.update", target_type="user", target_id=target.id,
          result="success", request=request, before=before,
          after={"display_name": target.display_name, "department": target.department},
          commit=False)
    db.commit()


def placement_scope(db: Session, actor: User) -> tuple[tuple[str, str | None], str | None]:
    """Where this person may place others: the scope they administer.

    A CSV import and a directory-group mapping both confer a role on someone
    who does not exist yet, and both need the same answer — so they ask the
    same function rather than keeping a copy each that agrees today.

    Neither ever confers platform scope. A Global Admin places people across
    the organisation; someone who leads one application places them in that
    application. Deriving it from the actor rather than fixing it at
    "organization" is what keeps the grant check meaningful — otherwise an
    application lead is refused every row, including roles well below them,
    for a reason that has nothing to do with what they asked for.
    """
    if is_global_admin(db, actor):
        return ("organization", str(actor.org_id)), None

    application_scopes = sorted({
        g.scope_id for g in active_roles(db, actor)
        if g.scope_type == "application" and g.scope_id})
    if len(application_scopes) == 1:
        return ("application", application_scopes[0]), None
    if not application_scopes:
        return ("organization", str(actor.org_id)), (
            "You do not administer a scope to place people in.")
    # More than one, and the file does not say which. Refusing is honest;
    # guessing would place people somewhere nobody chose.
    return ("organization", str(actor.org_id)), (
        "You lead more than one application ("
        + ", ".join(application_scopes)
        + "), so which of them these people belong to is ambiguous. "
          "Work one application at a time.")


# -------------------------------------------------------------- the seats
def seats_in_use(db: Session, org_id: uuid.UUID, application_id: uuid.UUID) -> int:
    """How many people in this organisation hold a seat on this application."""
    return db.scalar(
        select(func.count(UserLicense.id))
        .join(User, User.id == UserLicense.user_id)
        .where(User.org_id == org_id,
               UserLicense.application_id == application_id)) or 0


def assign_license(db: Session, *, actor: User, target: User, app: Application,
                   request: Request | None = None,
                   commit: bool = True) -> UserLicense:
    """Give someone a seat — if the organisation has one to give.

    `seats` NULL means uncapped, which is how the seed writes it. A number
    means exactly that many, and the count is taken here rather than trusted
    from a field that could drift out of step with the licence rows.
    """
    subscription = db.scalar(select(Subscription).where(
        Subscription.org_id == target.org_id,
        Subscription.application_id == app.id))
    moment = now()
    in_date = (subscription is not None
               and _as_utc(subscription.valid_from) <= moment
               and (subscription.valid_to is None
                    or _as_utc(subscription.valid_to) >= moment))
    if not in_date:
        audit(db, actor=actor, action="license.assign", target_type="user",
              target_id=target.id, result="blocked", request=request,
              application_id=app.id,
              after={"application": app.key, "reason": "no active subscription"})
        raise NotSubscribedError(
            f"Your organisation does not hold an active subscription to {app.name}.")

    existing = db.scalar(select(UserLicense).where(
        UserLicense.user_id == target.id, UserLicense.application_id == app.id))
    if existing is not None:
        return existing

    if subscription.seats is not None:
        used = seats_in_use(db, target.org_id, app.id)
        if used >= subscription.seats:
            audit(db, actor=actor, action="license.assign", target_type="user",
                  target_id=target.id, result="blocked", request=request,
                  application_id=app.id,
                  after={"application": app.key, "seats": subscription.seats,
                         "in_use": used, "reason": "no seat free"})
            raise SeatsExhaustedError(
                f"All {subscription.seats} {app.name} seats are in use. "
                "Free one, or increase the subscription.")

    seat = UserLicense(user_id=target.id, application_id=app.id, assigned_by=actor.id)
    db.add(seat)
    db.flush()
    bump_permissions_version(db, target.id)
    audit(db, actor=actor, action="license.assign", target_type="user",
          target_id=target.id, result="success", request=request,
          application_id=app.id, after={"application": app.key}, commit=False)
    if commit:
        db.commit()
    return seat


def remove_license(db: Session, *, actor: User, target: User, app: Application,
                   request: Request | None = None) -> None:
    """Take a seat back. Immediate: the guard re-reads entitlement on every
    request, so the next call that needs it is refused."""
    seat = db.scalar(select(UserLicense).where(
        UserLicense.user_id == target.id, UserLicense.application_id == app.id))
    if seat is None:
        return
    db.delete(seat)
    db.flush()
    bump_permissions_version(db, target.id)
    audit(db, actor=actor, action="license.remove", target_type="user",
          target_id=target.id, result="success", request=request,
          application_id=app.id, before={"application": app.key}, commit=False)
    db.commit()


def _as_utc(value):
    from datetime import timezone
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
