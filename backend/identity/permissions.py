"""The permission engine, as Core runs it: from rows.

    can(db, user, "engineering:hapext:convert", scope=("project", "P-2291"))

`can()` loads everything a decision reads (`load`) and hands it to
`resolution.resolve`, which runs the five steps — entitlement, collect roles,
filter by scope, most-specific-wins with deny beating allow on a tie, then
tool rules that may only take away — with no database in sight. A product
runs the same `resolve` over a token's claims. One engine, two sources
(OPEN-DECISIONS #11). Any error at any step is a refusal; nothing here
defaults to allow.

Also here: the FastAPI dependencies that put the engine in front of a route,
the version bump that makes a change bite within seconds, and the audit
writer. They live together because they share the same reading of the
session and the same failure posture.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .db import get_db
from .models import (
    Application, AuditLog, Organization, Permission, Role, RolePermission,
    Subscription, ToolRule, User, UserLicense, UserRole,
)
# The resolution moved to resolution.py so a product can import it without a
# database. Its names have always been importable from here, and still are.
from .resolution import (  # noqa: F401  (re-exported)
    HIDES_FROM_NAV, LEVEL_IMPLIES, SPECIFICITY, _LEVEL_ALLOWS, Grant,
    ResolutionInput, _utc, app_of, fail_closed, now, resolve, split_key,
)

GLOBAL_ADMIN = "global_admin"

# What an audit row records when there is genuinely nobody to name: a login
# attempt that supplied no address at all. Every other path has an actor.
#
# A sentinel rather than NULL because `actor_id` no longer carries a foreign
# key — `actor_email` is the only durable identity on a row, and "should
# always be populated" enforced by nothing is the exact shape of the bug that
# removal fixed. The column is NOT NULL; this is what makes that possible.
# It cannot collide with a real address: it has no "@".
ANONYMOUS_ACTOR = "(anonymous)"


# ----------------------------------------------------------- entitlement
def organization_active(db: Session, user: User) -> bool:
    """Is this person's organisation live?

    A suspended organisation keeps its data and its people can still sign
    in, but it holds nothing: no application, and no tenant-scoped privilege.
    Read on every check, so a suspension bites on the next request — the same
    re-read that makes suspending a person immediate. OPEN-DECISIONS #14.
    """
    try:
        org = db.get(Organization, user.org_id)
        return org is not None and org.status == "active"
    except Exception as exc:
        fail_closed('organization_active', exc)
        return False


def entitled(db: Session, user: User, app_key: str) -> bool:
    """Org live, subscribed and in date, and this person holds a seat."""
    try:
        app = db.scalar(select(Application).where(Application.key == app_key))
        if app is None:
            return False
        # A suspended organisation holds nothing, whatever it has paid for.
        # Checked before the subscription so the reason is the first one found.
        if not organization_active(db, user):
            return False
        sub = db.scalar(select(Subscription).where(
            Subscription.org_id == user.org_id,
            Subscription.application_id == app.id))
        if sub is None:
            return False
        moment = now()
        if _utc(sub.valid_from) > moment:
            return False
        if sub.valid_to is not None and _utc(sub.valid_to) < moment:
            return False
        seat = db.scalar(select(UserLicense).where(
            UserLicense.user_id == user.id,
            UserLicense.application_id == app.id))
        return seat is not None
    except Exception as exc:
        fail_closed('entitled', exc)
        return False


# ----------------------------------------------------------------- roles
def active_roles(db: Session, user: User) -> list[UserRole]:
    moment = now()
    rows = db.scalars(select(UserRole).where(UserRole.user_id == user.id)).all()
    return [r for r in rows if r.expires_at is None or _utc(r.expires_at) > moment]


def holds_business_admin(db: Session, user: User) -> bool:
    """Does this person lead any application, in a live organisation?

    Used by the guard to decide whether to let them as far as the audit
    reads, and by the audit endpoint's own check; what they may then *see* is
    scoped by the endpoint. The role's reach is tenant-scoped, so a suspended
    organisation's lead holds nothing. OPEN-DECISIONS #14.
    """
    try:
        if not organization_active(db, user):
            return False
        return any(g.role.key == "business_admin" for g in active_roles(db, user))
    except Exception as exc:
        fail_closed('holds_business_admin', exc)
        return False


def is_global_admin(db: Session, user: User) -> bool:
    # Deliberately not conditioned on the organisation's status. Global Admin
    # is a platform role and the person who would restore a suspended
    # organisation: they lose its applications through entitled(), not the
    # panel through this. OPEN-DECISIONS #14.
    try:
        for grant in active_roles(db, user):
            if grant.scope_type == "platform" and grant.role.key == GLOBAL_ADMIN:
                return True
        return False
    except Exception as exc:
        fail_closed('is_global_admin', exc)
        return False


# ---------------------------------------------------------- load(), can()
def load(db: Session, user: User, app_key: str) -> ResolutionInput:
    """Everything this person's decisions about one application read.

    The same tables `can()` has always read — the application, the
    organisation, the subscription, the seat, the grants and their roles, the
    role permissions, the tool rules — gathered in one pass instead of one
    query per grant. The token endpoint builds its claims from this, so a
    token carries exactly what `can()` would have decided from.

    Raises on a database error. `can()` fails closed around it; the token
    endpoint refuses to mint.
    """
    org_id = str(user.org_id)
    app = db.scalar(select(Application).where(Application.key == app_key))
    if app is None or not entitled(db, user, app_key):
        return ResolutionInput(app_key=app_key, org_id=org_id, entitled=False)

    entitled_until = _utc(db.scalar(select(Subscription.valid_to).where(
        Subscription.org_id == user.org_id,
        Subscription.application_id == app.id)))

    moment = now()
    grants = tuple(
        Grant(role_id=str(grant.role_id), role_key=role_key,
              scope_type=grant.scope_type, scope_id=grant.scope_id,
              expires_at=_utc(grant.expires_at))
        for grant, role_key in db.execute(
            select(UserRole, Role.key)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user.id)).all()
        if grant.expires_at is None or _utc(grant.expires_at) > moment
    )

    role_ids = {uuid.UUID(g.role_id) for g in grants}
    role_permissions: dict[tuple[str, str], str] = {}
    tool_rules: dict[tuple[str, str], str] = {}
    if role_ids:
        for role_id, key, effect in db.execute(
                select(RolePermission.role_id, Permission.key, RolePermission.effect)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id.in_(role_ids),
                       Permission.application_id == app.id)).all():
            role_permissions[(str(role_id), key)] = effect
        for module_key, role_id, level in db.execute(
                select(ToolRule.module_key, ToolRule.role_id, ToolRule.access_level)
                .where(ToolRule.org_id == user.org_id,
                       ToolRule.application_id == app.id,
                       ToolRule.role_id.in_(role_ids))).all():
            tool_rules[(module_key, str(role_id))] = level

    return ResolutionInput(
        app_key=app_key, org_id=org_id, entitled=True,
        entitled_until=entitled_until, grants=grants,
        role_permissions=role_permissions, tool_rules=tool_rules,
    )


def can(db: Session, user: User | None, permission_key: str,
        scope: tuple[str, str | None] | None = None) -> bool:
    """May this person do this thing, here? False on any doubt.

    Load, then resolve. The resolution is `resolution.resolve` — the same
    function a product runs over a token's claims.
    """
    try:
        if user is None or user.status != "active":
            return False
        return resolve(load(db, user, app_of(permission_key)), permission_key, scope)
    except Exception as exc:
        fail_closed('can', exc)
        return False


# ----------------------------------------------------- the current user
def load_user(db: Session, user_id: str | None) -> User | None:
    """The account behind a session, or None if it should not be trusted."""
    if not user_id:
        return None
    try:
        user = db.get(User, uuid.UUID(str(user_id)))
    except (ValueError, TypeError):
        return None
    if user is None or user.status != "active":
        return None
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    # The guard resolved this already for every guarded path and kept the
    # instance alive on the request. Reading it back is the whole point of
    # sharing the session; asking again would be the same row, twice.
    user = getattr(request.state, "identity_user", None)
    if user is None:
        user = load_user(db, security.session_user_id(request))
    if user is not None:
        # The version in the cookie is what the session was issued against.
        # Roles are re-read on every check anyway, so this only keeps the
        # cookie honest for the client that asks.
        if request.session.get(security.S_VERSION) != user.permissions_version:
            request.session[security.S_VERSION] = user.permissions_version
    return user


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return user


def require_global_admin(request: Request, user: User = Depends(require_user),
                         db: Session = Depends(get_db)) -> User:
    # The guard already answered this for anything under /api/admin/ and left
    # the answer on the request. Asking again would re-read the roles for no
    # new information — this dependency is the second lock on the same door,
    # not a second question.
    decided = getattr(request.state, "is_global_admin", None)
    if decided is None:
        decided = is_global_admin(db, user)
    if not decided:
        audit(db, actor=user, action="admin.access", target_type="route",
              target_id=request.url.path, source="api", result="blocked",
              request=request)
        raise HTTPException(status_code=403, detail="Global Admin only.")
    return user


def require_permission(permission_key: str, scope: tuple[str, str | None] | None = None):
    """A dependency that refuses unless `can()` says yes.

        @router.post("/convert", dependencies=[require_permission("engineering:hapext:convert")])
    """
    def dependency(request: Request, user: User = Depends(require_user),
                   db: Session = Depends(get_db)) -> User:
        if not can(db, user, permission_key, scope):
            audit(db, actor=user, action="permission.denied", target_type="permission",
                  target_id=permission_key, source="api", result="blocked",
                  request=request)
            raise HTTPException(status_code=403, detail="Not permitted.")
        return user
    return Depends(dependency)


# -------------------------------------------------------------- the bump
def bump_permissions_version(db: Session, user_id: uuid.UUID | str) -> int:
    """Call after any change to a person's roles, licences or applicable
    tool rules. Their next request re-resolves against the new state."""
    user = db.get(User, uuid.UUID(str(user_id)))
    if user is None:
        raise LookupError("no such user")
    user.permissions_version = (user.permissions_version or 0) + 1
    db.flush()
    return user.permissions_version


# ----------------------------------------------------------------- audit
def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # Render sits behind a proxy; the first hop in the chain is the client.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()[:64]
    return (request.client.host if request.client else None)


def audit(db: Session, *, action: str, result: str,
          actor: User | None = None, actor_email: str | None = None,
          org_id: uuid.UUID | None = None,
          application_id: uuid.UUID | None = None,
          target_type: str | None = None, target_id: str | None = None,
          source: str | None = "api", request: Request | None = None,
          before: dict[str, Any] | None = None, after: dict[str, Any] | None = None,
          commit: bool = True) -> AuditLog:
    """Append one row. There is no counterpart that edits or removes one.

    Every string is capped to its column's width. The audit log must be the
    one thing that never fails to write — a value from the wire being a few
    bytes too long (a 10,000-character login address, say) must not turn a
    clean 401 into a 500, still less lose the record of the attempt.
    """
    email = (actor.email if actor else actor_email) or ANONYMOUS_ACTOR
    row = AuditLog(
        org_id=org_id or (actor.org_id if actor else None),
        # Which product this concerns, where that is meaningful. Signing in is
        # not about one application and stays NULL; a seat or a tool rule is,
        # and a Business Admin may only read their own application's events.
        application_id=application_id,
        actor_id=actor.id if actor else None,
        actor_email=email[:254],
        action=action[:80], target_type=(target_type[:60] if target_type else None),
        target_id=(str(target_id)[:120] if target_id is not None else None),
        source=(source[:40] if source else None), result=result,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:400] if request else None),
        before=before, after=after,
    )
    db.add(row)
    if commit:
        db.commit()
    else:
        db.flush()
    return row
