"""The permission engine.

    can(db, user, "engineering:hapext:convert", scope=("project", "P-2291"))

resolves in five steps — entitlement, collect roles, filter by scope,
resolve most-specific-wins with deny beating allow on a tie, then tool rules
that may only take away — and any error at any step is a refusal. Nothing
here defaults to allow.

Also here: the FastAPI dependencies that put the engine in front of a route,
the version bump that makes a change bite within seconds, and the audit
writer. They live together because they share the same reading of the
session and the same failure posture.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .db import get_db
from .models import (
    Application, AuditLog, Permission, RolePermission, Subscription,
    ToolRule, User, UserLicense, UserRole,
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

# Higher number: more specific. Most specific wins.
SPECIFICITY = {"platform": 1, "organization": 2, "application": 3, "project": 4}

# What each tool-rule level still permits. A rule can only ever narrow what
# the role already allowed — nothing here can turn a denial into a grant,
# which is structural rather than a check: this runs after the role has
# already decided, and it can only subtract.
#
# `hidden` and `no_access` are NOT the same thing, and collapsing them is the
# mistake this table exists to prevent:
#
#   hidden     the module is not offered in the navigation, but the API still
#              answers. Decluttering, not a boundary. Anyone who knows the
#              URL can still call it — which is the point: it is for tools a
#              team simply does not use, not for tools they must not reach.
#   no_access  the API refuses. This is the security boundary.
#
# So `hidden` permits here and is filtered in the UI; `no_access` denies.
_LEVEL_ALLOWS: dict[str, Callable[[str], bool]] = {
    "full": lambda action: True,
    "edit": lambda action: True,
    "view": lambda action: action == "view",
    "hidden": lambda action: True,        # UX only — see above
    "no_access": lambda action: False,    # the boundary
}

# Levels that take a module out of the navigation, whatever the API does.
HIDES_FROM_NAV = frozenset({"hidden", "no_access"})

# What each level implies a role should be able to do. Used on the write path
# to refuse a rule that promises access the role does not grant.
LEVEL_IMPLIES: dict[str, frozenset[str]] = {
    "full": frozenset({"view", "convert", "export", "configure"}),
    "edit": frozenset({"view", "convert", "export"}),
    "view": frozenset({"view"}),
    "hidden": frozenset(),
    "no_access": frozenset(),
}


def now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ------------------------------------------------------------- the key
def split_key(permission_key: str) -> tuple[str, str, str]:
    """`app:module:action`, or ValueError. Three parts, no more, no less."""
    parts = permission_key.split(":")
    if len(parts) != 3 or not all(parts):
        raise ValueError(f"malformed permission key {permission_key!r}")
    return parts[0], parts[1], parts[2]


def app_of(permission_key: str) -> str:
    return split_key(permission_key)[0]


# ----------------------------------------------------------- entitlement
def entitled(db: Session, user: User, app_key: str) -> bool:
    """Org subscribed, in date, and this person holds a seat."""
    try:
        app = db.scalar(select(Application).where(Application.key == app_key))
        if app is None:
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
    except Exception:
        return False


# ----------------------------------------------------------------- roles
def active_roles(db: Session, user: User) -> list[UserRole]:
    moment = now()
    rows = db.scalars(select(UserRole).where(UserRole.user_id == user.id)).all()
    return [r for r in rows if r.expires_at is None or _utc(r.expires_at) > moment]


def _covers(grant: UserRole, user: User, app_key: str,
            requested: tuple[str, str | None]) -> bool:
    """Does this grant's scope reach the requested one?

    platform reaches everything. organization reaches everything in that
    organisation. application reaches that application and any project
    request made within it. project reaches that one project.
    """
    kind, ident = requested
    if grant.scope_type == "platform":
        return True
    if grant.scope_type == "organization":
        return grant.scope_id == str(user.org_id)
    if grant.scope_type == "application":
        return grant.scope_id == app_key
    if grant.scope_type == "project":
        return kind == "project" and ident is not None and grant.scope_id == ident
    return False


def holds_business_admin(db: Session, user: User) -> bool:
    """Does this person lead any application at all?

    Used by the guard to decide whether to let them as far as the audit
    reads; what they may then *see* is scoped by the endpoint.
    """
    try:
        return any(g.role.key == "business_admin" for g in active_roles(db, user))
    except Exception:
        return False


def is_global_admin(db: Session, user: User) -> bool:
    try:
        for grant in active_roles(db, user):
            if grant.scope_type == "platform" and grant.role.key == GLOBAL_ADMIN:
                return True
        return False
    except Exception:
        return False


# ------------------------------------------------------------------ can()
def can(db: Session, user: User | None, permission_key: str,
        scope: tuple[str, str | None] | None = None) -> bool:
    """May this person do this thing, here? False on any doubt."""
    try:
        if user is None or user.status != "active":
            return False
        app_key, module_key, action = split_key(permission_key)

        # 1. entitlement
        if not entitled(db, user, app_key):
            return False

        # 2. + 3. roles in force whose scope reaches the request
        requested = scope or ("application", app_key)
        if requested[0] not in SPECIFICITY:
            return False
        grants = [g for g in active_roles(db, user)
                  if _covers(g, user, app_key, requested)]
        if not grants:
            return False

        # 4. resolve: most specific wins; deny beats allow on a tie
        permission = db.scalar(select(Permission).where(Permission.key == permission_key))
        if permission is None:
            return False
        matches: list[tuple[int, str, UserRole]] = []
        for grant in grants:
            rp = db.scalar(select(RolePermission).where(
                RolePermission.role_id == grant.role_id,
                RolePermission.permission_id == permission.id))
            if rp is not None:
                matches.append((SPECIFICITY[grant.scope_type], rp.effect, grant))
        if not matches:
            return False
        top = max(spec for spec, _, _ in matches)
        decisive = [(effect, grant) for spec, effect, grant in matches if spec == top]
        if any(effect == "deny" for effect, _ in decisive):
            return False
        allowing = [grant for effect, grant in decisive if effect == "allow"]
        if not allowing:
            return False

        # 5. tool rules may narrow what the winning roles allowed, never widen
        app = db.scalar(select(Application).where(Application.key == app_key))
        for grant in allowing:
            rule = db.scalar(select(ToolRule).where(
                ToolRule.org_id == user.org_id,
                ToolRule.application_id == app.id,
                ToolRule.module_key == module_key,
                ToolRule.role_id == grant.role_id))
            if rule is None:
                continue
            allows = _LEVEL_ALLOWS.get(rule.access_level)
            if allows is None or not allows(action):
                return False
        return True
    except Exception:
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
