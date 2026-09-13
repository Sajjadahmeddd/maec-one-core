"""Screen 002 — Tool-Level Settings.

A per-organisation override on top of the role scheme: for one module and one
role, narrow what that role may do here. Two rules carry the whole screen.

**A tool rule can only take away.** It runs after the role has decided and it
can only subtract — that is structural, not a check. But an administrator who
sets `full` on a module the role denies would reasonably expect that to grant
something, and it never will. So the write path refuses a level that promises
more than the role allows, rather than storing a rule that silently does
nothing. A rule that lies about its effect is worse than no rule.

**`hidden` and `no_access` are different states.** `hidden` takes the module
out of the navigation and nothing more — the API still answers. `no_access`
is the boundary: the API refuses. They are stored distinctly and enforced
differently (see `_LEVEL_ALLOWS` in permissions.py). Collapsing them is how a
panel ends up with a module that looks unavailable and is not.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import (
    Application, Permission, Role, RolePermission, ToolRule, User, UserRole,
)
from .permissions import (
    HIDES_FROM_NAV, LEVEL_IMPLIES, audit, bump_permissions_version,
    is_global_admin, require_global_admin,
)

# Global Admin on the prefix is the floor: every route added here
# inherits it, and guard.py refuses each admin row a second time,
# independently. A route added here also needs a row in guard.ROUTES.
router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

# The level list is the engine's, not a copy of it: a level that exists here
# and not in permissions.py would be accepted and then enforced as nothing.
LEVELS = tuple(LEVEL_IMPLIES)
STATUSES = ("active", "controlled")


class ToolRuleChange(BaseModel):
    application_key: str = Field(max_length=40)
    module_key: str = Field(max_length=40)
    role_id: uuid.UUID
    # None clears the rule: the role's own grants apply unmodified.
    access_level: str | None = None
    status: str = "active"

    @field_validator("access_level")
    @classmethod
    def _known_level(cls, value: str | None) -> str | None:
        if value is not None and value not in LEVELS:
            raise ValueError(f"access_level must be one of {LEVELS} or null")
        return value

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return value


class ToolRulesPut(BaseModel):
    changes: list[ToolRuleChange] = Field(min_length=1, max_length=200)


def _role_allows(db: Session, role: Role, app_key: str, module: str) -> set[str]:
    """The actions this role actually grants on this module."""
    rows = db.execute(
        select(Permission.action, RolePermission.effect)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role.id,
               Permission.module_key == module)).all()
    return {action for action, effect in rows if effect == "allow"}


@router.get("/tool-rules")
def list_tool_rules(db: Session = Depends(get_db),
                    actor: User = Depends(require_global_admin)):
    """The matrix: one row per module, one column per role.

    Modules come from the seeded permission registry — the four real ones —
    not from a list in this file.
    """
    registry = db.scalars(select(Permission).order_by(
        Permission.module_key, Permission.action)).all()
    apps = {a.id: a for a in db.scalars(select(Application)).all()}

    modules: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for p in registry:
        app = apps.get(p.application_id)
        if app is None or (app.key, p.module_key) in seen:
            continue
        seen.add((app.key, p.module_key))
        modules.append({"application_key": app.key, "application_name": app.name,
                        "module_key": p.module_key})

    roles = db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)
    ).order_by(Role.level, Role.name)).all()

    rules: dict[str, dict[str, dict]] = {}
    for rule in db.scalars(select(ToolRule).where(ToolRule.org_id == actor.org_id)).all():
        app = apps.get(rule.application_id)
        if app is None:
            continue
        rules.setdefault(f"{app.key}:{rule.module_key}", {})[str(rule.role_id)] = {
            "access_level": rule.access_level,
            "status": rule.status,
            "hides_from_nav": rule.access_level in HIDES_FROM_NAV,
            "blocks_api": rule.access_level == "no_access",
        }

    return {
        "modules": modules,
        "roles": [{"id": str(r.id), "key": r.key, "name": r.name, "level": r.level}
                  for r in roles],
        "rules": rules,
        "levels": [
            {"key": "full", "label": "Full Access", "tone": "granted"},
            {"key": "edit", "label": "Edit", "tone": "granted",
             "note": "Everything except configuration."},
            {"key": "view", "label": "View", "tone": "scoped"},
            {"key": "hidden", "label": "Hidden", "tone": "inactive",
             "note": "Removed from navigation. The API still answers — this is "
                     "decluttering, not a security boundary."},
            {"key": "no_access", "label": "No Access", "tone": "denied",
             "note": "The API refuses. This is the security boundary."},
        ],
        "statuses": list(STATUSES),
    }


@router.put("/tool-rules")
def put_tool_rules(body: ToolRulesPut, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    """Apply a set of changes. Any rejection rejects the whole set.

    Two passes, the shape of admin_import's plan() and apply(): every change
    is resolved and checked first, writing nothing, and only a set with no
    rejection is written — then committed once.

    The order is what makes the first sentence true. A refusal is audited
    with its own commit on the session this route shares, so when changes
    were applied as the loop walked them, a batch whose second change
    overreached committed the first and still answered 409.
    See OPEN-DECISIONS #13.
    """
    # ---- pass 1: resolve and check. Nothing is written in this pass.
    #
    # A change naming something that does not exist is refused on the spot
    # with no audit row: there is no rule to record. A change naming real
    # things but promising more than the role grants is collected, so one
    # refusal names everything wrong with the set.
    planned: list[tuple[ToolRuleChange, Application, Role]] = []
    for change in body.changes:
        app = db.scalar(select(Application).where(
            Application.key == change.application_key))
        if app is None:
            raise HTTPException(status_code=422,
                                detail=f"Unknown application {change.application_key!r}.")

        role = db.get(Role, change.role_id)
        if role is None:
            raise HTTPException(status_code=422, detail="Unknown role.")
        if role.org_id is not None and role.org_id != actor.org_id \
                and not is_global_admin(db, actor):
            raise HTTPException(status_code=404, detail="No such role.")

        known = db.scalar(select(Permission).where(
            Permission.application_id == app.id,
            Permission.module_key == change.module_key))
        if known is None:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown module {change.module_key!r} for {app.key}.")

        planned.append((change, app, role))

    overreaching: list[tuple[ToolRuleChange, Application, Role, list[str]]] = []
    for change, app, role in planned:
        if change.access_level is None:
            continue
        # A rule may not promise access the role does not grant.
        implied = LEVEL_IMPLIES[change.access_level]
        granted = _role_allows(db, role, app.key, change.module_key)
        missing = sorted(implied - granted)
        if missing:
            overreaching.append((change, app, role, missing))

    if overreaching:
        for change, app, role, missing in overreaching:
            audit(db, actor=actor, action="tool_rule.set", target_type="tool_rule",
                  target_id=f"{app.key}:{change.module_key}:{role.key}",
                  result="blocked", request=request, org_id=actor.org_id,
                  after={"access_level": change.access_level,
                         "reason": "would grant what the role denies",
                         "missing": missing},
                  commit=False)
        db.commit()          # the refusal rows and nothing else: no change was applied
        problems = " ".join(
            f"{role.name} is not granted "
            f"{', '.join(f'{app.key}:{change.module_key}:{a}' for a in missing)}, "
            f"so '{change.access_level}' there would do nothing."
            for change, app, role, missing in overreaching)
        raise HTTPException(
            status_code=409,
            detail=(f"{problems} A tool rule can only take access away, never add "
                    f"it. Change the role on Roles & Permissions, or pick a "
                    f"narrower level. Nothing in this set was applied."))

    # ---- pass 2: every change passed. Write them all, commit once.
    applied, affected_users = [], set()
    for change, app, role in planned:
        existing = db.scalar(select(ToolRule).where(
            ToolRule.org_id == actor.org_id,
            ToolRule.application_id == app.id,
            ToolRule.module_key == change.module_key,
            ToolRule.role_id == role.id))

        if change.access_level is None:
            if existing is None:
                continue                  # nothing to clear: nobody's access changes
            db.delete(existing)
            applied.append({"module": change.module_key, "role": role.key,
                            "access_level": None})
        else:
            if existing is None:
                db.add(ToolRule(org_id=actor.org_id, application_id=app.id,
                                module_key=change.module_key, role_id=role.id,
                                access_level=change.access_level, status=change.status,
                                updated_by=actor.id))
            else:
                existing.access_level = change.access_level
                existing.status = change.status
                existing.updated_by = actor.id
            applied.append({"module": change.module_key, "role": role.key,
                            "access_level": change.access_level, "status": change.status})

        # Clearing a rule changes access as surely as setting one — usually it
        # widens it — so its holders are bumped either way. Under the token
        # design this version is how a product learns its tool-rule claims are
        # stale: a clear that did not bump would leave a removed rule enforced
        # for the token's whole lifetime, with no signal. OPEN-DECISIONS #13.
        for user_id in db.scalars(select(UserRole.user_id).where(
                UserRole.role_id == role.id)).all():
            affected_users.add(user_id)

    db.flush()
    for user_id in affected_users:
        bump_permissions_version(db, user_id)

    audit(db, actor=actor, action="tool_rule.set", target_type="tool_rule",
          target_id=f"{len(applied)} change(s)", result="success", request=request,
          org_id=actor.org_id,
          after={"changes": applied, "users_affected": len(affected_users)},
          commit=False)
    db.commit()
    return {"applied": applied, "users_affected": len(affected_users)}
