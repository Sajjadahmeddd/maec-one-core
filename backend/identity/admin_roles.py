"""Screen 001 — User & Role Access.

A permission-scheme editor: which role may do what. It does NOT edit people.
A role maps to permissions once, here; people receive roles in User
Management. Keeping those apart is what stops the panel becoming a
per-user permission grid nobody can reason about.

Every write runs the same non-escalation rule as a manual grant: you may not
give a role a permission you do not hold yourself. Global Admin is exempt,
because it holds everything by definition.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_db
from .models import Permission, Role, RolePermission, User, UserRole
from .permissions import (
    audit, bump_permissions_version, can, is_global_admin, require_global_admin,
    split_key,
)

# Global Admin on the prefix is the floor: every route added here
# inherits it, and guard.py refuses each admin row a second time,
# independently. A route added here also needs a row in guard.ROUTES.
router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

EFFECTS = ("allow", "deny")
MAX_NAME = 120


# ------------------------------------------------------------------ shapes
class PermissionChange(BaseModel):
    """`effect=None` removes the row: the role simply says nothing."""
    key: str = Field(max_length=120)
    effect: str | None = None

    @field_validator("key")
    @classmethod
    def _well_formed(cls, value: str) -> str:
        split_key(value)          # raises for anything not app:module:action
        return value

    @field_validator("effect")
    @classmethod
    def _known(cls, value: str | None) -> str | None:
        if value is not None and value not in EFFECTS:
            raise ValueError(f"effect must be one of {EFFECTS} or null")
        return value


class RolePatch(BaseModel):
    name: str | None = Field(default=None, max_length=MAX_NAME)
    description: str | None = Field(default=None, max_length=300)
    changes: list[PermissionChange] = Field(default_factory=list, max_length=200)


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    description: str | None = Field(default=None, max_length=300)
    clone_from: uuid.UUID | None = None


# ------------------------------------------------------------------ helpers
def _summarise(effects: dict[str, str], module: str, actions: list[str]) -> str:
    """One badge per module, derived from the real allow/deny rows.

    The Figma names badges the model has no concept of (Personal Load,
    Capacity View). These four are what the data can actually support.
    """
    allowed = [a for a in actions if effects.get(f"engineering:{module}:{a}") == "allow"]
    if not allowed:
        return "none"
    if len(allowed) == len(actions):
        return "full"
    if allowed == ["view"]:
        return "view"
    return "partial"


def _role_json(db: Session, role: Role, registry: list[Permission],
               holders: dict[uuid.UUID, int]) -> dict:
    rows = db.scalars(select(RolePermission).where(
        RolePermission.role_id == role.id)).all()
    by_id = {p.id: p for p in registry}
    effects = {by_id[r.permission_id].key: r.effect for r in rows if r.permission_id in by_id}

    modules, actions = _registry_shape(registry)
    return {
        "id": str(role.id),
        "key": role.key,
        "name": role.name,
        "description": role.description,
        "level": role.level,
        "is_custom": role.is_custom,
        "is_system": role.org_id is None,
        "user_count": holders.get(role.id, 0),
        "permissions": effects,
        "summary": {m: _summarise(effects, m, actions) for m in modules},
    }


def _registry_shape(registry: list[Permission]) -> tuple[list[str], list[str]]:
    modules, actions = [], []
    for p in registry:
        if p.module_key not in modules:
            modules.append(p.module_key)
        if p.action not in actions:
            actions.append(p.action)
    return modules, actions


def _registry(db: Session) -> list[Permission]:
    return list(db.scalars(select(Permission).order_by(
        Permission.module_key, Permission.action)).all())


def _holder_counts(db: Session) -> dict[uuid.UUID, int]:
    rows = db.execute(select(UserRole.role_id, func.count(UserRole.id))
                      .group_by(UserRole.role_id)).all()
    return {role_id: count for role_id, count in rows}


def _editable(db: Session, role: Role, actor: User) -> Role:
    """System roles are shared by every organisation and are not editable
    from a tenant's admin panel. A custom role must belong to the caller."""
    if role.org_id is None:
        raise HTTPException(
            status_code=409,
            detail=f"{role.name} is a system role and cannot be edited. "
                   "Clone it with + Add Custom Role and edit the copy.")
    if role.org_id != actor.org_id and not is_global_admin(db, actor):
        raise HTTPException(status_code=404, detail="No such role.")
    return role


def _refuse_escalation(db: Session, actor: User, key: str, request: Request,
                       role: Role) -> None:
    """You cannot give away what you do not hold.

    Dormant today: this router requires Global Admin, and a Global Admin
    returns on the first line. Kept so the rule holds the day a narrower
    administrator reaches role editing. Its refusal commits its own audit row,
    which is safe only because patch_role calls it before writing anything.
    """
    if is_global_admin(db, actor):
        return
    if not can(db, actor, key):
        audit(db, actor=actor, action="role.permission", target_type="role",
              target_id=role.id, result="blocked", request=request,
              after={"permission": key, "reason": "actor does not hold it"})
        raise HTTPException(
            status_code=403,
            detail=f"You cannot grant {key} because you do not hold it.")


def _bump_holders(db: Session, role: Role) -> int:
    """Everyone holding this role re-resolves on their next request."""
    holders = db.scalars(select(UserRole.user_id).where(
        UserRole.role_id == role.id)).all()
    for user_id in set(holders):
        bump_permissions_version(db, user_id)
    return len(set(holders))


# ------------------------------------------------------------------- routes
@router.get("/roles")
def list_roles(db: Session = Depends(get_db),
               actor: User = Depends(require_global_admin)):
    """Every role and what it may do, plus the registry the grid is drawn from.

    The module and action lists come from the seeded permissions table, not a
    constant here — add a module to the registry and this screen grows a
    column without being edited.
    """
    registry = _registry(db)
    modules, actions = _registry_shape(registry)
    holders = _holder_counts(db)
    roles = db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)
    ).order_by(Role.level, Role.name)).all()

    return {
        "roles": [_role_json(db, r, registry, holders) for r in roles],
        "modules": modules,
        "actions": actions,
        "permissions": [
            {"key": p.key, "module_key": p.module_key, "action": p.action,
             "description": p.description}
            for p in registry
        ],
    }


@router.post("/roles", status_code=201)
def create_role(body: RoleCreate, request: Request, db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    """+ Add Custom Role — a copy of an existing role, owned by this org."""
    key = body.name.strip().lower().replace(" ", "_")[:60]
    if not key:
        raise HTTPException(status_code=422, detail="A name is required.")
    if db.scalar(select(Role).where(Role.org_id == actor.org_id, Role.key == key)):
        raise HTTPException(status_code=409, detail=f"A role named {body.name!r} already exists.")

    source = None
    if body.clone_from is not None:
        source = db.get(Role, body.clone_from)
        if source is None:
            raise HTTPException(status_code=404, detail="No such role to clone.")

    role = Role(key=key, name=body.name.strip(), description=body.description,
                level=(source.level if source else 4),
                org_id=actor.org_id, is_custom=True,
                application_id=(source.application_id if source else None))
    db.add(role)
    db.flush()

    copied = 0
    if source is not None:
        for rp in db.scalars(select(RolePermission).where(
                RolePermission.role_id == source.id)).all():
            # a clone may not carry more than the caller holds
            permission = db.get(Permission, rp.permission_id)
            if rp.effect == "allow" and permission is not None:
                if not is_global_admin(db, actor) and not can(db, actor, permission.key):
                    continue
            db.add(RolePermission(role_id=role.id, permission_id=rp.permission_id,
                                  effect=rp.effect))
            copied += 1

    audit(db, actor=actor, action="role.create", target_type="role", target_id=role.id,
          result="success", request=request,
          after={"name": role.name, "cloned_from": (source.key if source else None),
                 "permissions_copied": copied}, commit=False)
    db.commit()
    registry = _registry(db)
    return _role_json(db, role, registry, _holder_counts(db))


@router.patch("/roles/{role_id}")
def patch_role(role_id: uuid.UUID, body: RolePatch, request: Request,
               db: Session = Depends(get_db),
               actor: User = Depends(require_global_admin)):
    """Rename a role, or change what it may do."""
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="No such role.")
    _editable(db, role, actor)

    registry = {p.key: p for p in _registry(db)}
    before = {"name": role.name, "description": role.description}

    # Every change is checked before anything is written. A refusal audits
    # with its own commit on the session this route shares, so a rename or an
    # earlier change applied first would have been committed alongside the
    # 403 — the defect put_tool_rules had. See OPEN-DECISIONS #13.
    for change in body.changes:
        if change.key not in registry:
            raise HTTPException(status_code=422,
                                detail=f"Unknown permission {change.key!r}.")
        if change.effect == "allow":
            _refuse_escalation(db, actor, change.key, request, role)

    if body.name is not None:
        role.name = body.name.strip()
    if body.description is not None:
        role.description = body.description

    applied: dict[str, str | None] = {}
    for change in body.changes:
        permission = registry[change.key]
        existing = db.scalar(select(RolePermission).where(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == permission.id))
        if change.effect is None:
            if existing is not None:
                db.delete(existing)
        elif existing is None:
            db.add(RolePermission(role_id=role.id, permission_id=permission.id,
                                  effect=change.effect))
        else:
            existing.effect = change.effect
        applied[change.key] = change.effect

    db.flush()
    affected = _bump_holders(db, role)
    audit(db, actor=actor, action="role.permission", target_type="role",
          target_id=role.id, result="success", request=request,
          before=before,
          after={"name": role.name, "changes": applied, "users_affected": affected},
          commit=False)
    db.commit()
    return _role_json(db, role, _registry(db), _holder_counts(db))


@router.delete("/roles/{role_id}")
def delete_role(role_id: uuid.UUID, request: Request, db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    """Remove a custom role — only when nobody holds it.

    A cascade here would silently strip people of access, which is the one
    thing an access-control panel must never do quietly. The count is in the
    message so the administrator knows how much reassignment is waiting.
    """
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="No such role.")
    _editable(db, role, actor)

    held = db.scalar(select(func.count(UserRole.id)).where(UserRole.role_id == role.id))
    if held:
        audit(db, actor=actor, action="role.delete", target_type="role",
              target_id=role.id, result="blocked", request=request,
              before={"name": role.name, "held_by": held})
        raise HTTPException(
            status_code=409,
            detail=f"{role.name} is still held by {held} "
                   f"{'person' if held == 1 else 'people'}. Reassign them first.")

    before = {"name": role.name, "key": role.key, "level": role.level}
    db.delete(role)
    db.flush()
    audit(db, actor=actor, action="role.delete", target_type="role", target_id=role_id,
          result="success", request=request, before=before, commit=False)
    db.commit()
    return {"deleted": str(role_id)}
