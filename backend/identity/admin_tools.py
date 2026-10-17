"""Screen 002 — Tool-Level Settings.

The grid: one row per feature an application has reported (a module), one
column per role, and in each cell Full Access or No Access for this
organisation. Plus a Status per feature: Active, or Inactive — switched off for
everyone. OPEN-DECISIONS #22, #23.

**The features are the apps'.** Core's code names none: each app reports its
own (PUT /api/gate/features, features.py) and its rows appear here, marked New
until an administrator first changes a rule on them. A feature an app no longer
reports is marked so, and only then can it be removed here — which retires its
key for good.

**Full Access and No Access.** No Access takes the feature away from a role.
Full Access leaves the role's own permissions to apply where the role allows
anything in the feature — what they may do inside stays the role's — and,
where the role allows nothing (every new feature, for all but Global Admin),
switches the whole feature on. A cell nobody has set shows what the role says:
Full Access when it allows anything in the feature, else No Access.

**Inactive is the boundary for everyone.** Every action of an inactive feature
is refused for every person in the organisation, Global Admins included; the
gate refuses an application in which the grid leaves someone nothing.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import features
from .db import get_db
from .models import (
    Application, Feature, Permission, Role, RolePermission, ToolRule, ToolSetting,
    User, UserRole,
)
from .permissions import (
    LEVELS, audit, bump_permissions_version, now, require_global_admin,
)

# Global Admin on the prefix is the floor: every route added here
# inherits it, and guard.py refuses each admin row a second time,
# independently. A route added here also needs a row in guard.ROUTES.
router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

# The level list is the engine's, not a copy of it: a level that exists here
# and not in resolution.py would be accepted and then enforced as nothing.
STATUSES = ("active", "inactive")
RULE_STATUS = "active"          # tool_rules.status: kept, always "active"


class ToolRuleChange(BaseModel):
    application_key: str = Field(max_length=40)
    module_key: str = Field(max_length=40)
    role_id: uuid.UUID
    # None clears the cell: the role's own permissions decide again.
    access_level: str | None = None

    @field_validator("access_level")
    @classmethod
    def _known_level(cls, value: str | None) -> str | None:
        if value is not None and value not in LEVELS:
            raise ValueError(f"access_level must be one of {LEVELS} or null")
        return value


class ToolRulesPut(BaseModel):
    changes: list[ToolRuleChange] = Field(min_length=1, max_length=200)


class ToolStatusPut(BaseModel):
    application_key: str = Field(max_length=40)
    module_key: str = Field(max_length=40)
    status: str

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return value


def _tool(db: Session, application_key: str, module_key: str) -> Application:
    """The application, if it has this module; 422 otherwise."""
    app = db.scalar(select(Application).where(Application.key == application_key))
    if app is None:
        raise HTTPException(status_code=422, detail=f"Unknown application {application_key!r}.")
    if db.scalar(select(Permission.id).where(Permission.application_id == app.id,
                                             Permission.module_key == module_key)) is None:
        raise HTTPException(status_code=422,
                            detail=f"Unknown module {module_key!r} for {app.key}.")
    return app


def _org_people(db: Session, org_id: uuid.UUID, role_id: uuid.UUID | None = None) -> set:
    """Who re-resolves after a change: the holders of one role, or everyone in
    the organisation who holds any role."""
    query = select(UserRole.user_id).join(User, User.id == UserRole.user_id).where(
        User.org_id == org_id)
    if role_id is not None:
        query = query.where(UserRole.role_id == role_id)
    return set(db.scalars(query).all())


# ------------------------------------------------------------------- routes
@router.get("/tool-rules")
def list_tool_rules(db: Session = Depends(get_db),
                    actor: User = Depends(require_global_admin)):
    """The grid: every feature, every role, and what each cell is.

    Features come from the registry the apps report into, never from a list in
    this file. Each cell is "full" or "no_access" — the grid's setting where
    there is one (`set: true`), else whether the role allows anything in it.
    `applications` is the monitoring line above each app's rows.
    """
    registry = db.scalars(select(Permission).order_by(
        Permission.module_key, Permission.action)).all()
    apps = {a.id: a for a in db.scalars(select(Application)).all()}
    settings = {(s.application_id, s.module_key): s.status
                for s in db.scalars(select(ToolSetting).where(
                    ToolSetting.org_id == actor.org_id)).all()}
    reported = {(f.application_id, f.key): f for f in db.scalars(select(Feature)).all()}

    modules: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for p in registry:
        app = apps.get(p.application_id)
        if app is None or (app.key, p.module_key) in seen:
            continue
        seen.add((app.key, p.module_key))
        feature = reported.get((app.id, p.module_key))
        modules.append({"application_key": app.key, "application_name": app.name,
                        # live or coming_soon: the application's own state
                        "application_status": app.status,
                        "module_key": p.module_key,
                        # the name the app gave it; the key until it reports
                        "name": feature.name if feature else p.module_key,
                        "is_new": bool(feature and feature.is_new),
                        "not_reported_since": (feature.not_reported_since.isoformat()
                                               if feature and feature.not_reported_since
                                               else None),
                        # the Status column: this organisation's switch
                        "status": settings.get((app.id, p.module_key), "active")})
    modules.sort(key=lambda m: (m["application_name"], m["name"].lower(), m["module_key"]))

    # one line per application with features: when it last reported, and what
    applications = []
    for app in sorted(apps.values(), key=lambda a: a.name):
        mine = [m for m in modules if m["application_key"] == app.key]
        if not mine and app.features_reported_at is None:
            continue
        applications.append({
            "key": app.key, "name": app.name, "status": app.status,
            "reported_at": (app.features_reported_at.isoformat()
                            if app.features_reported_at else None),
            "version": app.features_version,
            "features": len(mine),
            "new": sum(1 for m in mine if m["is_new"]),
            "not_reported": sum(1 for m in mine if m["not_reported_since"]),
        })

    roles = db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)
    ).order_by(Role.level, Role.name)).all()

    # each role's own effects per tool, for the cells nobody has set
    by_id = {p.id: p for p in registry}
    own: dict[tuple[str, str], list[str]] = {}
    for rp in db.scalars(select(RolePermission).where(
            RolePermission.role_id.in_([r.id for r in roles]))).all():
        perm = by_id.get(rp.permission_id)
        app = apps.get(perm.application_id) if perm else None
        if app is not None:
            own.setdefault((f"{app.key}:{perm.module_key}", str(rp.role_id)), []).append(rp.effect)

    rules = {}
    for rule in db.scalars(select(ToolRule).where(ToolRule.org_id == actor.org_id)).all():
        app = apps.get(rule.application_id)
        if app is not None:
            rules[(f"{app.key}:{rule.module_key}", str(rule.role_id))] = rule.access_level

    cells: dict[str, dict[str, dict]] = {}
    for m in modules:
        tool = f"{m['application_key']}:{m['module_key']}"
        for r in roles:
            set_here = rules.get((tool, str(r.id)))
            level = set_here or (
                "full" if "allow" in own.get((tool, str(r.id)), []) else "no_access")
            cells.setdefault(tool, {})[str(r.id)] = {"access_level": level,
                                                     "set": set_here is not None}

    return {
        "modules": modules,
        "applications": applications,
        "roles": [{"id": str(r.id), "key": r.key, "name": r.name, "level": r.level}
                  for r in roles],
        "cells": cells,
        "levels": [
            {"key": "full", "label": "Full Access", "tone": "granted"},
            {"key": "no_access", "label": "No Access", "tone": "denied"},
        ],
        "statuses": [
            {"key": "active", "label": "Active"},
            {"key": "inactive", "label": "Inactive"},
        ],
    }


@router.put("/tool-rules")
def put_tool_rules(body: ToolRulesPut, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    """Set cells of the grid. Any unknown target rejects the whole set.

    Two passes: every change is resolved first, writing nothing, and only a
    set with nothing unknown in it is written — then committed once.
    OPEN-DECISIONS #13. A feature a rule is set on is no longer New.
    """
    # ---- pass 1: resolve and check. Nothing is written in this pass.
    planned: list[tuple[ToolRuleChange, Application, Role]] = []
    for change in body.changes:
        app = _tool(db, change.application_key, change.module_key)
        role = db.get(Role, change.role_id)
        if role is None:
            raise HTTPException(status_code=422, detail="Unknown role.")
        if role.org_id is not None and role.org_id != actor.org_id:
            raise HTTPException(status_code=404, detail="No such role.")
        planned.append((change, app, role))

    # ---- pass 2: write them all, commit once.
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
        elif existing is None:
            db.add(ToolRule(org_id=actor.org_id, application_id=app.id,
                            module_key=change.module_key, role_id=role.id,
                            access_level=change.access_level, status=RULE_STATUS,
                            updated_by=actor.id))
        else:
            existing.access_level = change.access_level
            existing.updated_by = actor.id
        applied.append({"application": app.key, "module": change.module_key,
                        "role": role.key, "access_level": change.access_level})
        features.reviewed(db, app.id, [change.module_key])

        # Clearing a cell changes access as surely as setting one, so its
        # holders are bumped either way: under the token design this version
        # is how a product learns its claims are stale. OPEN-DECISIONS #13.
        affected_users |= _org_people(db, actor.org_id, role.id)

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


@router.put("/tool-status")
def put_tool_status(body: ToolStatusPut, request: Request,
                    db: Session = Depends(get_db),
                    actor: User = Depends(require_global_admin)):
    """Switch a tool on (active) or off (inactive) for the whole organisation."""
    app = _tool(db, body.application_key, body.module_key)
    setting = db.scalar(select(ToolSetting).where(
        ToolSetting.org_id == actor.org_id, ToolSetting.application_id == app.id,
        ToolSetting.module_key == body.module_key))
    before = setting.status if setting else "active"
    if setting is None:
        setting = ToolSetting(org_id=actor.org_id, application_id=app.id,
                              module_key=body.module_key, status=body.status,
                              updated_by=actor.id)
        db.add(setting)
    else:
        setting.status = body.status
        setting.updated_by = actor.id
    features.reviewed(db, app.id, [body.module_key])
    db.flush()

    # everyone in the organisation: a switched-off tool is off for every role
    affected = _org_people(db, actor.org_id) if before != body.status else set()
    for user_id in affected:
        bump_permissions_version(db, user_id)

    audit(db, actor=actor, action="tool_status.set", target_type="application",
          target_id=app.key, application_id=app.id, result="success", request=request,
          org_id=actor.org_id,
          before={"module": body.module_key, "status": before},
          after={"module": body.module_key, "status": body.status,
                 "users_affected": len(affected)},
          commit=False)
    db.commit()
    return {"application_key": app.key, "module_key": body.module_key,
            "status": body.status, "users_affected": len(affected)}


@router.delete("/features/{application_key}/{feature_key}")
def remove_feature(application_key: str, feature_key: str, request: Request,
                   db: Session = Depends(get_db),
                   actor: User = Depends(require_global_admin)):
    """Remove a feature its app no longer reports, and retire its key.

    Deletes its permissions, every role rule and grid setting on it. The key
    is recorded as retired: an app reporting it again is refused, because a
    key is permanent and must never come back meaning something else.
    """
    app = db.scalar(select(Application).where(Application.key == application_key))
    if app is None:
        raise HTTPException(status_code=404, detail=f"Unknown application {application_key!r}.")
    try:
        gone = features.remove(db, app, feature_key, actor.id, now())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    audit(db, actor=actor, action="features.remove", target_type="application",
          target_id=app.key, application_id=app.id, result="success", request=request,
          org_id=actor.org_id,
          before={"feature": gone.key, "name": gone.name,
                  "not_reported_since": gone.not_reported_since.isoformat()
                  if gone.not_reported_since else None},
          after={"retired": True}, commit=False)
    db.commit()
    return {"application_key": app.key, "feature_key": feature_key, "retired": True}
