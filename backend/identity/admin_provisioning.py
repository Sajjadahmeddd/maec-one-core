"""Screen 003 — Global Provisioning.

Rules can be authored now; nothing acts on them yet. Entra ID federation is
not built, and this screen says so rather than showing a plausible
"Connected · 142 users · SCIM active". The cards are derived from what is
actually configured, so the day a tenant is configured they change by
themselves rather than by someone remembering to edit a string.

A mapping says: someone arriving in this directory group gets this role. That
is a grant — deferred, but a grant — so authoring one runs `accounts.may_grant`,
the same check a manual grant and a CSV import run. An administrator cannot
write a rule that would hand out more than they hold, even though nobody is
handed anything until federation exists.
"""

from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import accounts
from .db import get_db
from .models import (
    Application, Organization, ProvisioningMap, Role, Subscription, User,
)
from .permissions import audit, require_global_admin

router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

STATUSES = ("active", "disabled")
APPROVALS = ("automatic", "manual")

# What a connected identity provider would look like. Nothing sets these
# today; the card reads them rather than asserting a state, so it tells the
# truth now and keeps telling it when that changes.
IDP_SETTINGS = ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID")


class MapCreate(BaseModel):
    directory_group: str = Field(min_length=1, max_length=200)
    role_id: uuid.UUID
    default_modules: list[str] = Field(default_factory=list, max_length=20)
    approval_type: str = "manual"
    status: str = "active"

    @field_validator("approval_type")
    @classmethod
    def _known_approval(cls, value: str) -> str:
        if value not in APPROVALS:
            raise ValueError(f"approval_type must be one of {APPROVALS}")
        return value

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return value


class MapPatch(BaseModel):
    role_id: uuid.UUID | None = None
    default_modules: list[str] | None = Field(default=None, max_length=20)
    approval_type: str | None = None
    status: str | None = None


# ----------------------------------------------------------- the three cards
def identity_provider(db: Session, org: Organization | None) -> dict:
    """Read, not asserted. Nothing configures a tenant yet, so this is
    "Not connected" because the configuration is absent — the card will say
    otherwise the moment it is present, without this file changing."""
    configured = [name for name in IDP_SETTINGS if os.environ.get(name, "").strip()]
    connected = len(configured) == len(IDP_SETTINGS)
    return {
        "key": "identity_provider",
        "label": "Identity Provider",
        "value": "Microsoft Entra ID" if connected else "Not connected",
        "state": "granted" if connected else "inactive",
        "detail": (
            f"Federated with {org.domain}" if connected and org else
            "Federation is not built. Mirage AEC runs Microsoft 365 on this "
            "domain, so Entra is the realistic source when it is — until "
            "then, people are created here or imported."),
        "action": "Configure",
        "derived_from": ", ".join(IDP_SETTINGS),
    }


def provisioning_mode(connected: bool, rules: int) -> dict:
    """Follows from whether anything can actually sync."""
    return {
        "key": "provisioning_mode",
        "label": "Provisioning Mode",
        "value": "Automatic" if connected else "Manual",
        "state": "granted" if connected else "scoped",
        "detail": (
            "Directory groups are applied as people arrive."
            if connected else
            f"{rules} rule(s) authored, applied by hand. Nothing is "
            "provisioned automatically until an identity provider is "
            "connected."),
    }


def default_access_policy(db: Session) -> dict:
    """Least Privilege, stated from the data: the role an unmapped person
    would receive is the lowest-privilege one that exists."""
    lowest = db.scalars(select(Role).where(Role.org_id.is_(None))
                        .order_by(Role.level.desc())).first()
    return {
        "key": "default_access_policy",
        "label": "Default Access Policy",
        "value": "Least Privilege",
        "state": "granted",
        "detail": (
            f"An unmapped person receives {lowest.name if lowest else 'the '
            'lowest role'} and no application seats until one is granted."),
    }


# ----------------------------------------------------------------- helpers
def _map_json(row: ProvisioningMap, roles: dict[uuid.UUID, Role],
              apps: dict[str, Application]) -> dict:
    role = roles.get(row.role_id)
    modules = row.default_modules or []
    return {
        "id": str(row.id),
        "directory_group": row.directory_group,
        "role_id": str(row.role_id),
        "role_key": role.key if role else None,
        "role_name": role.name if role else "(role removed)",
        "default_modules": modules,
        "module_names": [apps[m].name for m in modules if m in apps],
        "approval_type": row.approval_type or "manual",
        "status": row.status,
    }


def _subscribed(db: Session, actor: User) -> dict[str, Application]:
    """The applications this organisation actually holds. A rule may not
    promise a module the organisation has not bought."""
    out: dict[str, Application] = {}
    for sub in db.scalars(select(Subscription).where(
            Subscription.org_id == actor.org_id)).all():
        app = db.get(Application, sub.application_id)
        if app is not None:
            out[app.key] = app
    return out


def _check_role(db: Session, actor: User, role_id: uuid.UUID,
                request: Request) -> Role:
    """A mapping is a deferred grant, so it obeys the grant rule.

    `accounts.may_grant` — the same function a manual grant and a CSV import
    ask. A rule that would confer more than its author holds is refused when
    it is written, not discovered when it eventually fires.
    """
    role = db.get(Role, role_id)
    if role is None or (role.org_id is not None and role.org_id != actor.org_id):
        raise HTTPException(status_code=422, detail="Unknown role.")

    (scope_type, scope_id), problem = accounts.placement_scope(db, actor)
    if problem:
        raise HTTPException(status_code=409, detail=problem)

    why = accounts.may_grant(db, actor=actor, target_org_id=actor.org_id,
                             role=role, scope_type=scope_type, scope_id=scope_id)
    if why is not None:
        audit(db, actor=actor, action="provisioning.rule", target_type="role",
              target_id=role.id, result="blocked", request=request,
              after={"role": role.key, "reason": why})
        raise HTTPException(
            status_code=403,
            detail=f"You may not make a rule conferring {role.key}: {why}.")
    return role


def _check_modules(db: Session, actor: User, modules: list[str]) -> list[str]:
    subscribed = _subscribed(db, actor)
    unknown = [m for m in modules if m not in subscribed]
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=("Your organisation does not subscribe to "
                    f"{', '.join(sorted(unknown))}."))
    return sorted(set(modules))


# ------------------------------------------------------------------ routes
@router.get("/provisioning")
def read_provisioning(db: Session = Depends(get_db),
                      actor: User = Depends(require_global_admin)):
    org = db.get(Organization, actor.org_id)
    rows = db.scalars(select(ProvisioningMap).where(
        ProvisioningMap.org_id == actor.org_id)
        .order_by(ProvisioningMap.directory_group)).all()

    idp = identity_provider(db, org)
    connected = idp["state"] == "granted"
    roles = {r.id: r for r in db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id))).all()}
    apps = _subscribed(db, actor)

    return {
        "cards": [idp, provisioning_mode(connected, len(rows)),
                  default_access_policy(db)],
        "rules": [_map_json(r, roles, apps) for r in rows],
        "roles": [{"id": str(r.id), "key": r.key, "name": r.name, "level": r.level}
                  for r in sorted(roles.values(), key=lambda x: x.level)],
        "applications": [{"key": a.key, "name": a.name} for a in apps.values()],
        "approvals": list(APPROVALS),
        "statuses": list(STATUSES),
    }


@router.post("/provisioning", status_code=201)
def create_rule(body: MapCreate, request: Request, db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    group = body.directory_group.strip()
    if db.scalar(select(ProvisioningMap).where(
            ProvisioningMap.org_id == actor.org_id,
            ProvisioningMap.directory_group == group)):
        raise HTTPException(
            status_code=409,
            detail=f"{group} already has a rule. Edit that one instead — two "
                   "rules for one group would confer two roles.")

    role = _check_role(db, actor, body.role_id, request)
    modules = _check_modules(db, actor, body.default_modules)

    rule = ProvisioningMap(org_id=actor.org_id, directory_group=group,
                           role_id=role.id, default_modules=modules,
                           approval_type=body.approval_type, status=body.status)
    db.add(rule)
    db.flush()
    audit(db, actor=actor, action="provisioning.rule", target_type="provisioning_map",
          target_id=rule.id, result="success", request=request,
          after={"directory_group": group, "role": role.key,
                 "default_modules": modules, "approval_type": body.approval_type,
                 "status": body.status},
          commit=False)
    db.commit()

    roles = {role.id: role}
    return _map_json(rule, roles, _subscribed(db, actor))


@router.patch("/provisioning/{rule_id}")
def update_rule(rule_id: uuid.UUID, body: MapPatch, request: Request,
                db: Session = Depends(get_db),
                actor: User = Depends(require_global_admin)):
    rule = db.get(ProvisioningMap, rule_id)
    if rule is None or rule.org_id != actor.org_id:
        raise HTTPException(status_code=404, detail="No such rule.")

    before = {"role_id": str(rule.role_id), "default_modules": rule.default_modules,
              "approval_type": rule.approval_type, "status": rule.status}

    if body.role_id is not None:
        rule.role_id = _check_role(db, actor, body.role_id, request).id
    if body.default_modules is not None:
        rule.default_modules = _check_modules(db, actor, body.default_modules)
    if body.approval_type is not None:
        if body.approval_type not in APPROVALS:
            raise HTTPException(status_code=422, detail="Unknown approval type.")
        rule.approval_type = body.approval_type
    if body.status is not None:
        if body.status not in STATUSES:
            raise HTTPException(status_code=422, detail="Unknown status.")
        rule.status = body.status

    db.flush()
    audit(db, actor=actor, action="provisioning.rule", target_type="provisioning_map",
          target_id=rule.id, result="success", request=request, before=before,
          after={"role_id": str(rule.role_id), "default_modules": rule.default_modules,
                 "approval_type": rule.approval_type, "status": rule.status},
          commit=False)
    db.commit()

    roles = {r.id: r for r in db.scalars(select(Role)).all()}
    return _map_json(rule, roles, _subscribed(db, actor))
