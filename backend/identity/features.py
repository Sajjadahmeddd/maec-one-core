"""Applications tell Core their features. OPEN-DECISIONS #23.

Core's code names no feature of any application. Each application carries its
feature keys in its own code and, when it starts, sends the list here
(PUT /api/gate/features, router_gate.py). This module checks the report and
applies it, all or nothing:

* A new feature, or a new action of one: its `permissions` rows are created,
  allowed for Global Admin only and denied for every other role, built-in or
  custom. It is marked new until an administrator first changes a rule on it.
* A feature already known: its name follows the report; a "not reported" mark
  is cleared. Its role rules are never touched.
* A feature the report leaves out: never deleted — marked "not reported since".
  Only an administrator removes it (Tool-Level Settings), and its key is then
  retired: an app reporting it again is refused.

A key is permanent and the name is only what the panel shows. The permission
key is `<app>:<feature key>:<action>`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from .models import (
    Application, Feature, Permission, RetiredFeature, Role, RolePermission, ToolRule,
    ToolSetting,
)

KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
ACTIONS = ("use", "view", "convert", "export", "configure")
MAX_FEATURES = 200
MAX_VERSION = 64
MAX_NAME = 120
MAX_BODY = 256 * 1024
GLOBAL_ADMIN = "global_admin"


class ReportError(ValueError):
    """The report is refused as a whole; the message says why."""


@dataclass(frozen=True)
class Reported:
    key: str
    name: str
    actions: tuple[str, ...]


@dataclass
class Outcome:
    registered: int
    new: list[str] = field(default_factory=list)            # features created
    new_actions: list[str] = field(default_factory=list)    # "<key>:<action>" added
    renamed: list[str] = field(default_factory=list)
    back: list[str] = field(default_factory=list)           # reported again
    gone_quiet: list[str] = field(default_factory=list)     # newly not reported
    version_changed: bool = False
    not_reported: int = 0
    total: int = 0
    marked_new: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.new or self.new_actions or self.renamed or self.back
                    or self.gone_quiet or self.version_changed)

    def response(self) -> dict:
        return {"registered": self.registered, "new": len(self.new),
                "not_reported": self.not_reported}


def _printable(value: str) -> bool:
    return value.isprintable()


# ------------------------------------------------------------------ checking
def parse(body: Any, app_key: str) -> tuple[str | None, list[Reported]]:
    """The report, checked. Raises ReportError naming every problem found."""
    if not isinstance(body, dict):
        raise ReportError("The body must be a JSON object with 'features'.")
    problems: list[str] = []

    claimed = body.get("app")
    if claimed is not None and claimed != app_key:
        raise ReportError(f"An app registers only its own features: this is {app_key!r}, "
                          f"not {claimed!r}.")

    version = body.get("app_version")
    if version is not None:
        if not isinstance(version, str) or not version or len(version) > MAX_VERSION \
                or not _printable(version):
            problems.append(f"app_version must be 1 to {MAX_VERSION} printable characters.")

    features = body.get("features")
    if not isinstance(features, list):
        raise ReportError("'features' must be a list.")
    if len(features) > MAX_FEATURES:
        raise ReportError(f"At most {MAX_FEATURES} features per call; this has {len(features)}.")

    seen: set[str] = set()
    reported: list[Reported] = []
    for index, item in enumerate(features):
        where = f"features[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object with key, name and actions.")
            continue
        key, name, actions = item.get("key"), item.get("name"), item.get("actions")
        if not isinstance(key, str) or not KEY.match(key):
            problems.append(f"{where}: key {key!r} must match [a-z][a-z0-9_]{{0,39}}.")
            continue
        where = f"feature {key}"
        if key in seen:
            problems.append(f"{where} appears more than once.")
            continue
        seen.add(key)
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > MAX_NAME \
                or not _printable(name):
            problems.append(f"{where}: name must be 1 to {MAX_NAME} printable characters.")
        if not isinstance(actions, list) or not actions:
            problems.append(f"{where}: actions must be a non-empty list from {list(ACTIONS)}.")
            continue
        unknown = [a for a in actions if a not in ACTIONS]
        if unknown:
            problems.append(f"{where}: unknown action(s) {unknown}; allowed: {list(ACTIONS)}.")
        if len(set(actions)) != len(actions):
            problems.append(f"{where}: an action is listed twice.")
        if not problems or not any(p.startswith(where) for p in problems):
            reported.append(Reported(key=key, name=name.strip(), actions=tuple(actions)))

    if problems:
        raise ReportError(" ".join(problems[:20]))
    return version, reported


# ----------------------------------------------------------------- applying
def register(db: Session, app: Application, version: str | None,
             reported: list[Reported], now: datetime) -> Outcome:
    """Apply a checked report. Writes, flushes, and leaves the commit to the
    caller, so the whole report is one transaction."""
    retired = {r.key: r for r in db.scalars(select(RetiredFeature).where(
        RetiredFeature.application_id == app.id)).all()}
    clash = [f for f in reported if f.key in retired]
    if clash:
        r = retired[clash[0].key]
        raise ReportError(f"{r.key} was retired on {r.retired_at:%Y-%m-%d} and can't be "
                          "reused; use a new key.")

    known = {f.key: f for f in db.scalars(select(Feature).where(
        Feature.application_id == app.id)).all()}
    permissions = {p.key: p for p in db.scalars(select(Permission).where(
        Permission.application_id == app.id)).all()}
    modules = {p.module_key for p in permissions.values()}
    roles = db.scalars(select(Role)).all()
    out = Outcome(registered=len(reported))

    for f in reported:
        feature = known.get(f.key)
        if feature is None:
            # rows from before apps reported (#23) are existing, not new
            existed = f.key in modules
            feature = Feature(application_id=app.id, key=f.key, name=f.name,
                              is_new=not existed)
            db.add(feature)
            known[f.key] = feature
            if not existed:
                out.new.append(f.key)
        else:
            if feature.name != f.name:
                feature.name = f.name
                out.renamed.append(f.key)
            if feature.not_reported_since is not None:
                feature.not_reported_since = None
                out.back.append(f.key)

        for action in f.actions:
            key = f"{app.key}:{f.key}:{action}"
            if key in permissions:
                continue
            permission = Permission(key=key, application_id=app.id, module_key=f.key,
                                    action=action, description=f"{action.title()}: {f.name}")
            db.add(permission)
            db.flush()
            permissions[key] = permission
            # new things start switched off for everyone but Global Admin
            for role in roles:
                allowed = role.key == GLOBAL_ADMIN and role.org_id is None
                db.add(RolePermission(role_id=role.id, permission_id=permission.id,
                                      effect="allow" if allowed else "deny"))
            if f.key not in out.new:
                out.new_actions.append(f"{f.key}:{action}")
                feature.is_new = True

    reported_keys = {f.key for f in reported}
    for key in sorted((modules | set(known)) - reported_keys):
        feature = known.get(key)
        if feature is None:          # a module from before reports, never reported
            feature = Feature(application_id=app.id, key=key, name=key, is_new=False)
            db.add(feature)
            known[key] = feature
        if feature.not_reported_since is None:
            feature.not_reported_since = now
            out.gone_quiet.append(key)

    out.version_changed = version is not None and app.features_version != version
    out.total = len(known)
    out.not_reported = sum(1 for f in known.values() if f.not_reported_since is not None)
    out.marked_new = sum(1 for f in known.values() if f.is_new)
    app.features_reported_at = now
    if version is not None:
        app.features_version = version
    app.features_report = {"total": out.total, "new": out.marked_new,
                           "not_reported": out.not_reported}
    db.flush()
    return out


def reviewed(db: Session, application_id, module_keys) -> None:
    """An administrator changed a rule on these features: no longer new."""
    keys = list(set(module_keys))
    if keys:
        db.execute(update(Feature).where(Feature.application_id == application_id,
                                         Feature.key.in_(keys)).values(is_new=False))


def remove(db: Session, app: Application, key: str, retired_by, now: datetime) -> Feature:
    """Delete a feature the app no longer reports — its permissions, every role
    rule and grid setting on it — and retire its key. Raises LookupError if
    there is no such feature, ValueError if the app still reports it."""
    feature = db.scalar(select(Feature).where(Feature.application_id == app.id,
                                              Feature.key == key))
    if feature is None:
        raise LookupError(f"{app.name} has no feature {key!r}.")
    if feature.not_reported_since is None:
        raise ValueError(f"{app.name} still reports {key!r}; only a feature the app no "
                         "longer reports can be removed.")
    ids = list(db.scalars(select(Permission.id).where(
        Permission.application_id == app.id, Permission.module_key == key)).all())
    if ids:
        db.execute(delete(RolePermission).where(RolePermission.permission_id.in_(ids)))
        db.execute(delete(Permission).where(Permission.id.in_(ids)))
    for model in (ToolRule, ToolSetting):
        db.execute(delete(model).where(model.application_id == app.id, model.module_key == key))
    db.add(RetiredFeature(application_id=app.id, key=key, name=feature.name,
                          retired_at=now, retired_by=retired_by))
    db.delete(feature)
    db.flush()
    return feature
