"""The registry as production's database holds it from before apps reported.

Until OPEN-DECISIONS #23 the seed wrote Engineering Tools' four features and
Project Management's one permission, with every built-in role's rules. Core's
code no longer names any of them; the rows stay in the database and the apps
now report them. These tests run against that same state, so it lives here —
in the tests, the only place an application's feature keys may appear in
Core (test_no_feature_keys_in_core.py).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.identity.models import Application, Permission, Role, RolePermission

ENGINEERING_MODULES = ["hapext", "airsizer", "hapaudit", "rebadge"]
ACTIONS = ["view", "convert", "export", "configure"]

# What each built-in role was given on each module. Explicit denies are real
# rows, so "deny beats allow" has something to bite on.
ROLE_DEFAULTS: dict[str, dict[str, dict[str, str]]] = {
    "global_admin":   {m: {a: "allow" for a in ACTIONS} for m in ENGINEERING_MODULES},
    "business_admin": {m: {a: "allow" for a in ACTIONS} for m in ENGINEERING_MODULES},
    "project_lead":   {m: {**{a: "allow" for a in ACTIONS}, "configure": "deny"}
                       for m in ENGINEERING_MODULES},
    "employee": {
        "hapext":   {"view": "allow", "convert": "allow", "export": "allow", "configure": "deny"},
        "airsizer": {"view": "allow", "convert": "allow", "export": "allow", "configure": "deny"},
        "rebadge":  {"view": "allow", "convert": "allow", "export": "allow", "configure": "deny"},
        "hapaudit": {"view": "allow", "convert": "deny", "export": "deny", "configure": "deny"},
    },
}

# Project Management: one permission, allowed for every built-in role.
PROJECTS = ("app", "use")
BUILT_IN = ("global_admin", "business_admin", "project_lead", "employee")


def install(db: Session) -> None:
    """Write the rows the old seed wrote, exactly. Idempotent."""
    apps = {a.key: a for a in db.scalars(select(Application)).all()}
    roles = {r.key: r for r in db.scalars(select(Role).where(Role.org_id.is_(None))).all()}

    def permission(app, module, action, description):
        key = f"{app.key}:{module}:{action}"
        row = db.scalar(select(Permission).where(Permission.key == key))
        if row is None:
            row = Permission(key=key, application_id=app.id, module_key=module,
                             action=action, description=description)
            db.add(row)
            db.flush()
        return row

    def rule(role, row, effect):
        if db.scalar(select(RolePermission).where(RolePermission.role_id == role.id,
                                                  RolePermission.permission_id == row.id)) is None:
            db.add(RolePermission(role_id=role.id, permission_id=row.id, effect=effect))

    engineering = apps["engineering"]
    for role_key, modules in ROLE_DEFAULTS.items():
        for module, actions in modules.items():
            for action, effect in actions.items():
                rule(roles[role_key],
                     permission(engineering, module, action, f"{action.title()} in {module}"),
                     effect)

    module, action = PROJECTS
    row = permission(apps["projects"], module, action, "Use Project Management")
    for role_key in BUILT_IN:
        rule(roles[role_key], row, "allow")
    db.commit()
