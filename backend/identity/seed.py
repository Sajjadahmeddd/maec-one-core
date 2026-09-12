"""Bootstrap data. Idempotent: run it as often as you like.

    python -m backend.identity.seed

Reads from the environment (or .env):

    BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD   the first Global Admin
    SEED_TEST_USER_EMAIL / SEED_TEST_USER_PASSWORD     an ordinary engineer —
                                                       created ONLY when both
                                                       are set, so a production
                                                       seed never makes one

Every row is looked up by its natural key before it is created, so a second
run changes nothing. It is safe to run on every deploy, which is what the
Render start command does.

Existing passwords are LEFT ALONE. Set SEED_RESET_PASSWORDS=1 to re-apply the
bootstrap password — the recovery path for a lost admin account. It is opt-in
because this runs on every boot, and a restart must never quietly undo a
password somebody has since changed.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config  # noqa: F401  (loads .env)
from . import security
from .db import session_factory
from .models import (
    Application, Organization, Permission, Role, RolePermission, Subscription,
    User, UserLicense, UserRole,
)

ORG = {"name": "Mirage AEC", "domain": "mirageaec.com"}

# Keys match the launcher tiles exactly.
APPLICATIONS = [
    ("engineering", "Engineering Tools", "HAPExt, AirSizer Pro, HAPAudit & more", "live"),
    ("projects", "Project Management", "Plan, track and deliver projects efficiently", "coming_soon"),
    ("finance", "Finance & Billing", "Expenses, monitoring and invoice generation", "coming_soon"),
    ("people", "People & HR", "Attendance, leave, timesheet & more", "coming_soon"),
    ("timesheet", "Timesheet", "Submit and manage your timesheets", "live"),
    ("expenses", "Expense Control", "Track, approve and monitor expenses", "coming_soon"),
    ("attendance", "Attendance", "Daily attendance and team overview", "coming_soon"),
    ("kpa", "KPI", "Manage KPIs and performance goals", "coming_soon"),
]

# The exact hierarchy. Do not add levels.
ROLES = [
    ("global_admin", "Global Admin", 1,
     "Spans every organisation. Assigned to a named person, never shared."),
    ("business_admin", "Business & Commercial Lead", 2,
     "Allocates projects, resources and project leads within one application."),
    ("project_lead", "Project Lead", 3,
     "Manages the engineers on one project."),
    ("employee", "Normal User / Engineer", 4,
     "Uses the tools on the projects they are placed on."),
]

ENGINEERING_MODULES = ["hapext", "airsizer", "hapaudit", "rebadge"]
ACTIONS = ["view", "convert", "export", "configure"]

# What each role gets on each module, by default. Explicit denies are real
# rows, not omissions — so "deny beats allow" has something to bite on.
#   allow: every action;  deny: named actions denied, the rest allowed
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

FAR_FUTURE = datetime(2099, 12, 31, tzinfo=timezone.utc)


def _one(db: Session, model, **key):
    return db.scalar(select(model).filter_by(**key))


def run(db: Session, *, admin_email: str, admin_password: str,
        test_email: str | None = None, test_password: str | None = None,
        reset_passwords: bool = False) -> dict:
    """Seed everything. Returns counts of what was created this run.

    `reset_passwords` is off by default because this runs on every deploy.
    Left on, a restart would silently undo a password someone had changed;
    turned on deliberately (SEED_RESET_PASSWORDS=1) it is the recovery path
    for a lost admin password.
    """
    created: dict[str, int] = {}

    def made(kind: str):
        created[kind] = created.get(kind, 0) + 1

    # -- organisation
    org = _one(db, Organization, domain=ORG["domain"])
    if org is None:
        org = Organization(**ORG)
        db.add(org)
        db.flush()
        made("organizations")

    # -- applications
    apps: dict[str, Application] = {}
    for key, name, description, status in APPLICATIONS:
        app = _one(db, Application, key=key)
        if app is None:
            app = Application(key=key, name=name, description=description, status=status)
            db.add(app)
            db.flush()
            made("applications")
        apps[key] = app

    # -- roles (system: org_id NULL)
    roles: dict[str, Role] = {}
    for key, name, level, description in ROLES:
        role = _one(db, Role, key=key, org_id=None)
        if role is None:
            role = Role(key=key, name=name, level=level, description=description)
            db.add(role)
            db.flush()
            made("roles")
        roles[key] = role

    # -- permissions for engineering
    engineering = apps["engineering"]
    permissions: dict[str, Permission] = {}
    for module in ENGINEERING_MODULES:
        for action in ACTIONS:
            key = f"engineering:{module}:{action}"
            permission = _one(db, Permission, key=key)
            if permission is None:
                permission = Permission(
                    key=key, application_id=engineering.id, module_key=module,
                    action=action, description=f"{action.title()} in {module}")
                db.add(permission)
                db.flush()
                made("permissions")
            permissions[key] = permission

    # -- role defaults
    for role_key, modules in ROLE_DEFAULTS.items():
        role = roles[role_key]
        for module, actions in modules.items():
            for action, effect in actions.items():
                permission = permissions[f"engineering:{module}:{action}"]
                rp = _one(db, RolePermission, role_id=role.id, permission_id=permission.id)
                if rp is None:
                    db.add(RolePermission(role_id=role.id, permission_id=permission.id,
                                          effect=effect))
                    made("role_permissions")
    db.flush()

    # -- the subscription
    if _one(db, Subscription, org_id=org.id, application_id=engineering.id) is None:
        db.add(Subscription(org_id=org.id, application_id=engineering.id,
                            valid_from=datetime.now(timezone.utc), valid_to=FAR_FUTURE))
        db.flush()
        made("subscriptions")

    # -- the first Global Admin
    admin = _user(db, org, admin_email, admin_password, "Global Admin", made,
                  reset=reset_passwords)
    _grant(db, admin, roles["global_admin"], "platform", None, made)
    _license(db, admin, engineering, made)

    # -- an ordinary engineer, only when asked for
    if test_email and test_password:
        engineer = _user(db, org, test_email, test_password, "Test Engineer", made,
                         reset=reset_passwords)
        # granted at the application until a project registry exists; see
        # the brief's open item on where projects live
        _grant(db, engineer, roles["employee"], "application", "engineering", made)
        _license(db, engineer, engineering, made)

    db.commit()
    return created


def _user(db, org, email, password, display_name, made, *, reset: bool) -> User:
    email = email.strip().lower()
    security.check_password_policy(password, email=email)
    user = _one(db, User, org_id=org.id, email=email)
    if user is None:
        user = User(org_id=org.id, email=email, display_name=display_name,
                    password_hash=security.hash_password(password), status="active")
        db.add(user)
        db.flush()
        made("users")
    elif reset and not security.verify_password(password, user.password_hash):
        user.password_hash = security.hash_password(password)
        db.flush()
        made("password resets")
    return user


def _grant(db, user, role, scope_type, scope_id, made) -> None:
    if _one(db, UserRole, user_id=user.id, role_id=role.id,
            scope_type=scope_type, scope_id=scope_id) is None:
        db.add(UserRole(user_id=user.id, role_id=role.id,
                        scope_type=scope_type, scope_id=scope_id))
        db.flush()
        made("user_roles")


def _license(db, user, app, made) -> None:
    if _one(db, UserLicense, user_id=user.id, application_id=app.id) is None:
        db.add(UserLicense(user_id=user.id, application_id=app.id))
        db.flush()
        made("user_licenses")


def main() -> int:
    admin_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip()
    admin_password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not admin_email or not admin_password:
        print("seed: BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required.")
        return 2
    test_email = os.environ.get("SEED_TEST_USER_EMAIL", "").strip() or None
    test_password = os.environ.get("SEED_TEST_USER_PASSWORD", "") or None
    reset = os.environ.get("SEED_RESET_PASSWORDS", "").strip().lower() in ("1", "true", "yes")

    db = session_factory()()
    try:
        created = run(db, admin_email=admin_email, admin_password=admin_password,
                      test_email=test_email, test_password=test_password,
                      reset_passwords=reset)
    except security.WeakPasswordError as exc:
        print(f"seed: refused — {exc}")
        return 2
    finally:
        db.close()

    if created:
        print("seed: created " + ", ".join(f"{n} {k}" for k, n in sorted(created.items())))
    else:
        print("seed: nothing to do — everything was already in place")
    if reset:
        print("seed: SEED_RESET_PASSWORDS was set — bootstrap passwords re-applied.")
    print(f"seed: Global Admin is {admin_email}"
          + (f"; test engineer is {test_email}" if test_email and test_password else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
