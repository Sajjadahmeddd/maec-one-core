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

It seeds the organisation, the applications themselves (key, name, status),
the roles, the subscriptions and the first accounts — and no application's
features. Those are each application's own: it reports them when it starts
(PUT /api/gate/features, OPEN-DECISIONS #23), and they appear in Tool-Level
Settings then. The seed never removes or changes anything an app registered,
or any permission and role rule already in the database.

Existing passwords are LEFT ALONE. Set SEED_RESET_PASSWORDS=1 to re-apply the
bootstrap password and clear any lockout — the recovery path for a lost or
locked-out admin account. It is opt-in
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
from . import lockout, security, sessions
from .db import session_factory
from .models import (
    Application, Organization, Role, Subscription, User, UserLicense, UserRole,
)

ORG = {"name": "Mirage AEC", "domain": "mirageaec.com"}

# Keys match the launcher tiles exactly.
APPLICATIONS = [
    ("engineering", "Engineering Tools", "HAPExt, AirSizer Pro, HAPAudit & more", "live"),
    ("projects", "Project Management", "Plan, track and deliver projects efficiently", "coming_soon"),
    ("finance", "Finance & Billing", "Expenses, monitoring and invoice generation", "coming_soon"),
    ("people", "People & HR", "Attendance, leave, timesheet & more", "coming_soon"),
    # coming_soon: nothing is behind it yet. Seeded as live before Prompt 15;
    # run() corrects an existing database (see "-- corrections").
    ("timesheet", "Timesheet", "Submit and manage your timesheets", "coming_soon"),
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

    # An application that exists is never changed or removed here: since
    # Prompt 19 a Global Admin adds and edits applications on the Applications
    # screen, and the seed only creates the first ones when they are absent.
    # (The one-off Timesheet correction of Prompt 15 has done its work on every
    # database and is gone: it changed an existing row.)

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

    # -- the subscriptions: Engineering Tools and Project Management, neither
    # capped (seats NULL). Seats are still per person; there is just no limit
    # on how many the organisation may hand out.
    engineering, projects = apps["engineering"], apps["projects"]
    for application in (engineering, projects):
        if _one(db, Subscription, org_id=org.id, application_id=application.id) is None:
            db.add(Subscription(org_id=org.id, application_id=application.id,
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
    elif reset:
        # The recovery path for an administrator who cannot get in: the
        # password, and whatever lock their failed attempts left behind —
        # re-applying a password to an account that stays locked for another
        # half hour recovers nothing.
        if not security.verify_password(password, user.password_hash):
            user.password_hash = security.hash_password(password)
            # as any password change does: sessions minted under the old one end
            sessions.revoke_all(db, user.id)
            made("password resets")
        if lockout.clear(db, user.id):
            made("lockouts cleared")
        db.flush()
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
        print("seed: SEED_RESET_PASSWORDS was set — bootstrap passwords re-applied "
              "and lockouts cleared.")
    print(f"seed: Global Admin is {admin_email}"
          + (f"; test engineer is {test_email}" if test_email and test_password else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
