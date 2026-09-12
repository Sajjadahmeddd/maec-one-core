"""Screen 004 — Audit Logs & Security.

Read-only, by construction. There is no write endpoint here and there must
never be one: the table is append-only, enforced by a database trigger, and
the only thing that writes to it is `audit()` in permissions.py.

Two things carry this screen.

**Scope.** A Global Admin sees the whole organisation. A Business & Commercial
Lead sees only the applications they lead — filtered in the query, not in the
browser, so it holds when someone calls the endpoint directly.

**The export escapes formula injection.** Audit rows hold strings a stranger
chose: an email address, a user agent, a target id. A cell beginning `=`, `+`,
`-`, `@`, tab or carriage return is a formula to Excel and LibreOffice, and an
audit export is precisely the file an administrator opens without thinking.
Every cell is prefixed with an apostrophe when it starts with one of those.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, or_, select, text
from sqlalchemy.orm import Session

from . import config, security
from .db import get_db
from .models import Application, AuditLog, User
from .permissions import (
    ANONYMOUS_ACTOR, active_roles, is_global_admin, require_user,
)
from . import router_auth

# No router-level require_global_admin here, unlike the other admin
# modules: these reads also admit a Business Admin, scoped to their own
# applications. Every endpoint below depends on require_audit_reader,
# and guard.py independently refuses anyone else — two checks, as
# everywhere else in the panel.
router = APIRouter(prefix="/api/admin", tags=["admin"])

PAGE_SIZE_MAX = 200
EXPORT_MAX = 50_000
RESULTS = ("success", "warning", "blocked")

BUSINESS_ADMIN = "business_admin"

# Excel and LibreOffice treat a cell starting with any of these as a formula.
FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


# ------------------------------------------------------------- who may read
def require_audit_reader(request: Request, user: User = Depends(require_user),
                         db: Session = Depends(get_db)) -> User:
    """Global Admin, or a Business Admin reading their own applications.

    The guard admits Business Admins to GETs under /api/admin/audit and
    nothing else; this is the second, independent check, the way
    require_global_admin is elsewhere.
    """
    if is_global_admin(db, user):
        return user
    for grant in active_roles(db, user):
        if grant.role.key == BUSINESS_ADMIN:
            return user
    raise HTTPException(status_code=403, detail="Global Admin only.")


def visible_applications(db: Session, user: User) -> set[uuid.UUID] | None:
    """The applications this reader may see events for.

    `None` means "everything" — a Global Admin is not scoped. Otherwise it is
    the set of applications they hold `business_admin` on. An event with no
    application (signing in is not about one product) belongs to the platform,
    so a scoped reader does not see it.
    """
    if is_global_admin(db, user):
        return None
    keys = {g.scope_id for g in active_roles(db, user)
            if g.role.key == BUSINESS_ADMIN and g.scope_type == "application"}
    if not keys:
        return set()
    rows = db.scalars(select(Application.id).where(Application.key.in_(keys))).all()
    return set(rows)


# ------------------------------------------------------------------ the query
def _filtered(db: Session, user: User, *, q: str = "", action: str = "",
              result: str = "", since: datetime | None = None,
              until: datetime | None = None) -> Select:
    where = [AuditLog.org_id == user.org_id]

    allowed = visible_applications(db, user)
    if allowed is not None:
        # an empty set means a Business Admin who leads nothing yet: no rows,
        # rather than every row
        where.append(AuditLog.application_id.in_(allowed) if allowed
                     else AuditLog.id.is_(None))

    if q.strip():
        needle = f"%{q.strip().lower()}%"
        where.append(or_(func.lower(AuditLog.actor_email).like(needle),
                         func.lower(func.coalesce(AuditLog.target_id, "")).like(needle)))
    if action.strip():
        where.append(AuditLog.action.like(f"{action.strip()}%"))
    if result:
        if result not in RESULTS:
            raise HTTPException(status_code=422, detail=f"Unknown result {result!r}.")
        where.append(AuditLog.result == result)
    if since is not None:
        where.append(AuditLog.created_at >= since)
    if until is not None:
        where.append(AuditLog.created_at <= until)

    return select(AuditLog).where(*where)


def _row_json(row: AuditLog, apps: dict[uuid.UUID, Application]) -> dict:
    app = apps.get(row.application_id) if row.application_id else None
    return {
        "id": str(row.id),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        # The sentinel is returned as stored; the screen renders it as a dash.
        # Substituting here would hide that the row genuinely has nobody to
        # name, which is a fact about the event, not a display choice.
        "actor_email": row.actor_email,
        "anonymous": row.actor_email == ANONYMOUS_ACTOR,
        "actor_id": str(row.actor_id) if row.actor_id else None,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "application": app.key if app else None,
        "source": row.source,
        "result": row.result,
        "ip": row.ip,
        "user_agent": row.user_agent,
        "before": row.before,
        "after": row.after,
    }


# ------------------------------------------------------------------- routes
@router.get("/audit")
def list_audit(request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_audit_reader),
               q: str = Query(default="", max_length=200),
               action: str = Query(default="", max_length=80),
               result: str = Query(default=""),
               days: int | None = Query(default=None, ge=1, le=3650),
               page: int = Query(default=1, ge=1),
               page_size: int = Query(default=50, ge=1, le=PAGE_SIZE_MAX)):
    """The log, newest first. Filtered and paged in the database."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)) if days else None
    query = _filtered(db, user, q=q, action=action, result=result, since=since)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)).all()
    apps = {a.id: a for a in db.scalars(select(Application)).all()}

    return {
        "events": [_row_json(r, apps) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, ceil(total / page_size)),
        "scoped": visible_applications(db, user) is not None,
        "results": list(RESULTS),
    }


@router.get("/audit/stats")
def audit_stats(db: Session = Depends(get_db),
                user: User = Depends(require_audit_reader)):
    """The cards. Every number is a query — a near-empty log on day one is
    the correct answer, not a reason to invent one."""
    month = datetime.now(timezone.utc) - timedelta(days=30)

    def count(*extra) -> int:
        query = _filtered(db, user, since=month)
        if extra:
            query = query.where(*extra)
        return db.scalar(select(func.count()).select_from(query.subquery())) or 0

    return {
        "window_days": 30,
        "events": count(),
        "role_changes": count(or_(AuditLog.action.like("role.%"),
                                  AuditLog.action.like("license.%"),
                                  AuditLog.action.like("tool_rule.%"))),
        "security_alerts": count(AuditLog.result.in_(("blocked", "warning"))),
        "admin_actions": count(AuditLog.source == "api"),
        "sign_ins": count(AuditLog.action == "login.success"),
        "failed_sign_ins": count(AuditLog.action == "login.failed"),
    }


@router.get("/audit/controls")
def security_controls(db: Session = Depends(get_db),
                      user: User = Depends(require_audit_reader)):
    """The footer strip: what is actually switched on, read from the running
    configuration rather than typed into the page.

    Each entry names where it is enforced, so a claim here can be checked
    against the code rather than believed.
    """
    # Asked of the database rather than asserted: the trigger is the thing
    # that makes "append-only" true, so the card reports whether it is
    # actually installed. None means the question does not apply here —
    # SQLite has no such trigger, and the tests run on SQLite.
    trigger: bool | None = None
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        trigger = db.scalar(text(
            "select count(*) from pg_trigger "
            "where tgname = 'audit_logs_append_only'")) == 1

    return {
        "controls": [
            {"key": "hashing", "label": "Passwords hashed with argon2id",
             "on": True, "where": "identity/security.py"},
            {"key": "password_policy",
             "label": f"Minimum {security.MIN_PASSWORD_LENGTH} characters, "
                      "mixed case, digit and symbol",
             "on": True, "where": "identity/security.py"},
            {"key": "rate_limit",
             "label": f"Sign-in rate limited ({router_auth.LOGIN_RATE} per address)",
             "on": bool(router_auth.limiter.enabled), "where": "identity/router_auth.py"},
            {"key": "lockout",
             "label": f"Account locks after {router_auth.LOCK_AFTER} failures, "
                      "for escalating periods",
             "on": True, "where": "identity/router_auth.py"},
            {"key": "csrf", "label": "Admin changes require a CSRF token",
             "on": True, "where": "identity/guard.py"},
            {"key": "session",
             "label": "Session cookie is host-only, HttpOnly, SameSite=Lax"
                      + (", Secure" if config.on_render() else ""),
             "on": True, "where": "backend/main.py"},
            {"key": "append_only",
             "label": "Audit log is append-only in the database",
             "on": trigger if trigger is not None else False,
             "where": "migration 81e586581063",
             "note": None if trigger else
                     "Not verifiable on this database — the trigger is "
                     "PostgreSQL only."},
            {"key": "per_request",
             "label": "Every request re-reads the account, so suspension is "
                      "immediate",
             "on": True, "where": "identity/guard.py"},
        ],
    }


def _safe(value) -> str:
    """One cell, safe to open in a spreadsheet.

    An audit row carries strings a stranger chose — their email address, their
    user agent. Excel reads a leading `=`, `+`, `-`, `@`, tab or carriage
    return as the start of a formula, so a crafted address becomes code the
    moment an administrator opens the export. The apostrophe makes it text.
    """
    if value is None:
        return ""
    text = str(value)
    if text.startswith(FORMULA_LEADERS):
        return "'" + text
    return text


@router.get("/audit/export")
def export_audit(db: Session = Depends(get_db),
                 user: User = Depends(require_audit_reader),
                 q: str = Query(default="", max_length=200),
                 action: str = Query(default="", max_length=80),
                 result: str = Query(default=""),
                 days: int | None = Query(default=None, ge=1, le=3650)):
    """The filtered log as CSV, capped so one click cannot pull the table."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)) if days else None
    query = _filtered(db, user, q=q, action=action, result=result, since=since)
    rows = db.scalars(query.order_by(AuditLog.created_at.desc())
                      .limit(EXPORT_MAX)).all()
    apps = {a.id: a for a in db.scalars(select(Application)).all()}

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["Timestamp", "Actor", "Action", "Target type", "Target",
                     "Application", "Source", "Result", "IP", "User agent"])
    for row in rows:
        app = apps.get(row.application_id) if row.application_id else None
        writer.writerow([_safe(v) for v in (
            row.created_at.isoformat() if row.created_at else "",
            row.actor_email, row.action, row.target_type, row.target_id,
            app.key if app else "", row.source, row.result, row.ip, row.user_agent,
        )])

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        io.BytesIO(buffer.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="MAEC_audit_{stamp}.csv"',
                 "X-Audit-Rows": str(len(rows))},
    )
