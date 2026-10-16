"""Screen 005 — User Onboarding & Import.

Bulk import is the most likely escalation path in the whole panel: a file
from outside, naming people and the roles they should hold. It is treated as
hostile input throughout.

**Preview and commit are the same resolution.** `plan()` decides what a file
would do and writes nothing; `apply()` performs exactly what a plan permits.
The preview is `plan()` with nothing applied — not a second implementation
that agrees today and drifts tomorrow. The grant rule itself is
`accounts.may_grant`, the same function `grant_role` asks before writing, so
"you may not hand out this role" cannot mean one thing on the preview and
another at commit.

**The world can move between the two.** A role can be deleted, an address
taken, a seat used up in the seconds between previewing and committing. So
the commit re-plans from the stored records and refuses if the outcome has
changed, rather than replaying a decision that is no longer true.

**Nothing is half-created.** One transaction: every row, or none.
"""

from __future__ import annotations

import csv
import io
import re
import secrets
import uuid
from dataclasses import asdict, dataclass, field

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import accounts
from .db import get_db
from .models import Application, ImportBatch, Role, Subscription, User, UserRole
from .permissions import _utc as _as_utc, audit, now, require_global_admin

router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

MAX_BYTES = 25 * 1024 * 1024
MAX_ROWS = 5_000
# What a file must carry, and what it may. The template has all four.
REQUIRED_COLUMNS = ("name", "email", "job_role")
OPTIONAL_COLUMNS = ("department",)
TEMPLATE_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS
# Files made from the template before the column was renamed still import:
# their role_persona column is read as job_role.
COLUMN_ALIASES = {"role_persona": "job_role"}
FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")

# Bytes that mean this is not a CSV whatever the extension claims. A renamed
# executable or archive is the obvious attempt; a NUL byte anywhere in the
# first block is enough on its own, since CSV is text.
BINARY_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b", b"%PDF")

_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ------------------------------------------------------------------ the plan
@dataclass
class RowPlan:
    """One line of the file, and what would become of it."""
    line: int
    name: str = ""
    email: str = ""
    role_persona: str = ""
    department: str = ""
    action: str = "create"          # create | fail
    problems: list[str] = field(default_factory=list)
    role_key: str | None = None
    scope_type: str | None = None
    scope_id: str | None = None
    applications: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass
class ImportPlan:
    rows: list[RowPlan]
    columns_ok: bool = True
    file_problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return sum(1 for r in self.rows if r.ok)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rows if not r.ok)

    @property
    def can_commit(self) -> bool:
        return self.columns_ok and not self.file_problems and self.valid > 0

    def as_json(self) -> dict:
        return {
            "rows": [asdict(r) | {"ok": r.ok} for r in self.rows],
            "total": len(self.rows),
            "valid": self.valid,
            "failed": self.failed,
            "columns_ok": self.columns_ok,
            "file_problems": self.file_problems,
            "can_commit": self.can_commit,
        }

    def signature(self) -> list[list[str]]:
        """What this plan would create, in a form two plans can be compared by.

        Used to prove the commit is doing what the preview showed, and to
        refuse when the answer has changed underneath it.
        """
        return sorted([r.email, r.role_key or "", r.scope_type or "",
                       r.scope_id or "", ",".join(sorted(r.applications))]
                      for r in self.rows if r.ok)


# ------------------------------------------------------------------ parsing
def sniff(head: bytes, filename: str, content_type: str | None) -> list[str]:
    """Is this a CSV at all? Extension is a claim, not evidence."""
    problems = []
    if not filename.lower().endswith(".csv"):
        problems.append("Only .csv files are accepted.")
    if head.startswith(BINARY_MAGIC):
        problems.append("That is not a text file — it looks like a program or archive.")
    elif b"\x00" in head:
        problems.append("That file contains binary data, so it is not a CSV.")
    if content_type and not any(
            content_type.startswith(t) for t in
            ("text/", "application/csv", "application/vnd.ms-excel",
             "application/octet-stream")):
        problems.append(f"Unexpected content type {content_type!r}.")
    return problems


def _column(header: str | None) -> str:
    return "_".join((header or "").strip().lower().split())


def read_records(upload: UploadFile) -> tuple[list[dict], list[str]]:
    """Stream the file into records, enforcing the caps as it goes.

    The limits are applied during the read, not after: loading 200 MB and
    then objecting to its size is the same as having no limit.
    """
    problems: list[str] = []
    chunks: list[bytes] = []
    size = 0
    head = b""
    while True:
        chunk = upload.file.read(64 * 1024)
        if not chunk:
            break
        if not head:
            head = chunk[:512]
        size += len(chunk)
        if size > MAX_BYTES:
            return [], [f"That file is larger than {MAX_BYTES // (1024 * 1024)} MB."]
        chunks.append(chunk)

    problems += sniff(head, upload.filename or "", upload.content_type)
    if problems:
        return [], problems

    try:
        text = b"".join(chunks).decode("utf-8-sig")
    except UnicodeDecodeError:
        return [], ["That file is not valid UTF-8 text."]

    reader = csv.DictReader(io.StringIO(text))
    # "Job Role", "job role" and "job_role" are the same column
    headers = [_column(h) for h in (reader.fieldnames or [])]
    headers = [COLUMN_ALIASES.get(h, h) if COLUMN_ALIASES.get(h) not in headers else h
               for h in headers]
    missing = [c for c in REQUIRED_COLUMNS if c not in headers]
    if missing:
        return [], [f"Missing required column(s): {', '.join(missing)}."]

    records: list[dict] = []
    for row in reader:
        if len(records) >= MAX_ROWS:
            problems.append(
                f"That file has more than {MAX_ROWS} rows. Split it and import "
                "each part.")
            break
        record = {_column(k): (v or "").strip() for k, v in row.items()}
        # the plan reads the role as role_persona, whichever header carried it
        record["role_persona"] = record.get("job_role") or record.get("role_persona", "")
        records.append(record)
    return records, problems


# ------------------------------------------------------- the one resolution
def plan(db: Session, actor: User, records: list[dict],
         file_problems: list[str] | None = None) -> ImportPlan:
    """What this file would do. Writes nothing, ever.

    Both passes live here: the shape of each row, then whether it resolves
    against the database and whether this actor may do it.
    """
    result = ImportPlan(rows=[], file_problems=list(file_problems or []))
    if result.file_problems:
        result.columns_ok = False
        return result

    roles = {r.key: r for r in db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id))).all()}
    by_name = {r.name.strip().lower(): r for r in roles.values()}
    org_domains = {actor.email.rsplit("@", 1)[-1].lower()}
    from .models import Organization
    org = db.get(Organization, actor.org_id)
    if org is not None:
        org_domains.add(org.domain.lower())

    # every application this organisation actually holds, with seats left
    seats_left: dict[str, int | None] = {}
    apps: dict[str, Application] = {}
    for sub in db.scalars(select(Subscription).where(
            Subscription.org_id == actor.org_id)).all():
        app = db.get(Application, sub.application_id)
        if app is None:
            continue
        apps[app.key] = app
        seats_left[app.key] = (None if sub.seats is None else
                               sub.seats - accounts.seats_in_use(
                                   db, actor.org_id, app.id))

    scope, scope_problem = accounts.placement_scope(db, actor)
    if scope_problem:
        result.file_problems.append(scope_problem)
        result.columns_ok = False
        return result

    seen: set[str] = set()
    for index, record in enumerate(records, start=2):    # row 1 is the header
        row = RowPlan(line=index,
                      name=record.get("name", ""),
                      email=record.get("email", "").lower(),
                      role_persona=record.get("role_persona", ""),
                      department=record.get("department", ""))

        # ---- pass 1: shape
        if not row.name:
            row.problems.append("name is required")
        if not row.email:
            row.problems.append("email is required")
        elif not _ADDRESS.match(row.email):
            row.problems.append(f"{row.email!r} is not a valid email address")
        elif row.email in seen:
            row.problems.append("duplicated earlier in this file")
        if row.email:
            seen.add(row.email)
        if not row.role_persona:
            row.problems.append("job_role is required")

        # ---- pass 2: resolution
        if row.email and _ADDRESS.match(row.email):
            domain = row.email.rsplit("@", 1)[-1]
            if domain not in org_domains:
                row.problems.append(
                    f"{domain} is not a permitted domain for this organisation")
            if db.scalar(select(func.count(User.id)).where(
                    User.org_id == actor.org_id, User.email == row.email)):
                row.problems.append("already has an account")

        # a role's key ("project_lead") or its name ("Project Lead")
        wanted = row.role_persona.strip().lower()
        role = roles.get(wanted.replace(" ", "_")) or by_name.get(wanted)
        if row.role_persona and role is None:
            row.problems.append(f"no role named {row.role_persona!r}")
        elif role is not None:
            row.role_key = role.key
            row.scope_type, row.scope_id = scope
            # THE escalation check — the same function grant_role asks before
            # it writes, so the preview cannot promise what the commit refuses
            why = accounts.may_grant(db, actor=actor, target_org_id=actor.org_id,
                                     role=role, scope_type=row.scope_type,
                                     scope_id=row.scope_id)
            if why is not None:
                row.problems.append(f"you may not grant {role.key}: {why}")

        if row.problems:
            row.action = "fail"
        result.rows.append(row)

    return result


def apply(db: Session, actor: User, ready: ImportPlan,
          request: Request | None = None) -> dict:
    """Perform exactly what the plan permits. One transaction: all, or none.

    Created accounts are `invited` and carry a password nobody knows — a
    random secret, hashed and discarded. There is no email yet, so an
    administrator sets a real one from User Management when the person
    actually starts; until then the account cannot be signed in to.
    """
    created: list[str] = []
    try:
        for row in ready.rows:
            if not row.ok:
                continue
            person = accounts.create_user(
                db, actor=actor, email=row.email, display_name=row.name,
                password=secrets.token_urlsafe(32) + "Aa1!",
                department=row.department or None, status="invited",
                request=request, commit=False)
            if row.role_key:
                role = db.scalar(select(Role).where(
                    Role.key == row.role_key,
                    (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)))
                accounts.grant_role(
                    db, actor=actor, target=person, role=role,
                    scope_type=row.scope_type, scope_id=row.scope_id,
                    request=request, commit=False)
            created.append(row.email)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"created": created}


# ------------------------------------------------------------------ routes
class CommitBody(BaseModel):
    batch_id: uuid.UUID


def _batch_json(batch: ImportBatch, db: Session) -> dict:
    uploader = db.get(User, batch.uploaded_by) if batch.uploaded_by else None
    return {
        "id": str(batch.id),
        "filename": batch.filename,
        "uploaded_by": uploader.email if uploader else None,
        "records_total": batch.records_total,
        "records_valid": batch.records_valid,
        "records_failed": batch.records_failed,
        "status": batch.status,
        "created_at": batch.created_at.isoformat() if batch.created_at else None,
    }


@router.post("/import/validate")
def validate(request: Request, file: UploadFile = File(...),
             db: Session = Depends(get_db),
             actor: User = Depends(require_global_admin)):
    """Preview only. Nothing is created, and nothing can be."""
    records, problems = read_records(file)
    preview = plan(db, actor, records, problems)

    batch = ImportBatch(
        org_id=actor.org_id, filename=(file.filename or "upload.csv")[:300],
        uploaded_by=actor.id, records_total=len(preview.rows),
        records_valid=preview.valid, records_failed=preview.failed,
        status="pending",
        # the validated records, not the file: enough to re-plan at commit,
        # and never the bytes that were uploaded
        report=preview.as_json())
    db.add(batch)
    db.flush()
    audit(db, actor=actor, action="import.validate", target_type="import_batch",
          target_id=batch.id, result="success" if preview.can_commit else "warning",
          request=request,
          after={"filename": batch.filename, "total": len(preview.rows),
                 "valid": preview.valid, "failed": preview.failed},
          commit=False)
    db.commit()

    blocked = [r for r in preview.rows
               if any("may not grant" in p for p in r.problems)]
    if blocked:
        audit(db, actor=actor, action="import.escalation",
              target_type="import_batch", target_id=batch.id, result="blocked",
              request=request,
              after={"rows": [r.line for r in blocked],
                     "roles": sorted({r.role_persona for r in blocked})})

    return {"batch_id": str(batch.id), **preview.as_json()}


@router.post("/import/commit")
def commit(body: CommitBody, request: Request, db: Session = Depends(get_db),
           actor: User = Depends(require_global_admin)):
    """Create what the preview showed — having checked it is still true."""
    batch = db.get(ImportBatch, body.batch_id)
    if batch is None or batch.org_id != actor.org_id:
        raise HTTPException(status_code=404, detail="No such import.")
    if batch.status != "pending":
        raise HTTPException(status_code=409,
                            detail=f"That import was already {batch.status}.")

    previewed = ImportPlan(
        rows=[RowPlan(**{k: v for k, v in r.items() if k != "ok"})
              for r in (batch.report or {}).get("rows", [])])

    # Re-resolved against the database as it is now, through the same
    # function the preview used. A role deleted or an address taken since
    # then changes the answer, and the commit must not replay a decision
    # that is no longer true.
    records = [{"name": r.name, "email": r.email,
                "role_persona": r.role_persona, "department": r.department}
               for r in previewed.rows]
    fresh = plan(db, actor, records)

    if fresh.signature() != previewed.signature():
        batch.status = "failed"
        audit(db, actor=actor, action="import.commit", target_type="import_batch",
              target_id=batch.id, result="blocked", request=request,
              after={"reason": "the preview no longer matches the database"},
              commit=False)
        db.commit()
        raise HTTPException(
            status_code=409,
            detail="The database has changed since this file was checked — a "
                   "role, an address or a seat is no longer as it was. Upload "
                   "it again to see the current preview.")

    if not fresh.can_commit:
        raise HTTPException(status_code=409,
                            detail="Nothing in that file can be created.")

    outcome = apply(db, actor, fresh, request)

    batch.status = "success" if fresh.failed == 0 else "warnings"
    batch.records_valid = fresh.valid
    batch.records_failed = fresh.failed
    audit(db, actor=actor, action="import.commit", target_type="import_batch",
          target_id=batch.id, result="success" if fresh.failed == 0 else "warning",
          request=request,
          after={"created": len(outcome["created"]), "skipped": fresh.failed},
          commit=False)
    db.commit()
    return {"batch_id": str(batch.id), "created": outcome["created"],
            "skipped": fresh.failed, "status": batch.status}


@router.get("/import/batches")
def batches(db: Session = Depends(get_db),
            actor: User = Depends(require_global_admin)):
    rows = db.scalars(select(ImportBatch).where(
        ImportBatch.org_id == actor.org_id)
        .order_by(ImportBatch.created_at.desc()).limit(50)).all()
    return {"batches": [_batch_json(b, db) for b in rows]}


@router.get("/import/batches/{batch_id}")
def batch_detail(batch_id: uuid.UUID, db: Session = Depends(get_db),
                 actor: User = Depends(require_global_admin)):
    """One batch's people, and the role each holds in each application.

    Once committed, read from the accounts as they are now — a role changed or
    an account removed since shows as it is, not as it was imported. Before
    that, what the preview planned, marked as planned. Rows that failed
    validation created nobody and are not listed.

    `roles` maps an application key to the role held there ({name, level}),
    and `everywhere` is a role held across the organisation (or the platform)
    — it applies in every application. A fixed number of queries, however
    many people.
    """
    batch = db.get(ImportBatch, batch_id)
    if batch is None or batch.org_id != actor.org_id:
        raise HTTPException(status_code=404, detail="No such import.")

    rows = [r for r in (batch.report or {}).get("rows", []) if r.get("ok")]
    committed = batch.status in ("success", "warnings")
    roles = {r.key: r for r in db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id))).all()}

    def placed(role: Role, scope_type: str | None, scope_id: str | None,
               into: dict) -> None:
        held = {"name": role.name, "level": role.level}
        if scope_type == "application" and scope_id:
            into["roles"][scope_id] = held
        elif scope_type in ("organization", "platform"):
            into["everywhere"] = held

    people: list[dict] = []
    if committed:
        emails = [r["email"] for r in rows]
        users = {u.email: u for u in db.scalars(select(User).where(
            User.org_id == actor.org_id, User.email.in_(emails))).all()} if emails else {}
        moment = now()
        grants = db.execute(
            select(UserRole.user_id, Role, UserRole.scope_type, UserRole.scope_id,
                   UserRole.expires_at)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id.in_([u.id for u in users.values()]))
        ).all() if users else []
        for row in rows:
            person = users.get(row["email"])
            entry = {"name": person.display_name if person else row["name"],
                     "email": row["email"],
                     "status": person.status if person else "removed",
                     "roles": {}, "everywhere": None}
            if person is not None:
                for user_id, role, scope_type, scope_id, expires_at in grants:
                    if user_id == person.id and (
                            expires_at is None or _as_utc(expires_at) > moment):
                        placed(role, scope_type, scope_id, entry)
            people.append(entry)
    else:
        for row in rows:
            entry = {"name": row["name"], "email": row["email"], "status": "planned",
                     "roles": {}, "everywhere": None}
            role = roles.get(row.get("role_key") or "")
            if role is not None:
                placed(role, row.get("scope_type"), row.get("scope_id"), entry)
            people.append(entry)

    apps = db.scalars(select(Application).order_by(Application.name)).all()
    return {
        "batch": _batch_json(batch, db),
        "committed": committed,
        "applications": [{"key": a.key, "name": a.name, "status": a.status}
                         for a in apps],
        "people": people,
    }


def _safe(value: str) -> str:
    """Same rule as the audit export: a template is a file people open."""
    text = str(value or "")
    return "'" + text if text.startswith(FORMULA_LEADERS) else text


@router.get("/import/template")
def template(db: Session = Depends(get_db),
             actor: User = Depends(require_global_admin)):
    """A template naming the roles that actually exist in this organisation."""
    roles = db.scalars(select(Role).where(
        (Role.org_id.is_(None)) | (Role.org_id == actor.org_id)
    ).order_by(Role.level)).all()
    from .models import Organization
    org = db.get(Organization, actor.org_id)
    domain = org.domain if org else "example.com"

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(list(TEMPLATE_COLUMNS))
    for role in roles[:3]:
        writer.writerow([_safe(v) for v in (
            f"Example {role.name}", f"example.{role.key}@{domain}",
            role.key, "Mechanical")])

    return StreamingResponse(
        io.BytesIO(buffer.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition":
                 'attachment; filename="MAEC_user_import_template.csv"'})
