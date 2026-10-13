"""Import Project Management's people into Core, from the command line.

    python -m backend.identity.import_users --file people.csv              # dry run
    python -m backend.identity.import_users --file people.csv --commit \\
        --temp-passwords-out /tmp/temporary-passwords.csv

    # on the VPS, inside the Core container, the CSV on stdin:
    docker compose -f deploy/compose.yml --env-file deploy/env.production \\
        exec -T core python -m backend.identity.import_users --file - [--commit] < people.csv

The CSV has exactly these columns, in any order:

    email, name, role, password_hash, password_scheme, must_change_password

* role — bu_head or engineer. What each becomes is decided here, not in the
  file: bu_head is Global Admin at platform scope; engineer is Employee
  (Normal User / Engineer) for the application `projects`. Both get a
  Project Management seat.
* email — lowercased and trimmed. Matched case-insensitively.
* name — kept exactly as given, never normalised: Project Management matches
  its older project-lead rows by full name.
* password_scheme — promanage_pbkdf2, with a hash in exactly the shape
  security.PROMANAGE_HASH accepts: the hash is stored as it is, the person
  keeps their password, and their first sign-in re-hashes it to argon2id.
  must_change_password is carried over. Empty: a temporary password is
  generated, must_change_password is set, and the temporary passwords are
  written once to --temp-passwords-out (created mode 600, never overwritten),
  never to the screen or a log.

A dry run (the default) changes nothing and prints, per row, what a commit
would do and why — by row number, never an email or a hash. Rows whose email
is outside @mirageaec.com are allowed, and counted as a warning.

The whole file is rejected, before anything is written, if any email is
invalid or appears twice, any role or password_scheme is unknown, any
promanage_pbkdf2 hash is malformed, or a column is missing.

Idempotent by email: a person who already has an account is never changed —
not their password, status or name; only a missing role or seat is added. A
second run changes nothing. Every account, role and seat goes through
accounts.create_user, grant_role and assign_license, so the rules, limits and
audit rows that apply in the admin panel apply here. One transaction: any
refusal rolls back the whole run.

Acts as the organisation's first Global Admin (the one the seed creates):
create_user and grant_role need an administrator, and the audit rows for each
account name them. One more row, import.commit, records the run itself as
"(command line)", with its counts; so does one import_batches row.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func, select

from . import config  # noqa: F401  (loads .env)
from . import accounts, security, seed
from .db import session_factory
from .models import (
    Application, ImportBatch, Organization, Role, User, UserLicense, UserRole,
)
from .permissions import audit
from .resolution import _utc

COLUMNS = ("email", "name", "role", "password_hash", "password_scheme",
           "must_change_password")
SCHEME = "promanage_pbkdf2"
APP_KEY = "projects"
HOME_DOMAIN = seed.ORG["domain"]
MAX_ROWS = 5_000
MAX_NAME = 200                     # users.display_name

# What each Project Management role becomes in Core: (role key, scope type, scope id).
ROLE_MAP = {
    "bu_head": ("global_admin", "platform", None),
    "engineer": ("employee", "application", APP_KEY),
}

TRUE = frozenset({"true", "t", "1", "yes", "y"})
FALSE = frozenset({"false", "f", "0", "no", "n"})
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

COMMAND_LINE_ACTOR = "(command line)"

EXIT_OK, EXIT_FAILED, EXIT_REJECTED = 0, 1, 2


class Rejected(Exception):
    """The file, as a whole, is refused. Nothing was written."""


@dataclass
class Row:
    line: int
    email: str
    name: str
    role: str
    password_hash: str | None          # carried over, or None for a temporary one
    must_change: bool
    outside: bool                      # email outside @mirageaec.com
    # decided by plan()
    create: bool = False
    add_role: bool = False
    add_seat: bool = False
    reason: str = ""

    @property
    def actions(self) -> list[str]:
        if self.create:
            return ["create"]
        return [a for a, on in (("add role", self.add_role), ("add seat", self.add_seat)) if on]


@dataclass
class Plan:
    rows: list[Row] = field(default_factory=list)
    org: Organization | None = None
    actor: User | None = None
    app: Application | None = None
    roles: dict[str, Role] = field(default_factory=dict)

    def count(self, what: str) -> int:
        return sum(1 for r in self.rows if what in r.actions)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.rows if not r.actions)

    @property
    def temporary(self) -> list[Row]:
        return [r for r in self.rows if r.create and r.password_hash is None]

    @property
    def outside(self) -> list[int]:
        return [r.line for r in self.rows if r.outside]


# ------------------------------------------------------------ reading the file
def read(text: str) -> list[Row]:
    """Every row, checked. Raises Rejected — naming row numbers, never an
    email or a hash — if anything in the file is wrong."""
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in COLUMNS if c not in headers]
    unknown = [h for h in headers if h not in COLUMNS]
    if missing or unknown:
        raise Rejected("the header must be exactly: " + ", ".join(COLUMNS)
                       + (f" (missing: {', '.join(missing)})" if missing else "")
                       + (f" (unexpected: {', '.join(unknown)})" if unknown else ""))
    reader.fieldnames = headers

    problems: list[str] = []
    rows: list[Row] = []
    seen: dict[str, int] = {}
    for number, record in enumerate(reader, start=2):        # line 1 is the header
        if len(rows) >= MAX_ROWS:
            raise Rejected(f"more than {MAX_ROWS} rows")
        if None in record:                                     # more fields than headers
            problems.append(f"row {number}: more values than columns")
            continue
        get = lambda name: (record.get(name) or "")            # noqa: E731
        email = get("email").strip().lower()
        name = get("name")
        role = get("role").strip()
        scheme = get("password_scheme").strip()
        hashed = get("password_hash").strip()
        change = get("must_change_password").strip().lower()

        wrong: list[str] = []
        if not _ADDRESS.match(email):
            wrong.append("email is not a valid address")
        elif email in seen:
            wrong.append(f"email repeats row {seen[email]}")
        if not name.strip():
            wrong.append("name is empty")
        elif len(name) > MAX_NAME:
            wrong.append(f"name is longer than {MAX_NAME} characters")
        if role not in ROLE_MAP:
            wrong.append("role is not bu_head or engineer")
        if scheme == SCHEME:
            if not security.is_promanage_hash(hashed):
                wrong.append(f"password_hash is not a valid {SCHEME} hash")
            if change not in TRUE | FALSE:
                wrong.append("must_change_password is not true or false")
        elif scheme == "":
            if hashed:
                wrong.append("password_hash is given without a password_scheme")
        else:
            wrong.append(f"password_scheme is not {SCHEME} or empty")

        if email and email not in seen:
            seen[email] = number
        if wrong:
            problems.append(f"row {number}: " + "; ".join(wrong))
            continue
        rows.append(Row(
            line=number, email=email, name=name, role=role,
            password_hash=hashed if scheme == SCHEME else None,
            must_change=(change in TRUE) if scheme == SCHEME else True,
            outside=not email.endswith("@" + HOME_DOMAIN)))
    if problems:
        raise Rejected("\n".join(problems))
    if not rows:
        raise Rejected("the file has no rows")
    return rows


# ----------------------------------------------------------------- the plan
def _actor(db, org: Organization) -> User:
    holders = [u for u in accounts.global_admin_holders(db) if u.org_id == org.id]
    if not holders:
        raise Rejected("no active Global Admin to act as — run the seed first")
    return min(holders, key=lambda u: (_utc(u.created_at), str(u.id)))


def plan(db, rows: list[Row]) -> Plan:
    """What a commit would do, row by row. Writes nothing."""
    org = db.scalar(select(Organization).where(Organization.domain == HOME_DOMAIN))
    if org is None:
        raise Rejected("the organisation does not exist — run the seed first")
    app = db.scalar(select(Application).where(Application.key == APP_KEY))
    if app is None:
        raise Rejected("Project Management is not registered — run the seed first")
    result = Plan(org=org, actor=_actor(db, org), app=app)
    for key in {role for role, _, _ in ROLE_MAP.values()}:
        role = db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None),
                                            Role.is_custom.is_(False)))
        if role is None:
            raise Rejected(f"the built-in role {key} is missing — run the seed first")
        result.roles[key] = role

    for row in rows:
        role_key, scope_type, scope_id = ROLE_MAP[row.role]
        role = result.roles[role_key]
        found = db.scalars(select(User).where(func.lower(User.email) == row.email)).all()
        here = [u for u in found if u.org_id == org.id]
        if found and not here:
            raise Rejected(f"row {row.line}: an account with that email belongs to "
                           "another organisation")
        if not here:
            row.create = True
            row.reason = ("new account; "
                          + ("password carried over" if row.password_hash
                             else "temporary password")
                          + f"; must change password: {'yes' if row.must_change else 'no'}")
        else:
            person = here[0]
            row.add_role = db.scalar(select(UserRole.id).where(
                UserRole.user_id == person.id, UserRole.role_id == role.id,
                UserRole.scope_type == scope_type,
                (UserRole.scope_id == scope_id) if scope_id else UserRole.scope_id.is_(None),
            )) is None
            row.add_seat = db.scalar(select(UserLicense.id).where(
                UserLicense.user_id == person.id,
                UserLicense.application_id == app.id)) is None
            row.reason = ("account exists and is left as it is"
                          + ("" if row.add_role or row.add_seat
                             else "; it already has the role and the seat"))
        result.rows.append(row)
    return result


# ------------------------------------------------------------- applying it
def _temporary_password() -> str:
    # meets the password rule: upper, lower, digit and symbol guaranteed
    return secrets.token_urlsafe(12) + "Aa1!"


def _write_temporary(path: Path, rows: list[tuple[str, str]]) -> None:
    """Create the file — never overwrite one — readable by its owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["email", "temporary_password"])
        writer.writerows(rows)
        out.flush()
        os.fsync(out.fileno())


def apply(db, ready: Plan, *, temp_out: Path | None, source_name: str) -> dict:
    """Perform exactly what the plan permits, in one transaction."""
    actor, app = ready.actor, ready.app
    passwords: list[tuple[str, str]] = []
    created = roles_added = seats_added = 0
    for row in ready.rows:
        if not row.actions:
            continue
        role_key, scope_type, scope_id = ROLE_MAP[row.role]
        role = ready.roles[role_key]
        if row.create:
            temporary = None if row.password_hash else _temporary_password()
            # create_user runs every rule a new account obeys, and audits it.
            # Given a carried-over hash, it is called with a throwaway
            # password that is replaced by the hash straight after.
            person = accounts.create_user(
                db, actor=actor, email=row.email, display_name=row.name,
                password=temporary or _temporary_password(), status="active",
                commit=False)
            person.display_name = row.name             # exactly as given
            if row.password_hash:
                person.password_hash = row.password_hash
                person.must_change_password = row.must_change
            else:
                passwords.append((row.email, temporary))
                person.must_change_password = True
            db.flush()
            audit(db, actor=actor, action="user.import", target_type="user",
                  target_id=person.id, source="cli", result="success",
                  after={"from": "Project Management",
                         "password": "carried over" if row.password_hash else "temporary",
                         "must_change_password": person.must_change_password},
                  commit=False)
            created += 1
            row.add_role = row.add_seat = True
        else:
            person = db.scalar(select(User).where(User.org_id == ready.org.id,
                                                  func.lower(User.email) == row.email))
        if row.add_role:
            accounts.grant_role(db, actor=actor, target=person, role=role,
                                scope_type=scope_type, scope_id=scope_id, commit=False)
            roles_added += 1
        if row.add_seat:
            accounts.assign_license(db, actor=actor, target=person, app=app, commit=False)
            seats_added += 1

    counts = {"rows": len(ready.rows), "created": created, "roles_added": roles_added,
              "seats_added": seats_added, "skipped": ready.skipped,
              "outside_mirageaec": len(ready.outside),
              "temporary_passwords": len(passwords)}
    db.add(ImportBatch(
        org_id=ready.org.id, filename=source_name[:300], uploaded_by=actor.id,
        records_total=len(ready.rows), records_valid=len(ready.rows), records_failed=0,
        status="warnings" if ready.outside else "success",
        report={"source": "import_users", **counts}))
    audit(db, actor_email=COMMAND_LINE_ACTOR, action="import.commit",
          target_type="import_batch", target_id=source_name[:120], org_id=ready.org.id,
          application_id=app.id, source="cli", result="success", after=counts, commit=False)
    db.flush()

    # The temporary passwords are written before the commit, so a failure to
    # write them can still undo everything; a failed commit removes the file.
    if passwords:
        _write_temporary(temp_out, passwords)
    try:
        db.commit()
    except Exception:
        if passwords and temp_out is not None and temp_out.exists():
            temp_out.unlink()
        raise
    return counts


# ------------------------------------------------------------------ the CLI
def _scrub(message: str, rows: list[Row]) -> str:
    """An error message, with any email from the file taken out."""
    for row in rows:
        message = re.sub(re.escape(row.email), "<email>", message, flags=re.IGNORECASE)
    return message


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.identity.import_users",
        description="Import Project Management's people. A dry run unless --commit.")
    parser.add_argument("--file", required=True, metavar="CSV",
                        help="the CSV to import, or - to read it from stdin")
    parser.add_argument("--commit", action="store_true",
                        help="write the changes; without it nothing is written")
    parser.add_argument("--temp-passwords-out", metavar="PATH", type=Path,
                        help="where to write temporary passwords (created mode 600, "
                             "never overwritten); required when a commit generates any")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    out = sys.stdout

    try:
        if args.file == "-":
            raw, source_name = sys.stdin.buffer.read(), "stdin"
        else:
            raw, source_name = Path(args.file).read_bytes(), Path(args.file).name
        rows = read(raw.decode("utf-8-sig"))
    except Rejected as exc:
        print(f"import_users: the file is rejected; nothing was written.\n{exc}", file=sys.stderr)
        return EXIT_REJECTED
    except (OSError, UnicodeDecodeError) as exc:
        print(f"import_users: cannot read the file ({type(exc).__name__}).", file=sys.stderr)
        return EXIT_FAILED

    with session_factory()() as db:
        try:
            ready = plan(db, rows)
        except Rejected as exc:
            print(f"import_users: refused; nothing was written.\n{exc}", file=sys.stderr)
            return EXIT_REJECTED

        print(f"import_users: {len(ready.rows)} rows; acting as the organisation's first "
              f"Global Admin (account {ready.actor.id}).", file=out)
        for row in ready.rows:
            print(f"  row {row.line}: {', '.join(row.actions) or 'skip'} — {row.reason}",
                  file=out)
        print(f"summary: create {ready.count('create')}, add role "
              f"{sum(1 for r in ready.rows if r.add_role and not r.create)}, add seat "
              f"{sum(1 for r in ready.rows if r.add_seat and not r.create)}, skip "
              f"{ready.skipped}", file=out)
        if ready.outside:
            print(f"warning: {len(ready.outside)} row(s) with an email outside "
                  f"@{HOME_DOMAIN} (rows {', '.join(map(str, ready.outside))}) — allowed.",
                  file=out)

        if not args.commit:
            print("dry run: nothing was written. Add --commit to apply.", file=out)
            return EXIT_OK
        if not any(r.actions for r in ready.rows):
            print("nothing to do: every row already has its account, role and seat.", file=out)
            return EXIT_OK
        temp_out = args.temp_passwords_out
        if ready.temporary:
            if temp_out is None:
                print(f"import_users: {len(ready.temporary)} row(s) need a temporary "
                      "password; give --temp-passwords-out. Nothing was written.",
                      file=sys.stderr)
                return EXIT_REJECTED
            if temp_out.exists():
                print("import_users: the --temp-passwords-out file already exists, and is "
                      "never overwritten. Nothing was written.", file=sys.stderr)
                return EXIT_REJECTED
        try:
            counts = apply(db, ready, temp_out=temp_out, source_name=source_name)
        except Exception as exc:
            db.rollback()
            print(f"import_users: refused, and every change rolled back: "
                  f"{type(exc).__name__}: {_scrub(str(exc), ready.rows)}", file=sys.stderr)
            return EXIT_FAILED

    print(f"committed: {counts['created']} created, {counts['roles_added']} roles added, "
          f"{counts['seats_added']} seats added, {counts['skipped']} skipped.", file=out)
    if counts["temporary_passwords"]:
        print(f"{counts['temporary_passwords']} temporary password(s) written to the "
              "--temp-passwords-out file (mode 600). Hand them out, then delete it.", file=out)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
