"""python -m backend.identity.import_users — Project Management's people into Core.

Every address, name and hash here is made up in the test. The output is
checked for each of them: the command names rows by number, never by email,
and never prints a hash.
"""

from __future__ import annotations

import csv
import io
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.identity import import_users, security
from backend.identity.models import (
    Application, AuditLog, ImportBatch, Role, Subscription, User, UserLicense, UserRole,
)

from test_promanage_hash import promanage_hash

BU_PASSWORD = "Made-Up-Business-Head-1"
ENG_PASSWORD = "Made-Up-Engineer-Pass-2"
BU_HASH = promanage_hash(BU_PASSWORD, salt=bytes(range(16, 32)))
ENG_HASH = promanage_hash(ENG_PASSWORD, salt=bytes(range(32, 48)))

# (email, name, role, password_hash, password_scheme, must_change_password)
PEOPLE = [
    ("Bu.Head.One@MirageAEC.com ", "Made Up Head", "bu_head", BU_HASH, "promanage_pbkdf2", "false"),
    ("eng.one@mirageaec.com", " Ánna  María van der Berg ", "engineer", ENG_HASH,
     "promanage_pbkdf2", "true"),
    ("eng.two@mirageaec.com", "Second Engineer", "engineer", "", "", ""),
    ("someone@example.org", "Outside Engineer", "engineer", ENG_HASH, "promanage_pbkdf2", "f"),
]
EMAILS = ["bu.head.one@mirageaec.com", "eng.one@mirageaec.com", "eng.two@mirageaec.com",
          "someone@example.org"]
SECRETS = [BU_HASH, ENG_HASH, BU_PASSWORD, ENG_PASSWORD] + EMAILS + [
    "Bu.Head.One@MirageAEC.com"]


def write_csv(path, rows=PEOPLE, header=import_users.COLUMNS):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return path


def run(capsys, *args):
    code = import_users.main([str(a) for a in args])
    out = capsys.readouterr()
    text = out.out + out.err
    for secret in SECRETS:
        assert secret.lower() not in text.lower(), "an email or a hash reached the output"
    return code, text


def counts(db):
    db.expire_all()
    return tuple(db.scalar(select(func.count()).select_from(t))
                 for t in (User, UserRole, UserLicense, AuditLog, ImportBatch))


def person(db, email) -> User | None:
    db.expire_all()
    return db.scalar(select(User).where(User.email == email))


def grants(db, user):
    return {(r.key, g.scope_type, g.scope_id) for g, r in db.execute(
        select(UserRole, Role).join(Role, Role.id == UserRole.role_id)
        .where(UserRole.user_id == user.id)).all()}


def seats(db, user):
    return set(db.scalars(select(Application.key).join(
        UserLicense, UserLicense.application_id == Application.id)
        .where(UserLicense.user_id == user.id)).all())


def sign_in(email, password):
    from backend.main import app
    return TestClient(app).post("/api/auth/login", json={"email": email, "password": password})


# --------------------------------------------------------------- dry run
def test_a_dry_run_writes_nothing(identity, db, tmp_path, capsys):
    before = counts(db)
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv"),
                     "--temp-passwords-out", tmp_path / "temp.csv")
    assert code == 0
    assert counts(db) == before
    assert not (tmp_path / "temp.csv").exists()
    assert "dry run: nothing was written" in text
    for line in (2, 3, 4, 5):
        assert f"row {line}: create" in text
    assert "warning: 1 row(s) with an email outside @mirageaec.com (rows 5)" in text


# ----------------------------------------------------------------- commit
def test_a_commit_creates_people_roles_and_seats(identity, db, tmp_path, capsys):
    temp = tmp_path / "temp.csv"
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
                     "--temp-passwords-out", temp)
    assert code == 0, text
    assert "committed: 4 created" in text

    head = person(db, EMAILS[0])                       # lowercased and trimmed
    assert head is not None and head.display_name == "Made Up Head"
    assert grants(db, head) == {("global_admin", "platform", None)}
    assert seats(db, head) == {"projects"}
    assert head.password_hash == BU_HASH and head.must_change_password is False

    one = person(db, EMAILS[1])
    assert one.display_name == " Ánna  María van der Berg "    # exactly as given, spaces too
    assert grants(db, one) == {("employee", "application", "projects")}
    assert seats(db, one) == {"projects"}
    assert one.must_change_password is True                     # carried over

    two = person(db, EMAILS[2])                       # no hash: a temporary one
    assert two.must_change_password is True
    assert two.password_hash.startswith("$argon2id$")

    outside = person(db, EMAILS[3])
    assert outside is not None and seats(db, outside) == {"projects"}

    [batch] = db.scalars(select(ImportBatch)).all()
    assert batch.status == "warnings" and batch.records_total == 4
    assert batch.report["created"] == 4 and batch.report["outside_mirageaec"] == 1
    assert db.scalar(select(func.count()).select_from(AuditLog)
                     .where(AuditLog.action == "user.import")) == 4
    assert db.scalar(select(func.count()).select_from(AuditLog)
                     .where(AuditLog.action == "import.commit")) == 1


def test_a_second_run_changes_nothing(identity, db, tmp_path, capsys):
    source = write_csv(tmp_path / "in.csv")
    run(capsys, "--file", source, "--commit", "--temp-passwords-out", tmp_path / "t1.csv")
    before = counts(db)
    code, text = run(capsys, "--file", source, "--commit",
                     "--temp-passwords-out", tmp_path / "t2.csv")
    assert code == 0
    assert "nothing to do" in text
    assert counts(db) == before
    assert not (tmp_path / "t2.csv").exists()


def test_an_existing_person_is_never_changed_only_given_what_is_missing(identity, db, tmp_path,
                                                                      capsys):
    from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD
    engineer = person(db, ENGINEER_EMAIL)
    name, password_hash, status = engineer.display_name, engineer.password_hash, engineer.status
    rows = [(ENGINEER_EMAIL.upper(), "A Different Name", "engineer", ENG_HASH,
             "promanage_pbkdf2", "true")]
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv", rows), "--commit")
    assert code == 0, text
    assert "row 2: add role, add seat — account exists and is left as it is" in text
    engineer = person(db, ENGINEER_EMAIL)
    assert (engineer.display_name, engineer.password_hash, engineer.status) == (
        name, password_hash, status)
    assert ("employee", "application", "projects") in grants(db, engineer)
    assert "projects" in seats(db, engineer)
    assert sign_in(ENGINEER_EMAIL, ENGINEER_PASSWORD).status_code == 200    # same password


# ---------------------------------------------------- signing in afterwards
def test_an_imported_person_signs_in_with_their_old_password_and_is_rehashed(identity, db,
                                                                           tmp_path, capsys):
    run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
        "--temp-passwords-out", tmp_path / "temp.csv")
    r = sign_in(EMAILS[0], BU_PASSWORD)
    assert r.status_code == 200 and r.json()["must_change_password"] is False
    assert person(db, EMAILS[0]).password_hash.startswith("$argon2id$")


def test_must_change_password_true_is_sent_to_change_it(identity, db, tmp_path, capsys):
    run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
        "--temp-passwords-out", tmp_path / "temp.csv")
    from backend.main import app
    browser = TestClient(app)
    r = browser.post("/api/auth/login", json={"email": EMAILS[1], "password": ENG_PASSWORD})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    refused = browser.get("/api/admin/whoami")
    assert refused.status_code == 403
    assert refused.json()["detail"] == "Password change required."


def test_temporary_passwords_go_to_their_own_file_and_work(identity, db, tmp_path, capsys):
    temp = tmp_path / "temp.csv"
    run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
        "--temp-passwords-out", temp)
    with open(temp, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert [r["email"] for r in rows] == [EMAILS[2]]
    if sys.platform != "win32":                      # Windows has no POSIX modes
        assert (os.stat(temp).st_mode & 0o777) == 0o600
    r = sign_in(EMAILS[2], rows[0]["temporary_password"])
    assert r.status_code == 200 and r.json()["must_change_password"] is True


def test_a_commit_needing_temporary_passwords_without_a_file_writes_nothing(identity, db,
                                                                          tmp_path, capsys):
    before = counts(db)
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit")
    assert code == 2 and "give --temp-passwords-out" in text
    assert counts(db) == before


def test_the_temporary_password_file_is_never_overwritten(identity, db, tmp_path, capsys):
    temp = tmp_path / "temp.csv"
    temp.write_text("already here\n", encoding="utf-8")
    before = counts(db)
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
                     "--temp-passwords-out", temp)
    assert code == 2 and "never overwritten" in text
    assert temp.read_text(encoding="utf-8") == "already here\n"
    assert counts(db) == before


def test_a_refusal_during_the_commit_rolls_everything_back(identity, db, tmp_path, capsys):
    """No projects subscription: assign_license refuses the first seat, and
    every account created before it in the run is undone."""
    projects = db.scalar(select(Application).where(Application.key == "projects"))
    db.delete(db.scalar(select(Subscription).where(Subscription.application_id == projects.id)))
    db.commit()
    before = counts(db)
    temp = tmp_path / "temp.csv"
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv"), "--commit",
                     "--temp-passwords-out", temp)
    assert code == 1 and "rolled back" in text and "NotSubscribedError" in text
    assert counts(db) == before
    assert not temp.exists()


def test_stdin_is_read_with_file_dash(identity, db, tmp_path, capsys, monkeypatch):
    data = (tmp_path / "in.csv")
    write_csv(data)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data.read_bytes())))
    code, text = run(capsys, "--file", "-")
    assert code == 0 and "row 2: create" in text


# ------------------------------------------------------------ rejections
REJECTIONS = {
    "an invalid email": ([("not-an-address", "X", "engineer", "", "", "")], "row 2: email is not"),
    "an email twice, in different case": (
        [("dup@mirageaec.com", "A", "engineer", "", "", ""),
         ("DUP@mirageaec.com", "B", "engineer", "", "", "")], "row 3: email repeats row 2"),
    "an unknown role": ([("x@mirageaec.com", "X", "admin", "", "", "")], "role is not bu_head"),
    "a Django-style hash": (
        [("x@mirageaec.com", "X", "engineer", "pbkdf2_sha256$100000$" + "a" * 32 + "$" + "b" * 64,
          "promanage_pbkdf2", "false")], "password_hash is not a valid"),
    "an uppercase-hex hash": (
        [("x@mirageaec.com", "X", "engineer", BU_HASH.upper().replace("PBKDF2_SHA256", "pbkdf2_sha256"),
          "promanage_pbkdf2", "false")], "password_hash is not a valid"),
    "an unknown scheme": ([("x@mirageaec.com", "X", "engineer", BU_HASH, "bcrypt", "false")],
                          "password_scheme is not"),
    "a hash without a scheme": ([("x@mirageaec.com", "X", "engineer", BU_HASH, "", "")],
                                "without a password_scheme"),
    "an unclear must_change_password": (
        [("x@mirageaec.com", "X", "engineer", BU_HASH, "promanage_pbkdf2", "maybe")],
        "must_change_password is not"),
    "an empty name": ([("x@mirageaec.com", "  ", "engineer", "", "", "")], "name is empty"),
}


@pytest.mark.parametrize("case", sorted(REJECTIONS))
def test_the_whole_file_is_rejected(identity, db, tmp_path, capsys, case):
    rows, message = REJECTIONS[case]
    good = [("fine@mirageaec.com", "Fine", "engineer", "", "", "")]
    before = counts(db)
    code, text = run(capsys, "--file", write_csv(tmp_path / "in.csv", good + rows
                                                 if "row 2" not in message else rows),
                     "--commit", "--temp-passwords-out", tmp_path / "temp.csv")
    assert code == 2, text
    assert "rejected; nothing was written" in text
    assert message.split(": ", 1)[-1] in text
    assert counts(db) == before


def test_a_missing_column_rejects_the_file(identity, db, tmp_path, capsys):
    code, text = run(capsys, "--file", write_csv(
        tmp_path / "in.csv", [("x@mirageaec.com", "X", "engineer", "", "")],
        header=import_users.COLUMNS[:-1]), "--commit")
    assert code == 2 and "missing: must_change_password" in text
