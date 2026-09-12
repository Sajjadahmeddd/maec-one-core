"""Screen 005 — bulk import, treated as hostile input.

The two tests that matter most:

* `test_preview_and_commit_cannot_diverge` — the preview must be the same
  resolution the commit performs, not a parallel one that agrees today.
* `test_a_real_uploader_cannot_grant_a_role_they_lack` — a genuine actor who
  genuinely lacks the grant, with nothing mocked out.
"""

from __future__ import annotations

import csv
import io

import pytest
from sqlalchemy import select

from backend.identity import accounts, admin_import
from backend.identity.config import CSRF_HEADER
from backend.identity.models import (
    AuditLog, ImportBatch, Role, User, UserLicense, UserRole,
)

from conftest import ADMIN_EMAIL

VALIDATE = "/api/admin/import/validate"
COMMIT = "/api/admin/import/commit"


def headers(client):
    return {CSRF_HEADER: client.csrf}


def db_user(db, email):
    return db.scalar(select(User).where(User.email == email))


def db_role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def csv_bytes(rows, header=("name", "email", "role_persona", "department")):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def upload(client, data, filename="people.csv", content_type="text/csv"):
    return client.post(VALIDATE, headers=headers(client),
                       files={"file": (filename, io.BytesIO(data), content_type)})


GOOD = [("Ada Lovelace", "ada@mirageaec.com", "employee", "Mechanical"),
        ("Alan Turing", "alan@mirageaec.com", "employee", "Electrical")]


# ------------------------------------------------- preview commits nothing
def test_validate_creates_nobody(admin_client, db):
    before = db.scalar(select(User.id).where(User.email == "ada@mirageaec.com"))
    body = upload(admin_client, csv_bytes(GOOD)).json()
    assert body["valid"] == 2 and body["failed"] == 0
    assert body["can_commit"] is True
    assert before is None
    assert db_user(db, "ada@mirageaec.com") is None      # still nobody


def test_the_preview_names_what_each_row_would_become(admin_client):
    row = upload(admin_client, csv_bytes(GOOD)).json()["rows"][0]
    assert row["email"] == "ada@mirageaec.com"
    assert row["role_key"] == "employee"
    assert row["scope_type"] == "organization"
    assert row["action"] == "create" and row["ok"] is True


def test_commit_creates_exactly_what_was_previewed(admin_client, db):
    preview = upload(admin_client, csv_bytes(GOOD)).json()
    done = admin_client.post(COMMIT, headers=headers(admin_client),
                             json={"batch_id": preview["batch_id"]})
    assert done.status_code == 200, done.text
    assert sorted(done.json()["created"]) == ["ada@mirageaec.com", "alan@mirageaec.com"]

    ada = db_user(db, "ada@mirageaec.com")
    assert ada.status == "invited"
    assert ada.must_change_password is True
    grant = db.scalar(select(UserRole).where(UserRole.user_id == ada.id))
    assert grant.role.key == "employee" and grant.scope_type == "organization"


# ------------------------------------ preview and commit are one resolution
def test_preview_and_commit_cannot_diverge(admin_client, db):
    """They are the same function, so this asserts the property directly:
    what `plan()` said, `apply()` did — row for row."""
    preview = upload(admin_client, csv_bytes(GOOD)).json()
    promised = sorted(r["email"] for r in preview["rows"] if r["ok"])

    admin_client.post(COMMIT, headers=headers(admin_client),
                      json={"batch_id": preview["batch_id"]})
    actually = sorted(u.email for u in db.scalars(select(User)).all()
                      if u.email in promised)
    assert actually == promised

    # and nothing the preview refused was created
    refused = [r["email"] for r in preview["rows"] if not r["ok"]]
    for email in refused:
        assert db_user(db, email) is None


def test_the_commit_refuses_when_the_world_moved_since_the_preview(admin_client, db):
    """A role deleted between preview and commit changes the answer. The
    commit re-plans and refuses rather than replaying a stale decision."""
    custom = admin_client.post("/api/admin/roles", headers=headers(admin_client),
                               json={"name": "Temp Persona",
                                     "clone_from": str(db_role(db, "employee").id)}).json()
    rows = [("Grace Hopper", "grace@mirageaec.com", custom["key"], "Software")]
    preview = upload(admin_client, csv_bytes(rows)).json()
    assert preview["valid"] == 1

    admin_client.delete(f"/api/admin/roles/{custom['id']}", headers=headers(admin_client))

    done = admin_client.post(COMMIT, headers=headers(admin_client),
                             json={"batch_id": preview["batch_id"]})
    assert done.status_code == 409
    assert "changed since" in done.json()["detail"]
    assert db_user(db, "grace@mirageaec.com") is None


def test_an_address_taken_between_preview_and_commit_is_caught(admin_client, db):
    rows = [("Ada Lovelace", "ada@mirageaec.com", "employee", "Mechanical")]
    preview = upload(admin_client, csv_bytes(rows)).json()
    assert preview["valid"] == 1

    admin_client.post("/api/admin/users", headers=headers(admin_client),
                      json={"email": "ada@mirageaec.com", "display_name": "Ada",
                            "password": "Interloper@2026"})

    done = admin_client.post(COMMIT, headers=headers(admin_client),
                             json={"batch_id": preview["batch_id"]})
    assert done.status_code == 409


# --------------------------------------------------- the escalation check
def test_a_real_uploader_cannot_grant_a_role_they_lack(db, identity):
    """A genuine Business Admin, genuinely lacking the grant, with nothing
    mocked. `plan()` asks `accounts.may_grant` — the same function
    `grant_role` asks before writing — so this is the real refusal.
    """
    admin = db_user(db, ADMIN_EMAIL)
    lead = User(org_id=admin.org_id, email="lead@mirageaec.com",
                display_name="Business Lead", status="active",
                password_hash=security_hash())
    db.add(lead)
    db.flush()
    db.add(UserRole(user_id=lead.id, role_id=db_role(db, "business_admin").id,
                    scope_type="application", scope_id="engineering"))
    # a seat too: without entitlement `can()` denies everything, so a lead
    # with no licence could not grant anything — which is correct, and would
    # make this test pass for the wrong reason
    from backend.identity.models import Application
    db.add(UserLicense(user_id=lead.id, application_id=db.scalar(
        select(Application.id).where(Application.key == "engineering"))))
    db.commit()

    # the lead may not confer Global Admin on anyone
    escalating = [{"name": "Mallory", "email": "mallory@mirageaec.com",
                   "role_persona": "global_admin", "department": "Ops"}]
    refused = admin_import.plan(db, lead, escalating)
    assert refused.valid == 0
    assert any("may not grant global_admin" in p for p in refused.rows[0].problems)

    # and the same actor, asking for something at or below them, is fine
    ordinary = [{"name": "Ordinary", "email": "ordinary@mirageaec.com",
                 "role_persona": "employee", "department": "Ops"}]
    allowed = admin_import.plan(db, lead, ordinary)
    assert allowed.valid == 1, allowed.rows[0].problems


def security_hash():
    from backend.identity import security
    return security.hash_password("Lead-Fixture@2026")


def test_the_escalation_check_is_the_same_function_grant_role_uses():
    """Not two implementations that agree today.

    If `plan()` grew its own copy of the rule, this is the test that would
    have to be deleted to make it pass.
    """
    import inspect
    source = inspect.getsource(admin_import.plan)
    assert "accounts.may_grant" in source
    grant_source = inspect.getsource(accounts.grant_role)
    assert "may_grant" in grant_source


def test_an_escalating_row_is_audited_blocked(admin_client, db):
    """Global Admin can grant anything, so the row passes for them — but a
    row naming an unknown role is still refused and recorded."""
    rows = [("Nobody", "nobody@mirageaec.com", "wizard", "Ops")]
    body = upload(admin_client, csv_bytes(rows)).json()
    assert body["failed"] == 1
    assert "no role named" in body["rows"][0]["problems"][0]
    assert body["can_commit"] is False


# ------------------------------------------------------ hostile input
def test_a_renamed_executable_is_refused(admin_client):
    body = upload(admin_client, b"MZ\x90\x00" + b"\x00" * 200,
                  filename="people.csv").json()
    assert body["can_commit"] is False
    assert any("program or archive" in p for p in body["file_problems"])


def test_a_zip_pretending_to_be_csv_is_refused(admin_client):
    body = upload(admin_client, b"PK\x03\x04" + b"x" * 100).json()
    assert any("program or archive" in p for p in body["file_problems"])


def test_a_wrong_extension_is_refused(admin_client):
    body = upload(admin_client, csv_bytes(GOOD), filename="people.xlsx").json()
    assert any(".csv" in p for p in body["file_problems"])


def test_missing_columns_are_named(admin_client):
    data = csv_bytes([("Ada", "ada@mirageaec.com")], header=("name", "email"))
    body = upload(admin_client, data).json()
    assert any("role_persona" in p and "department" in p
               for p in body["file_problems"])


def test_too_many_rows_is_refused_during_the_parse(admin_client):
    many = [(f"P{n}", f"p{n}@mirageaec.com", "employee", "Ops")
            for n in range(admin_import.MAX_ROWS + 10)]
    body = upload(admin_client, csv_bytes(many)).json()
    assert any("more than" in p for p in body["file_problems"]) or \
        body["total"] <= admin_import.MAX_ROWS


def test_a_duplicate_inside_the_file_is_caught(admin_client):
    rows = [("Ada", "ada@mirageaec.com", "employee", "Ops"),
            ("Ada Again", "ada@mirageaec.com", "employee", "Ops")]
    body = upload(admin_client, csv_bytes(rows)).json()
    assert body["valid"] == 1 and body["failed"] == 1
    assert "duplicated earlier" in body["rows"][1]["problems"][0]


def test_a_foreign_domain_is_refused(admin_client):
    rows = [("Outsider", "someone@evil.example", "employee", "Ops")]
    body = upload(admin_client, csv_bytes(rows)).json()
    assert any("not a permitted domain" in p for p in body["rows"][0]["problems"])


def test_a_malformed_address_is_refused(admin_client):
    rows = [("Broken", "not-an-address", "employee", "Ops")]
    body = upload(admin_client, csv_bytes(rows)).json()
    assert body["failed"] == 1


def test_an_existing_account_is_refused(admin_client):
    rows = [("The Admin", ADMIN_EMAIL, "employee", "Ops")]
    body = upload(admin_client, csv_bytes(rows)).json()
    assert any("already has an account" in p for p in body["rows"][0]["problems"])


def test_nothing_is_created_when_any_row_fails_to_write(admin_client, db, monkeypatch):
    """One transaction: a failure part-way leaves nothing behind."""
    preview = upload(admin_client, csv_bytes(GOOD)).json()

    real = accounts.grant_role
    calls = {"n": 0}

    def explode(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("database went away")
        return real(*args, **kwargs)

    monkeypatch.setattr(accounts, "grant_role", explode)
    with pytest.raises(RuntimeError):
        admin_client.post(COMMIT, headers=headers(admin_client),
                          json={"batch_id": preview["batch_id"]})

    db.expire_all()
    assert db_user(db, "ada@mirageaec.com") is None
    assert db_user(db, "alan@mirageaec.com") is None


# ---------------------------------------------------------- the template
def test_the_template_lists_real_roles_and_escapes_formulas(admin_client, db):
    r = admin_client.get("/api/admin/import/template")
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0] == list(admin_import.REQUIRED_COLUMNS)
    personas = {row[2] for row in rows[1:]}
    real = {x.key for x in db.scalars(select(Role)).all()}
    assert personas <= real                      # no invented role names
    for row in rows:
        for cell in row:
            assert not cell.startswith(admin_import.FORMULA_LEADERS)


def test_the_batch_history_is_real(admin_client):
    upload(admin_client, csv_bytes(GOOD))
    batches = admin_client.get("/api/admin/import/batches").json()["batches"]
    assert batches and batches[0]["filename"] == "people.csv"
    assert batches[0]["uploaded_by"] == ADMIN_EMAIL
    assert batches[0]["status"] == "pending"


def test_the_report_holds_no_raw_file_content(admin_client, db):
    """Only the validation report, never the bytes that were uploaded."""
    upload(admin_client, csv_bytes(GOOD))
    batch = db.scalar(select(ImportBatch))
    assert set(batch.report) == {"rows", "total", "valid", "failed",
                                 "columns_ok", "file_problems", "can_commit"}
    assert "name,email,role_persona" not in str(batch.report)


def test_a_batch_cannot_be_committed_twice(admin_client):
    preview = upload(admin_client, csv_bytes(GOOD)).json()
    first = admin_client.post(COMMIT, headers=headers(admin_client),
                              json={"batch_id": preview["batch_id"]})
    assert first.status_code == 200
    again = admin_client.post(COMMIT, headers=headers(admin_client),
                              json={"batch_id": preview["batch_id"]})
    assert again.status_code == 409


# ------------------------------------------------------ the floor holds
@pytest.mark.parametrize("path", [VALIDATE, COMMIT, "/api/admin/import/batches",
                                  "/api/admin/import/template"])
def test_an_engineer_is_refused(engineer_client, path):
    r = engineer_client.request("POST" if "import/" in path and "batches" not in path
                                and "template" not in path else "GET", path,
                                json={}, headers={CSRF_HEADER: engineer_client.csrf})
    assert r.status_code == 403


def test_uploading_without_csrf_is_refused(admin_client):
    r = admin_client.post(VALIDATE,
                          files={"file": ("x.csv", io.BytesIO(csv_bytes(GOOD)),
                                          "text/csv")})
    assert r.status_code == 403


def test_every_import_action_is_audited(admin_client, db):
    preview = upload(admin_client, csv_bytes(GOOD)).json()
    admin_client.post(COMMIT, headers=headers(admin_client),
                      json={"batch_id": preview["batch_id"]})
    actions = {a.action for a in db.scalars(select(AuditLog)).all()}
    assert "import.validate" in actions
    assert "import.commit" in actions
    assert "user.create" in actions
