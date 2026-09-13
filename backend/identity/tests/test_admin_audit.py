"""Screen 004 — the audit log, its scoping, and the export.

Two things get the most attention here: that a Business Admin sees only
their own applications' events even when calling the endpoint directly, and
that the CSV cannot carry a formula into someone's spreadsheet.
"""

from __future__ import annotations

import csv
import io

import pytest
from sqlalchemy import select

from backend.identity.config import CSRF_HEADER
from backend.identity.models import Application, AuditLog, Role, User, UserRole
from backend.identity.permissions import ANONYMOUS_ACTOR, audit

from conftest import ADMIN_EMAIL

AUDIT = "/api/admin/audit"


def headers(client):
    return {CSRF_HEADER: client.csrf}


def db_user(db, email):
    return db.scalar(select(User).where(User.email == email))


def db_role(db, key):
    return db.scalar(select(Role).where(Role.key == key, Role.org_id.is_(None)))


def app_id(db, key="engineering"):
    return db.scalar(select(Application.id).where(Application.key == key))


# ------------------------------------------------------------- reading
def test_the_log_shows_real_events_newest_first(admin_client, db):
    body = admin_client.get(AUDIT).json()
    assert body["total"] > 0                     # signing in wrote rows
    actions = [e["action"] for e in body["events"]]
    assert "login.success" in actions
    stamps = [e["created_at"] for e in body["events"]]
    assert stamps == sorted(stamps, reverse=True)
    assert body["scoped"] is False               # a Global Admin is not scoped


def test_the_actor_is_the_email_not_an_id(admin_client):
    row = next(e for e in admin_client.get(AUDIT).json()["events"]
               if e["action"] == "login.success")
    assert row["actor_email"] == ADMIN_EMAIL
    assert row["anonymous"] is False


def test_an_event_with_nobody_to_name_is_flagged(admin_client, db):
    audit(db, action="login.failed", result="warning", actor_email=None,
          org_id=db_user(db, ADMIN_EMAIL).org_id)
    row = next(e for e in admin_client.get(AUDIT).json()["events"]
               if e["actor_email"] == ANONYMOUS_ACTOR)
    assert row["anonymous"] is True              # the screen renders this as —


def test_the_list_is_paged_and_filtered_in_the_database(admin_client):
    first = admin_client.get(AUDIT, params={"page_size": 1}).json()
    assert len(first["events"]) == 1
    assert first["pages"] == first["total"]

    only = admin_client.get(AUDIT, params={"action": "login."}).json()
    assert only["total"] >= 1
    assert all(e["action"].startswith("login.") for e in only["events"])


def test_filtering_by_result(admin_client, db):
    admin_client.post("/api/admin/roles", headers=headers(admin_client),
                      json={"name": "Blocked Probe"})
    # a blocked row: a tool rule that would grant what the role denies
    admin_client.put("/api/admin/tool-rules", headers=headers(admin_client),
                     json={"changes": [{"application_key": "engineering",
                                        "module_key": "hapext",
                                        "role_id": str(db_role(db, "employee").id),
                                        "access_level": "full"}]})
    blocked = admin_client.get(AUDIT, params={"result": "blocked"}).json()
    assert blocked["total"] >= 1
    assert all(e["result"] == "blocked" for e in blocked["events"])


def test_an_unknown_result_is_refused(admin_client):
    assert admin_client.get(AUDIT, params={"result": "exploded"}).status_code == 422


def test_the_page_size_is_capped(admin_client):
    assert admin_client.get(AUDIT, params={"page_size": 100000}).status_code == 422


def test_searching_by_actor(admin_client):
    hit = admin_client.get(AUDIT, params={"q": "admin@"}).json()
    assert hit["total"] >= 1
    assert all("admin@" in e["actor_email"] for e in hit["events"])


# --------------------------------------------------------------- stats
def test_the_cards_are_real_counts(admin_client, db):
    stats = admin_client.get(f"{AUDIT}/stats").json()
    assert stats["window_days"] == 30
    assert stats["events"] > 0
    assert stats["sign_ins"] >= 1

    total_now = stats["events"]
    audit(db, action="role.grant", result="success",
          actor=db_user(db, ADMIN_EMAIL))
    after = admin_client.get(f"{AUDIT}/stats").json()
    assert after["events"] == total_now + 1
    assert after["role_changes"] >= 1


def test_an_empty_log_reports_zero_not_a_placeholder(admin_client, db):
    """Day one is genuinely empty, and that is the correct answer."""
    db.execute(select(AuditLog))            # ensure the table exists
    from sqlalchemy import delete
    # SQLite has no append-only trigger, so the suite can empty it here; a
    # real database would refuse, which is the point of the trigger.
    db.execute(delete(AuditLog))
    db.commit()
    stats = admin_client.get(f"{AUDIT}/stats").json()
    # the request itself writes nothing on a successful read
    assert stats["events"] == 0
    assert stats["role_changes"] == 0
    assert stats["security_alerts"] == 0


# ------------------------------------------------------------ controls
def test_the_controls_strip_reads_the_real_configuration(admin_client):
    controls = {c["key"]: c for c in
                admin_client.get(f"{AUDIT}/controls").json()["controls"]}
    assert controls["hashing"]["on"] is True
    assert "argon2id" in controls["hashing"]["label"]
    assert controls["lockout"]["on"] is True
    assert "5 failures" in controls["lockout"]["label"]
    # every claim says where it is enforced, so it can be checked
    assert all(c["where"] for c in controls.values())


def test_the_rate_limit_card_reflects_whether_it_is_actually_on(admin_client):
    from backend.identity import router_auth
    was = router_auth.limiter.enabled
    try:
        router_auth.limiter.enabled = False
        off = {c["key"]: c for c in
               admin_client.get(f"{AUDIT}/controls").json()["controls"]}
        assert off["rate_limit"]["on"] is False
        router_auth.limiter.enabled = True
        on = {c["key"]: c for c in
              admin_client.get(f"{AUDIT}/controls").json()["controls"]}
        assert on["rate_limit"]["on"] is True
    finally:
        router_auth.limiter.enabled = was


def test_the_append_only_card_is_honest_on_sqlite(admin_client):
    """The trigger is PostgreSQL only. The card must say so rather than
    claim a protection this database does not have."""
    controls = {c["key"]: c for c in
                admin_client.get(f"{AUDIT}/controls").json()["controls"]}
    card = controls["append_only"]
    assert card["on"] is False
    assert "PostgreSQL only" in card["note"]


# -------------------------------------------------------------- export
def test_the_export_is_csv_with_the_filtered_rows(admin_client):
    r = admin_client.get(f"{AUDIT}/export", params={"action": "login."})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][:3] == ["Timestamp", "Actor", "Action"]
    assert all(row[2].startswith("login.") for row in rows[1:])
    assert int(r.headers["X-Audit-Rows"]) == len(rows) - 1


@pytest.mark.parametrize("hostile", [
    "=cmd|'/c calc'!A1",
    "+1+1",
    "-2+3",
    "@SUM(A1:A9)",
    "\t=1+1",
])
def test_the_export_defuses_a_formula_in_any_cell(admin_client, db, hostile):
    """An audit row carries strings a stranger chose. The export is exactly
    the file an administrator opens without thinking."""
    audit(db, action="probe.formula", result="success", actor_email=hostile,
          target_id=hostile, org_id=db_user(db, ADMIN_EMAIL).org_id)

    r = admin_client.get(f"{AUDIT}/export", params={"action": "probe.formula"})
    text = r.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    row = next(x for x in rows[1:] if "probe.formula" in x)

    # the rule, stated once and without exceptions: after escaping, no cell
    # begins with anything a spreadsheet reads as a formula
    from backend.identity.admin_audit import FORMULA_LEADERS
    for cell in row:
        assert not cell.startswith(FORMULA_LEADERS), f"unescaped: {cell!r}"

    # and the value is preserved, merely made inert
    assert any(c == "'" + hostile for c in row), row


def test_a_harmless_cell_is_left_alone(admin_client, db):
    audit(db, action="probe.plain", result="success",
          actor_email="plain@mirageaec.com",
          org_id=db_user(db, ADMIN_EMAIL).org_id)
    r = admin_client.get(f"{AUDIT}/export", params={"action": "probe.plain"})
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    row = next(x for x in rows[1:] if "probe.plain" in x)
    assert "plain@mirageaec.com" in row          # no stray apostrophe


# --------------------------------------------------------------- scoping
@pytest.fixture
def business_admin(db, identity):
    """Someone who leads Engineering Tools and nothing else."""
    from backend.identity import security
    from backend.identity.models import UserLicense
    admin = db_user(db, ADMIN_EMAIL)
    lead = User(org_id=admin.org_id, email="lead@mirageaec.com",
                display_name="Business Lead", status="active",
                password_hash=security.hash_password("Lead@2026"))
    db.add(lead)
    db.flush()
    db.add(UserRole(user_id=lead.id, role_id=db_role(db, "business_admin").id,
                    scope_type="application", scope_id="engineering"))
    db.add(UserLicense(user_id=lead.id, application_id=app_id(db)))
    db.commit()
    return lead


@pytest.fixture
def lead_client(business_admin, identity):
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)
    body = client.post("/api/auth/login",
                       json={"email": "lead@mirageaec.com", "password": "Lead@2026"})
    assert body.status_code == 200, body.text
    client.csrf = body.json()["csrf_token"]
    return client


def test_a_business_admin_sees_only_their_applications_events(lead_client, db):
    engineering = app_id(db)
    timesheet = app_id(db, "timesheet")
    org = db_user(db, ADMIN_EMAIL).org_id
    audit(db, action="probe.engineering", result="success",
          actor_email="x@mirageaec.com", org_id=org, application_id=engineering)
    audit(db, action="probe.timesheet", result="success",
          actor_email="x@mirageaec.com", org_id=org, application_id=timesheet)
    audit(db, action="probe.platform", result="success",
          actor_email="x@mirageaec.com", org_id=org)      # no application

    body = lead_client.get(AUDIT).json()
    assert body["scoped"] is True
    actions = {e["action"] for e in body["events"]}
    assert "probe.engineering" in actions
    assert "probe.timesheet" not in actions      # not their application
    assert "probe.platform" not in actions       # not about one application


def test_the_scope_holds_for_the_export_too(lead_client, db):
    org = db_user(db, ADMIN_EMAIL).org_id
    audit(db, action="probe.timesheet", result="success",
          actor_email="x@mirageaec.com", org_id=org,
          application_id=app_id(db, "timesheet"))
    r = lead_client.get(f"{AUDIT}/export")
    assert "probe.timesheet" not in r.content.decode("utf-8-sig")


def test_the_scope_holds_for_the_stats_too(lead_client, admin_client, db):
    mine = lead_client.get(f"{AUDIT}/stats").json()["events"]
    everything = admin_client.get(f"{AUDIT}/stats").json()["events"]
    assert mine < everything


def test_a_business_admin_cannot_reach_any_other_admin_route(lead_client):
    for path in ("/api/admin/users", "/api/admin/roles", "/api/admin/tool-rules",
                 "/api/admin/whoami"):
        assert lead_client.get(path).status_code == 403, path


def test_a_business_admin_cannot_write_anywhere_under_admin(lead_client):
    r = lead_client.post("/api/admin/roles",
                         headers={CSRF_HEADER: lead_client.csrf},
                         json={"name": "Nope"})
    assert r.status_code == 403


# ----------------------------------- a suspended organisation (OPEN-DECISIONS #14)
def _suspend_the_organisation(db):
    org = db_user(db, ADMIN_EMAIL).org
    org.status = "suspended"
    db.commit()


def test_a_suspended_organisations_lead_loses_the_audit_reads(lead_client, db):
    """A Business Admin's reach is tenant-scoped, and the tenant is suspended."""
    assert lead_client.get(AUDIT).status_code == 200
    _suspend_the_organisation(db)
    for path in (AUDIT, f"{AUDIT}/stats", f"{AUDIT}/export", f"{AUDIT}/controls"):
        assert lead_client.get(path).status_code == 403, path


def test_the_endpoints_own_check_refuses_a_suspended_lead(business_admin, db):
    """The second lock, without the guard in front of it: the refusal above
    must not depend on the door alone."""
    from fastapi import HTTPException
    from backend.identity.admin_audit import require_audit_reader
    _suspend_the_organisation(db)
    with pytest.raises(HTTPException) as refused:
        require_audit_reader(None, business_admin, db)
    assert refused.value.status_code == 403


def test_a_suspended_organisations_global_admin_keeps_the_panel(admin_client, db):
    """Global Admin is a platform role, and the person who would restore the
    account. Locking them out of the only place that can do it is the
    foot-gun. They lose the applications, like everyone in the organisation."""
    _suspend_the_organisation(db)
    assert admin_client.get("/api/admin/whoami").status_code == 200
    assert admin_client.get(AUDIT).status_code == 200
    me = admin_client.get("/api/auth/me").json()
    assert not any(app["entitled"] for app in me["apps"])
    assert me["organization_suspended"] is True


def test_a_suspended_organisations_members_still_sign_in_to_an_explanation(
        app_client, engineer_credentials, db):
    """Refusing sign-in would mean the generic failure — "incorrect password"
    — for someone whose organisation's access lapsed. Signed in, the launcher
    can say why it is empty."""
    _suspend_the_organisation(db)
    r = app_client.post("/api/auth/login", json=engineer_credentials)
    assert r.status_code == 200
    body = r.json()
    assert not any(app["entitled"] for app in body["apps"])
    assert body["organization_suspended"] is True


# ---------------------------------------------------- the floor holds
def test_an_ordinary_engineer_is_refused(engineer_client):
    for path in (AUDIT, f"{AUDIT}/stats", f"{AUDIT}/export", f"{AUDIT}/controls"):
        assert engineer_client.get(path).status_code == 403, path


def test_a_stranger_is_refused(app_client):
    for path in (AUDIT, f"{AUDIT}/stats", f"{AUDIT}/export"):
        assert app_client.get(path).status_code == 401, path


def test_there_is_no_write_endpoint_on_audit(admin_client):
    """The table is append-only; the API must not offer a way round that."""
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        r = admin_client.request(method, AUDIT, json={},
                                 headers=headers(admin_client))
        assert r.status_code in (404, 405), f"{method} {AUDIT} -> {r.status_code}"


def test_the_routes_are_read_only_in_the_source():
    """A grep, so adding a write route here fails the suite rather than
    quietly appearing."""
    from pathlib import Path
    from backend.identity import admin_audit as _module
    source = Path(_module.__file__).resolve()
    text = source.read_text(encoding="utf-8")
    for verb in ("@router.post", "@router.put", "@router.patch", "@router.delete"):
        assert verb not in text, f"{verb} must never appear in admin_audit.py"


# ------------------------------------------- the guard exception, precisely
def test_the_guard_itself_refuses_non_get_not_just_the_absence_of_routes():
    """Whether a Business Admin can write under /api/admin/audit must not
    depend on no write route happening to exist there."""
    from backend.identity.guard import may_read_audit
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert may_read_audit("/api/admin/audit", method) is False, method
    assert may_read_audit("/api/admin/audit", "GET") is True


def test_a_future_sub_path_does_not_inherit_the_exception():
    """The exception is an exact list, not a prefix. Anything mounted under
    /api/admin/audit/ later has to be added here deliberately."""
    from backend.identity.guard import may_read_audit
    for path in ("/api/admin/audit/retention",
                 "/api/admin/audit/purge",
                 "/api/admin/audit/actor/someone",
                 "/api/admin/audit/../users"):
        assert may_read_audit(path, "GET") is False, path


def test_the_exception_covers_exactly_the_four_audit_reads():
    from backend.identity.guard import ADMIN_READER_PATHS
    assert ADMIN_READER_PATHS == {
        "/api/admin/audit", "/api/admin/audit/stats",
        "/api/admin/audit/controls", "/api/admin/audit/export"}


def test_a_business_admin_cannot_post_to_the_audit_path(lead_client):
    """Through the real stack, not just the predicate."""
    r = lead_client.post(AUDIT, headers={CSRF_HEADER: lead_client.csrf}, json={})
    assert r.status_code == 403


# --------------------------------- export shares the list's scope filter
def test_list_stats_and_export_all_use_one_scope_filter():
    """Export is where scoped data leaves the system as a file. If it built
    its own query, that is the preview/commit divergence of screen 005 in a
    more sensitive place — so assert the shared call directly."""
    import inspect

    from backend.identity import admin_audit
    for fn in (admin_audit.list_audit, admin_audit.audit_stats,
               admin_audit.export_audit):
        assert "_filtered(" in inspect.getsource(fn), fn.__name__


def test_the_export_is_bounded(admin_client):
    from backend.identity import admin_audit
    assert admin_audit.EXPORT_MAX == 50_000
    assert "limit(EXPORT_MAX)" in __import__("inspect").getsource(
        admin_audit.export_audit)


# ----------------------------------- no card divides by an unscoped total
def test_no_stat_card_is_a_proportion(admin_client):
    """A percentage needs a denominator, and an unscoped denominator would
    tell a Business Admin how much activity exists in applications they
    cannot see. Every card is a plain count of rows they may read."""
    import inspect

    from backend.identity import admin_audit
    source = inspect.getsource(admin_audit.audit_stats)
    assert "/" not in source.replace("role.%", "").replace("license.%", "") \
        .replace("tool_rule.%", "").replace("/audit/stats", ""), \
        "audit_stats contains arithmetic division"

    body = admin_client.get(f"{AUDIT}/stats").json()
    for key, value in body.items():
        assert isinstance(value, int), f"{key} is not a plain count"
