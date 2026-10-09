"""Platform events: audit rows that belong to no organisation.

A failed sign-in for an address no account has, a calling service that could
not prove itself, a client registered from the command line — each was written
with no organisation, and every read filtered by the reader's organisation, so
nobody ever saw them. A password-spraying run against made-up addresses left a
full record that no screen would show.
"""

from __future__ import annotations

import csv
import io

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity.models import AuditLog, Role, User, UserRole
from backend.identity.permissions import audit

from conftest import ENGINEER_EMAIL, ENGINEER_PASSWORD

AUDIT = "/api/admin/audit"
EXPORT = "/api/admin/audit/export"


def _platform_events(app_client, db):
    """One of each kind of event that has no organisation to belong to."""
    app_client.post("/api/auth/login", json={"email": "nobody@spray.example",
                                             "password": "Guess-1234"})
    app_client.post("/oauth/token", data={"grant_type": "authorization_code",
                                          "client_id": "made-up", "client_secret": "x",
                                          "code": "x"})
    audit(db, actor_email="(command line)", action="oauth.client.register",
          target_type="oauth_client", target_id="engineering-probe", source="cli",
          result="success")
    db.expire_all()
    rows = db.scalars(select(AuditLog).where(AuditLog.org_id.is_(None))).all()
    assert {r.action for r in rows} >= {"login.failed", "oauth.token",
                                        "oauth.client.register"}
    return rows


def _business_admin_client(db):
    from backend.main import app
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    lead = db.scalar(select(Role).where(Role.key == "business_admin", Role.org_id.is_(None)))
    db.add(UserRole(user_id=engineer.id, role_id=lead.id,
                    scope_type="application", scope_id="engineering"))
    db.commit()
    client = TestClient(app)
    client.post("/api/auth/login", json={"email": ENGINEER_EMAIL, "password": ENGINEER_PASSWORD})
    return client


def test_a_global_admin_sees_platform_events_when_asking_for_them(admin_client, app_client, db):
    _platform_events(app_client, db)

    usual = admin_client.get(AUDIT, params={"days": 1}).json()
    assert "nobody@spray.example" not in {e["actor_email"] for e in usual["events"]}
    assert usual["platform"] is False and usual["can_see_platform"] is True

    platform = admin_client.get(AUDIT, params={"days": 1, "platform": "true"}).json()
    actors = {e["actor_email"] for e in platform["events"]}
    actions = {e["action"] for e in platform["events"]}
    assert platform["platform"] is True
    assert "nobody@spray.example" in actors
    assert {"login.failed", "oauth.token", "oauth.client.register"} <= actions
    # and nothing from the organisation leaks into the platform view
    assert "admin@mirageaec.com" not in actors


def test_the_filters_still_apply_to_platform_events(admin_client, app_client, db):
    _platform_events(app_client, db)
    r = admin_client.get(AUDIT, params={"platform": "true", "action": "oauth."}).json()
    assert r["events"] and all(e["action"].startswith("oauth.") for e in r["events"])


def test_the_export_carries_platform_events_too(admin_client, app_client, db):
    _platform_events(app_client, db)
    r = admin_client.get(EXPORT, params={"platform": "true"})
    assert r.status_code == 200
    assert "MAEC_audit_platform_" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert "nobody@spray.example" in {row[1] for row in rows[1:]}

    usual = admin_client.get(EXPORT)
    assert "nobody@spray.example" not in usual.content.decode("utf-8-sig")


def test_a_business_admin_is_refused_platform_events(app_client, db, identity):
    _platform_events(app_client, db)
    lead = _business_admin_client(db)
    for path in (AUDIT, EXPORT):
        r = lead.get(path, params={"platform": "true"})
        assert r.status_code == 403, (path, r.status_code)
        assert r.json()["detail"] == "Platform events are visible to Global Admins only."

    # and their ordinary view never contains them either
    usual = lead.get(AUDIT).json()
    assert usual["can_see_platform"] is False
    assert "nobody@spray.example" not in {e["actor_email"] for e in usual["events"]}
