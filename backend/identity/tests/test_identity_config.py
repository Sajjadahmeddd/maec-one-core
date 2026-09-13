"""Configuration and the fail-closed handlers.

Two small surfaces that carry more weight than their size suggests: what
happens when a secret is missing, and what the service says when the engine
refuses because it broke rather than because it decided.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from backend.identity import config, permissions


# ------------------------------------------------------- SESSION_SECRET
def clear_secret(monkeypatch):
    for name in ("SESSION_SECRET", "MAEC_SECRET_KEY", "RENDER"):
        monkeypatch.delenv(name, raising=False)


def test_a_configured_secret_is_used_as_given(monkeypatch):
    clear_secret(monkeypatch)
    monkeypatch.setenv("SESSION_SECRET", "  a-real-secret  ")
    assert config.session_secret() == "a-real-secret"
    assert config.session_secret_configured() is True


def test_the_old_name_still_works(monkeypatch):
    """Render already generated MAEC_SECRET_KEY; renaming it must not sign
    everyone out on the deploy that renames it."""
    clear_secret(monkeypatch)
    monkeypatch.setenv("MAEC_SECRET_KEY", "the-value-render-made")
    assert config.session_secret() == "the-value-render-made"


def test_locally_a_missing_secret_is_generated(monkeypatch):
    """Frictionless is right here: the cost is being signed out on restart,
    on a machine with one instance and one developer."""
    clear_secret(monkeypatch)
    assert len(config.session_secret()) >= 32
    assert config.session_secret_configured() is False


def test_on_render_a_missing_secret_refuses_to_start(monkeypatch):
    """The same fallback on Render is a bug that hides.

    One instance: everyone is signed out on every restart. More than one:
    each instance generates a *different* secret, requests round-robin, and
    sessions fail to validate on whichever instance did not mint them — so
    users are signed out at random and nothing in the logs explains it.
    Refusing to boot is strictly better than booting into that.
    """
    clear_secret(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(RuntimeError) as raised:
        config.session_secret()
    assert "SESSION_SECRET" in str(raised.value)


# --------------------------------------------------------- located paths
def test_repo_root_is_anchored_to_the_package_not_to_a_count():
    """The third location-derived path in this codebase. `parents[1]` in a
    test is what silently skipped the entire PostgreSQL module during the
    extraction; this one is in production config, where being wrong means
    .env is not found and every setting falls back to its default."""
    import backend.identity as identity
    here = Path(identity.__file__).resolve().parent
    assert config.REPO_ROOT / "backend" / "identity" == here


# ------------------------------------------------------- fail-closed noise
class Boom(Exception):
    pass


def test_a_fail_closed_refusal_is_logged_with_its_type(caplog):
    with caplog.at_level(logging.WARNING, logger="maec.identity"):
        permissions.fail_closed("entitled", Boom("the database went away"))
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "entitled" in message
    assert "Boom" in message
    assert "the database went away" in message


def test_the_log_line_stops_before_the_bound_parameters(caplog):
    """SQLAlchemy puts the statement and its parameters after a newline, and
    those carry whatever was bound — an address, a password hash. Only the
    driver's own first line is written down."""
    exc = Boom(
        "(psycopg.OperationalError) connection refused\n"
        "[SQL: SELECT users.email FROM users WHERE users.email = %(email)s]\n"
        "[parameters: {'email': 'someone@mirageaec.com'}]"
    )
    with caplog.at_level(logging.WARNING, logger="maec.identity"):
        permissions.fail_closed("can", exc)
    message = caplog.records[0].getMessage()
    assert "connection refused" in message
    assert "someone@mirageaec.com" not in message
    assert "parameters" not in message
    assert "SQL:" not in message


def test_every_fail_closed_handler_names_itself():
    """Seven handlers, seven distinct names — a log line that cannot say which
    of them fired is only marginally better than no log line.

    `organization_active` joined in Prompt 5 (OPEN-DECISIONS #14), and
    `resolve` in Prompt 6, when the resolution moved to resolution.py so a
    product can run it without a database. A new handler failing this test
    first is the test doing its job: the set is pinned so each addition is
    named deliberately."""
    import inspect as _inspect

    from backend.identity import guard, resolution

    named = set()
    for module in (permissions, guard, resolution):
        source = Path(module.__file__).read_text(encoding="utf-8")
        for line in source.splitlines():
            if "fail_closed(" in line and "def fail_closed" not in line:
                argument = line.split("fail_closed(", 1)[1]
                if argument.startswith(("'", '"')):
                    named.add(argument[1:argument.index(argument[0], 1)])
    assert named == {"organization_active", "entitled", "holds_business_admin",
                     "is_global_admin", "can", "resolve", "guard.inspect"}
    assert _inspect.signature(permissions.fail_closed).parameters.keys() == {"where", "exc"}
