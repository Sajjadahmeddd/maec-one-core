"""python -m backend.identity.clients — registering a client.

The secret is printed once and never stored. These tests hold the command to
that: the printed secret authenticates, the database holds only its hash, the
audit row names the registration without the secret, and listing clients
never shows one.
"""

from __future__ import annotations

from sqlalchemy import select

from backend.identity import clients, oauth
from backend.identity.models import AuditLog, OAuthClient

REDIRECT = "http://et.maec.local:8080/auth/callback"
REGISTER = ["register", "--application", "engineering",
            "--name", "Engineering Tools", "--redirect-uri", REDIRECT]


def _printed(output: str, label: str) -> str:
    return next(line.split(":", 1)[1].strip()
                for line in output.splitlines() if line.strip().startswith(label + ":"))


def test_register_prints_the_secret_once_and_stores_only_its_hash(db, capsys):
    assert clients.main(REGISTER) == 0
    output = capsys.readouterr().out
    client_id, secret = _printed(output, "client_id"), _printed(output, "client_secret")

    db.expire_all()
    [row] = db.scalars(select(OAuthClient)).all()
    assert row.client_id == client_id
    assert row.redirect_uris == [REDIRECT]
    assert secret not in row.client_secret_hash
    assert oauth.authenticate_client(db, client_id, secret).id == row.id

    [entry] = db.scalars(select(AuditLog).where(
        AuditLog.action == "oauth.client.register")).all()
    assert entry.actor_email == clients.COMMAND_LINE_ACTOR
    assert entry.target_id == client_id
    assert secret not in str(entry.after)


def test_list_names_clients_and_never_prints_a_secret(db, capsys):
    clients.main(REGISTER)
    registered = capsys.readouterr().out
    client_id, secret = _printed(registered, "client_id"), _printed(registered, "client_secret")

    assert clients.main(["list"]) == 0
    listed = capsys.readouterr().out
    assert client_id in listed and REDIRECT in listed
    assert secret not in listed
    assert "argon2" not in listed


def test_an_unsafe_redirect_uri_is_refused_with_its_reason(db, capsys):
    code = clients.main(["register", "--application", "engineering", "--name", "Probe",
                         "--redirect-uri", "http://public.example.com/cb"])
    assert code == 2
    assert "https" in capsys.readouterr().err
    assert db.scalars(select(OAuthClient)).all() == []


def test_an_unknown_application_is_refused(db, capsys):
    code = clients.main(["register", "--application", "nope", "--name", "Probe",
                         "--redirect-uri", REDIRECT])
    assert code == 2
    assert "No application" in capsys.readouterr().err


def test_listing_with_nothing_registered_says_so(db, capsys):
    assert clients.main(["list"]) == 0
    assert "No clients are registered" in capsys.readouterr().out
