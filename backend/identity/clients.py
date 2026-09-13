"""Register an OIDC client, from the command line.

    python -m backend.identity.clients register --application engineering \\
        --name "Engineering Tools" \\
        --redirect-uri http://et.maec.local:8080/auth/callback

    python -m backend.identity.clients list

The secret is printed once and never stored — only its argon2id hash is. It
cannot be shown again: lose it and register a new client. Registration is
audited as `oauth.client.register`.

A command, not a screen, on purpose: registering a client is a deployment
step taken once per application, by whoever is wiring that application to
Core, and it prints a secret that belongs in the client's own configuration.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from . import config  # noqa: F401  (loads .env)
from . import oauth
from .db import session_factory
from .models import Application, OAuthClient
from .permissions import audit

# What an audit row names as the actor for a registration made here. Like
# ANONYMOUS_ACTOR it has no "@", so it cannot collide with a real address.
COMMAND_LINE_ACTOR = "(command line)"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.identity.clients",
        description="Register and list the services Core hands verified identities to.")
    commands = parser.add_subparsers(dest="command", required=True)

    register = commands.add_parser("register", help="register a client and print its secret once")
    register.add_argument("--application", required=True,
                          help="the application key the client serves, e.g. engineering")
    register.add_argument("--name", required=True, help="a name a person recognises")
    register.add_argument("--redirect-uri", dest="redirect_uris", action="append",
                          required=True, metavar="URI",
                          help="an exact callback URI; repeat for more than one")

    commands.add_parser("list", help="list registered clients, without secrets")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    with session_factory()() as db:
        if args.command == "register":
            try:
                client, secret = oauth.register_client(
                    db, application_key=args.application, name=args.name,
                    redirect_uris=args.redirect_uris)
            except oauth.ClientRegistrationError as exc:
                print(f"clients: refused — {exc}", file=sys.stderr)
                return 2
            audit(db, actor_email=COMMAND_LINE_ACTOR, action="oauth.client.register",
                  target_type="oauth_client", target_id=client.client_id,
                  application_id=client.application_id, source="cli", result="success",
                  after={"name": client.name, "redirect_uris": client.redirect_uris})
            print(f"Registered {client.name} for {args.application}.")
            print(f"  client_id:      {client.client_id}")
            print(f"  client_secret:  {secret}")
            for uri in client.redirect_uris:
                print(f"  redirect_uri:   {uri}")
            print("The secret is shown this once and is not stored anywhere. "
                  "Put it in the client's own configuration now.")
            return 0

        rows = db.execute(
            select(OAuthClient, Application.key)
            .join(Application, Application.id == OAuthClient.application_id)
            .order_by(OAuthClient.created_at)).all()
        if not rows:
            print("No clients are registered.")
        for client, application_key in rows:
            used = client.last_used_at.isoformat() if client.last_used_at else "never"
            print(f"{client.client_id}  [{client.status}]  {client.name}  "
                  f"application={application_key}  last used {used}")
            for uri in client.redirect_uris:
                print(f"    {uri}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
