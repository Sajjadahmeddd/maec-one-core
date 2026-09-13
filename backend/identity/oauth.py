"""The rules of the authorization-code flow, kept out of the router.

The router translates HTTP to intent and back; the rules — what a client is,
what makes a redirect target safe, how a code is minted, consumed and swept,
how a calling service proves who it is — live here, the way accounts.py keeps
the rules for people out of admin_users.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from . import security
from .models import Application, AuthorizationCode, OAuthClient, User
from .resolution import _utc, now

# A code lives thirty seconds. It only has to survive one redirect and one
# server-to-server call; anything longer is time for a leaked code to be used.
CODE_TTL = timedelta(seconds=30)

# Consumed and expired codes are kept this long after expiry, for the audit
# trail and for diagnosing a failed exchange, then swept when a new code is
# written. No scheduler: every mint sweeps.
CODE_KEEP = timedelta(minutes=10)

# 32 bytes of randomness: 256 bits, 43 url-safe characters.
CODE_BYTES = 32
SECRET_BYTES = 32

# Plain http is accepted only for hosts that cannot be reached from outside a
# developer's machine. Everything else must be https.
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
LOCAL_SUFFIX = ".local"


class ClientRegistrationError(ValueError):
    """Refused: this client could not be registered as described."""


# ------------------------------------------------------------------ clients
def find_client(db: Session, client_id: str) -> OAuthClient | None:
    if not client_id:
        return None
    return db.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))


def active_client(db: Session, client_id: str) -> OAuthClient | None:
    client = find_client(db, client_id)
    return client if client is not None and client.status == "active" else None


def redirect_uri_registered(client: OAuthClient, redirect_uri: str) -> bool:
    """Is this exactly one of the client's registered redirect URIs?

    Whole-string equality and nothing looser: no prefix match, no allowance
    for a trailing slash or an extra path segment, no case folding. The
    classic OIDC open redirect is a check that is almost exact — a prefix
    match lets `https://app.example/callback.evil.example` through.
    """
    registered = client.redirect_uris if isinstance(client.redirect_uris, list) else []
    return bool(redirect_uri) and any(
        isinstance(uri, str) and uri == redirect_uri for uri in registered)


def _check_redirect_uri(uri: str) -> str:
    parts = urlsplit(uri)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ClientRegistrationError(f"{uri!r} is not an absolute http(s) URI.")
    if parts.fragment or "#" in uri:
        raise ClientRegistrationError(f"{uri!r} has a fragment; a redirect URI may not.")
    if "*" in uri:
        raise ClientRegistrationError(f"{uri!r} has a wildcard; redirect URIs are exact.")
    host = parts.hostname.lower()
    local = host in LOCAL_HOSTS or host.endswith(LOCAL_SUFFIX)
    if parts.scheme == "http" and not local:
        raise ClientRegistrationError(
            f"{uri!r} is plain http on a public host. Use https; http is accepted only "
            "for localhost, 127.0.0.1 and .local development hosts.")
    return uri


def register_client(db: Session, *, application_key: str, name: str,
                    redirect_uris: list[str]) -> tuple[OAuthClient, str]:
    """Register a client and return it with its secret — the only time the
    secret exists outside the caller. Only its argon2id hash is stored."""
    app = db.scalar(select(Application).where(Application.key == application_key))
    if app is None:
        raise ClientRegistrationError(f"No application {application_key!r}.")
    if not name.strip():
        raise ClientRegistrationError("A client needs a name.")
    uris = [_check_redirect_uri(uri.strip()) for uri in redirect_uris if uri.strip()]
    if not uris:
        raise ClientRegistrationError("A client needs at least one redirect URI.")

    secret = secrets.token_urlsafe(SECRET_BYTES)
    client = OAuthClient(
        client_id=f"{application_key}-{secrets.token_hex(8)}",
        client_secret_hash=security.hash_password(secret),
        application_id=app.id, name=name.strip(), redirect_uris=uris)
    db.add(client)
    db.commit()
    return client, secret


def authenticate_client(db: Session, client_id: str | None,
                        client_secret: str | None) -> OAuthClient | None:
    """The calling service, if it proved who it is. Constant work.

    The secret is verified even when there is no such client, or no secret
    was sent: every failure costs one argon2, so the time a refusal takes says
    nothing about which client ids exist.
    """
    client = find_client(db, client_id or "")
    verified = security.verify_password(
        client_secret or "", client.client_secret_hash if client else None)
    if client is None or not verified or client.status != "active":
        return None
    return client


# -------------------------------------------------------------------- codes
def hash_code(code: str) -> str:
    """SHA-256, hex. The code is 256 bits of randomness, so a fast hash is
    enough to make a leaked table useless, and it can be looked up by."""
    return hashlib.sha256(code.encode()).hexdigest()


def sweep_codes(db: Session, *, at: datetime | None = None) -> None:
    """Delete codes that expired longer than CODE_KEEP ago. Runs on write."""
    moment = at or now()
    db.execute(delete(AuthorizationCode).where(
        AuthorizationCode.expires_at < moment - CODE_KEEP))


def mint_code(db: Session, *, client: OAuthClient, user: User, redirect_uri: str,
              nonce: str, state: str | None) -> str:
    """A new code, bound to this client, person, application, redirect URI and
    nonce. Returns the code; stores only its hash. Flushes; the caller commits."""
    sweep_codes(db)
    code = secrets.token_urlsafe(CODE_BYTES)
    moment = now()
    db.add(AuthorizationCode(
        code_hash=hash_code(code), oauth_client_id=client.id, user_id=user.id,
        application_id=client.application_id, redirect_uri=redirect_uri,
        nonce=nonce, state_echo=state, expires_at=moment + CODE_TTL,
        created_at=moment))
    db.flush()
    return code


def consume_code(db: Session, code: str, *, client_id: uuid.UUID, redirect_uri: str,
                 at: datetime | None = None) -> AuthorizationCode | None:
    """Mark the code consumed and return it — atomically, or not at all.

    One conditional UPDATE: this code, issued to this client for this redirect
    URI, not consumed and not expired. Two exchanges racing for one code both
    run it, and the database lets exactly one change the row; the other
    changes nothing and gets None. No read-then-write.

    The client and redirect URI are conditions of the statement, not checks
    after it. A client presenting a code issued to another client is refused
    without spending it — a client with valid credentials cannot burn codes
    that are not its own.

    The caller commits straight away, so a code is spent even if everything
    after this refuses: a code is single-use whether or not the exchange
    succeeds.
    """
    if not code:
        return None
    moment = at or now()
    code_hash = hash_code(code)
    changed = db.execute(
        update(AuthorizationCode)
        .where(AuthorizationCode.code_hash == code_hash,
               AuthorizationCode.oauth_client_id == client_id,
               AuthorizationCode.redirect_uri == redirect_uri,
               AuthorizationCode.consumed_at.is_(None),
               AuthorizationCode.expires_at > moment)
        .values(consumed_at=moment)
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        return None
    row = db.scalar(select(AuthorizationCode).where(AuthorizationCode.code_hash == code_hash))
    db.refresh(row)
    return row


def why_not_redeemable(db: Session, code: str, *, client_id: uuid.UUID,
                       redirect_uri: str, at: datetime | None = None) -> str:
    """Why consume_code refused, for the audit trail. It records; it never
    decides — the refusal has already happened."""
    row = db.scalar(select(AuthorizationCode).where(
        AuthorizationCode.code_hash == hash_code(code))) if code else None
    moment = at or now()
    if row is None:
        return "no such code"
    if row.consumed_at is not None:
        return "already redeemed"
    if _utc(row.expires_at) <= moment:
        return "expired"
    if row.oauth_client_id != client_id:
        return "issued to another client"
    if row.redirect_uri != redirect_uri:
        return "redirect_uri does not match the one used at authorize"
    return "not redeemable"
