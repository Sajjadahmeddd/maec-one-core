"""Passwords, sessions and the CSRF token.

Hashing is argon2id (argon2-cffi's default). Nothing reversible is ever
stored, and nothing here logs or returns a hash.

The cookie is Starlette's signed cookie, and it carries two things: a 256-bit
random session id, new on every sign-in, and the CSRF token. Who the session
belongs to is not in it. `sessions.py` looks the id up — by its SHA-256 — in
the `sessions` table, and that row is the authority: no valid row, not
signed in, whatever the signature says. OPEN-DECISIONS #5.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Request

from . import config

# Cookie keys. Short, because every request carries them.
S_ID = "sid"          # the session id; the sessions row holds its SHA-256
S_CSRF = "csrf"

_hasher = PasswordHasher()   # argon2id, library defaults

# One real hash of a random password, verified against on every failed
# lookup so a request for an unknown address costs the same time as a wrong
# password for a known one.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(24))


# ------------------------------------------- Project Management's hashes
# People imported from Project Management keep the password they already
# have: their hash is carried over as it is (import_users.py) and verified
# here until their first sign-in, which re-hashes it to argon2id
# (router_auth.login, via needs_rehash). So the old format disappears as people
# sign in, and nothing else in Core ever has to know it.
#
# Exactly one shape, the whole string, and nothing looser:
#
#     pbkdf2_sha256$<salt: 32 lowercase hex>$<digest: 64 lowercase hex>
#
# PBKDF2-HMAC-SHA256, 100,000 iterations (fixed in that app's code, not stored
# in the hash), the salt hex-decoded to 16 bytes, a 32-byte digest stored as
# hex. Not Django's format (which stores the iterations and uses base64) and
# not passlib's. Anything else — uppercase hex, other lengths, an iteration
# field, base64 — is not this format and stays "wrong password".
PROMANAGE_HASH = re.compile(r"pbkdf2_sha256\$([0-9a-f]{32})\$([0-9a-f]{64})")
PROMANAGE_ITERATIONS = 100_000


def is_promanage_hash(password_hash: str | None) -> bool:
    return bool(password_hash) and PROMANAGE_HASH.fullmatch(password_hash) is not None


def _verify_promanage(password: str, password_hash: str) -> bool:
    match = PROMANAGE_HASH.fullmatch(password_hash)
    if match is None:
        return False
    salt, digest = bytes.fromhex(match.group(1)), bytes.fromhex(match.group(2))
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                    PROMANAGE_ITERATIONS)
    return hmac.compare_digest(candidate, digest)


# -------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-work verification. A missing hash still burns one argon2.

    A Project Management hash is verified as PBKDF2 instead (above). Every other
    path — argon2, an unknown address's dummy hash, anything unrecognised — is
    exactly as it was.
    """
    try:
        if is_promanage_hash(password_hash):
            return _verify_promanage(password, password_hash)
        return _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False              # fail closed, whatever went wrong


def needs_rehash(password_hash: str) -> bool:
    """Should this hash be replaced at the next successful sign-in? Always
    for a Project Management hash: that is how the old format disappears."""
    if is_promanage_hash(password_hash):
        return True
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return False


# The familiar composition policy: at least eight characters, with an
# uppercase letter, a lowercase letter, a digit and a symbol.
#
# It checks the *shape* of a password rather than whether anyone would guess
# it, so `Admin@123` passes. What stands between that and an intruder is the
# rest of the sign-in path: per-IP rate limiting, an escalating lockout after
# five failures, and argon2id, which is expensive per attempt by design. Those
# are the defences that actually hold; this function is the house rule.
MIN_PASSWORD_LENGTH = 8

_SPECIAL = "a symbol"


class WeakPasswordError(ValueError):
    pass


def check_password_policy(password: str, *, email: str = "") -> None:
    """Raise if this password would not be accepted. Server-side, always.

    `email` is accepted and ignored — every caller already passes it, and it
    is where a rule about the address would go if one is ever wanted back.
    """
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    # A symbol is anything that is not a letter, a digit or a space — so
    # punctuation a non-US keyboard produces counts, rather than only the
    # dozen characters an ASCII list would have named.
    missing = [
        label for label, present in (
            ("an uppercase letter", any(c.isupper() for c in password)),
            ("a lowercase letter", any(c.islower() for c in password)),
            ("a digit", any(c.isdigit() for c in password)),
            (_SPECIAL, any(not c.isalnum() and not c.isspace() for c in password)),
        ) if not present
    ]
    if missing:
        if len(missing) > 1:
            wanted = ", ".join(missing[:-1]) + " and " + missing[-1]
        else:
            wanted = missing[0]
        raise WeakPasswordError(f"Password must contain {wanted}.")


# --------------------------------------------------------------- sessions
def constant_time_equal(a: str | None, b: str | None) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


def begin(request: Request, session_id: str) -> None:
    """Write a new session into the cookie: this id, and a new CSRF token.

    Everything from before is discarded, so a cookie planted before sign-in is
    worthless after it. Called by `sessions.start`, which writes the row.
    """
    request.session.clear()
    request.session[S_ID] = session_id
    request.session[S_CSRF] = secrets.token_urlsafe(32)


def end_session(request: Request) -> None:
    try:
        request.session.clear()
    except AssertionError:
        pass                      # no SessionMiddleware — nothing to clear


def session_id(request: Request) -> str | None:
    """The session id the cookie carries, or None. Not proof of anything
    until `sessions.resolve` has found a valid row for it."""
    try:
        value = request.session.get(S_ID)
    except AssertionError:
        return None
    return value if isinstance(value, str) and value else None


def client_ip(request: Request | None) -> str | None:
    """Where a request came from: the one answer the login rate limit, the
    audit log and the sessions row all use.

    It is the connection's peer as uvicorn's ProxyHeadersMiddleware leaves it
    (main.py): rewritten from X-Forwarded-For only when the peer is one of
    TRUSTED_PROXIES, untouched otherwise. The header itself is never read
    here — it is whatever the sender chose to write. OPEN-DECISIONS #6.
    """
    if request is None or request.client is None:
        return None
    host = request.client.host
    return host[:64] if host else None


def csrf_token(request: Request) -> str | None:
    try:
        return request.session.get(S_CSRF)
    except AssertionError:
        return None


def csrf_ok(request: Request) -> bool:
    """The header must match the token the session holds. Constant time."""
    expected = csrf_token(request)
    supplied = request.headers.get(config.CSRF_HEADER)
    if not expected or not supplied:
        return False
    return constant_time_equal(expected, supplied)
