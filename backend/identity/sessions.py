"""Server-side sessions: the record that makes a sign-in revocable.

The cookie carries a random session id; the `sessions` row for its SHA-256 is
the authority. A request is signed in only when that row exists, has not been
revoked, and is inside both its absolute and its idle window — checked on
every request, so revoking a row signs that browser out on its next call.
OPEN-DECISIONS #5, and #19 for why it matters: one cookie opens every app.

    start(db, request, user)       a new session, at sign-in
    resolve(db, request)           the valid row for this browser, or None
    check(db, session_id)          the same question, with the reason it failed
    end(db, request)               sign-out: revoke this browser's session
    revoke_all(db, user_id)        every session a person holds

Only `start` sweeps. A sign-in is a write anyway, and it is often enough to
keep the table small without a scheduler.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from . import config, security
from .models import LoginSession, User
from .resolution import _utc, now

# 32 bytes of randomness: 256 bits, 43 url-safe characters.
SESSION_ID_BYTES = 32

# The idle window is pushed forward on use, but at most this often per
# session — so a page that makes ten calls is one write, not ten.
TOUCH_EVERY = timedelta(minutes=1)

# Ended rows are kept this long before a sweep deletes them, so a refusal can
# still tell "your session expired" from "you never signed in".
KEEP_ENDED = timedelta(days=1)

# Why `check` refused. Run 2's gate passes these on to the app's front door.
OK = "ok"
NOT_SIGNED_IN = "not_signed_in"
SESSION_EXPIRED = "session_expired"


def hash_id(session_id: str) -> str:
    """SHA-256, hex. The id is 256 bits of randomness, so a fast hash is
    enough to make a leaked table useless, and the row can be looked up by
    it. The same reasoning as `oauth.hash_code`."""
    return hashlib.sha256(session_id.encode()).hexdigest()


def _absolute() -> timedelta:
    return timedelta(hours=config.session_absolute_hours())


def _idle() -> timedelta:
    return timedelta(minutes=config.session_idle_minutes())


def _idle_end(moment: datetime, absolute_end: datetime) -> datetime:
    """The idle window from `moment`, never past the session's absolute end."""
    return min(moment + _idle(), _utc(absolute_end))


# ------------------------------------------------------------------ begin
def start(db: Session, request: Request, user: User, *,
          at: datetime | None = None) -> LoginSession:
    """A new session for a freshly verified person. Flushes; the caller commits.

    Whatever session this browser held before — this person's or someone
    else's — is revoked first, and the id and CSRF token are new. So a cookie
    planted before sign-in is worthless after it: the fixation defence.
    """
    moment = at or now()
    previous = _row_for(db, security.session_id(request))
    if previous is not None and previous.revoked_at is None:
        previous.revoked_at = moment

    sweep(db, at=moment)

    session_id = secrets.token_urlsafe(SESSION_ID_BYTES)
    absolute_end = moment + _absolute()
    row = LoginSession(
        session_hash=hash_id(session_id), user_id=user.id,
        created_at=moment, last_seen_at=moment,
        absolute_expires_at=absolute_end,
        idle_expires_at=_idle_end(moment, absolute_end),
        ip=security.client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:400] or None),
    )
    db.add(row)
    db.flush()
    security.begin(request, session_id)
    return row


def sweep(db: Session, *, at: datetime | None = None) -> None:
    """Delete rows that ended — revoked, or past either window — more than
    KEEP_ENDED ago. Runs on write; no scheduler."""
    cutoff = (at or now()) - KEEP_ENDED
    # No in-memory synchronisation: a swept row is never read again, and
    # SQLAlchemy's "evaluate" would compare SQLite's naive datetimes with an
    # aware cutoff and raise.
    db.execute(delete(LoginSession).where(or_(
        LoginSession.revoked_at < cutoff,
        LoginSession.absolute_expires_at < cutoff,
        LoginSession.idle_expires_at < cutoff,
    )).execution_options(synchronize_session=False))


# ------------------------------------------------------------- the check
def _row_for(db: Session, session_id: str | None) -> LoginSession | None:
    if not session_id:
        return None
    return db.scalar(select(LoginSession).where(
        LoginSession.session_hash == hash_id(session_id)))


def _ended(row: LoginSession, moment: datetime) -> bool:
    return (row.revoked_at is not None
            or _utc(row.absolute_expires_at) <= moment
            or _utc(row.idle_expires_at) <= moment)


def check(db: Session, session_id: str | None, *,
          at: datetime | None = None) -> tuple[LoginSession | None, str]:
    """The valid row for this session id, and why not when there is none.

    `NOT_SIGNED_IN` when no id was sent or no row knows it; `SESSION_EXPIRED`
    when the row exists but was revoked or has run out. Reads only — `resolve`
    is what refreshes the idle window.
    """
    row = _row_for(db, session_id)
    if row is None:
        return None, NOT_SIGNED_IN
    if _ended(row, at or now()):
        return None, SESSION_EXPIRED
    return row, OK


def resolve(db: Session, request: Request, *,
            at: datetime | None = None) -> LoginSession | None:
    """The valid session this browser holds, or None — and a browser holding
    an id with no valid row has its cookie cleared, so it stops sending it.

    A valid row's idle window is pushed forward, at most once a minute. That
    write commits on its own: it runs before the route has written anything.
    """
    moment = at or now()
    session_id = security.session_id(request)
    row, _reason = check(db, session_id, at=moment)
    if row is None:
        if session_id:
            security.end_session(request)
        return None
    touch(db, row, at=moment)
    return row


def touch(db: Session, row: LoginSession, *, at: datetime | None = None) -> bool:
    """Push the idle window forward if a minute has passed. True if it wrote."""
    moment = at or now()
    if moment - _utc(row.last_seen_at) < TOUCH_EVERY:
        return False
    row.last_seen_at = moment
    row.idle_expires_at = _idle_end(moment, row.absolute_expires_at)
    db.commit()
    return True


# ------------------------------------------------------------------- end
def end(db: Session, request: Request, *, at: datetime | None = None) -> bool:
    """Sign-out: revoke this browser's session and clear its cookie. Flushes;
    the caller commits. True if there was a live session to revoke."""
    row = _row_for(db, security.session_id(request))
    security.end_session(request)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = at or now()
    db.flush()
    return True


def revoke_all(db: Session, user_id: uuid.UUID | str, *,
               at: datetime | None = None) -> int:
    """Revoke every live session this person holds. Flushes; the caller
    commits. Returns how many were live."""
    changed = db.execute(
        update(LoginSession)
        .where(LoginSession.user_id == uuid.UUID(str(user_id)),
               LoginSession.revoked_at.is_(None))
        .values(revoked_at=at or now())
        .execution_options(synchronize_session="fetch")
    ).rowcount
    db.flush()
    return changed or 0

