"""The sign-in lockout: per account *and* client address. OPEN-DECISIONS #20.

Five failed sign-ins from one address lock that account — for that address
only — for a minute, doubling with each further lock from the same address up
to thirty. Other addresses are unaffected: someone guessing at a colleague's
account locks themselves out, not the colleague.

Two rules close what the account-wide lock left open:

* **A lock that expires starts the count again from zero.** Before, the count
  only reset on a successful sign-in, so the first failure after a lock ended
  locked the account again — about two requests an hour held anyone out.
* **Failures during a lock are counted and audited, but never extend it** (a
  fixed window, Prompt 9a E5).

Escalation is kept, by counting locks rather than failures: `strikes` is how
many times this address has locked this account, and each lock is twice the
last. It resets when the address signs in successfully, or an administrator
resets the password.

One row per (account, address) in `login_locks`. Rows that are neither
locked nor recently used are swept when a failure is recorded. No scheduler.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from .models import LoginLock, User
from .resolution import _utc, now

LOCK_AFTER = 5
LOCK_BASE = timedelta(minutes=1)
LOCK_CAP = timedelta(minutes=30)

# An address that has not failed for this long, and holds no lock, is forgotten.
FORGET_AFTER = timedelta(days=1)

# The address when the request has none (no peer): one shared bucket, so a
# request without an address is still counted rather than exempt.
NO_ADDRESS = "unknown"


def lock_length(strikes: int) -> timedelta:
    """How long the lock that follows `strikes` earlier ones lasts."""
    return min(LOCK_BASE * (2 ** max(0, strikes)), LOCK_CAP)


def _row(db: Session, user: User, address: str) -> LoginLock | None:
    return db.scalar(select(LoginLock).where(
        LoginLock.user_id == user.id, LoginLock.address == address))


def locked(db: Session, user: User, address: str | None, *,
           at: datetime | None = None) -> bool:
    """Is this account locked for this address right now? A lock that has
    expired is reset here — its count starts again from zero."""
    moment = at or now()
    row = _row(db, user, address or NO_ADDRESS)
    if row is None or row.locked_until is None:
        return False
    if _utc(row.locked_until) > moment:
        return True
    row.failed_count = 0
    row.locked_until = None
    row.updated_at = moment
    db.flush()
    return False


def record_failure(db: Session, user: User, address: str | None, *,
                   at: datetime | None = None) -> LoginLock:
    """Count one failed sign-in from this address. Locks when the count
    reaches LOCK_AFTER and no lock is in force; never extends one. Call
    `locked()` first, so an expired lock has already been reset. Flushes."""
    moment = at or now()
    address = address or NO_ADDRESS
    _sweep(db, moment)
    row = _row(db, user, address)
    if row is None:
        row = LoginLock(user_id=user.id, address=address, failed_count=0,
                        strikes=0, updated_at=moment)
        db.add(row)
    in_force = row.locked_until is not None and _utc(row.locked_until) > moment
    row.failed_count += 1
    row.updated_at = moment
    if row.failed_count >= LOCK_AFTER and not in_force:
        row.locked_until = moment + lock_length(row.strikes)
        row.strikes += 1
    db.flush()
    return row


def clear(db: Session, user_id: uuid.UUID | str, address: str | None = None) -> int:
    """Forget the locks on an account — for one address (a successful sign-in
    from it), or every address (an administrator's reset). Flushes."""
    where = [LoginLock.user_id == uuid.UUID(str(user_id))]
    if address is not None:
        where.append(LoginLock.address == (address or NO_ADDRESS))
    removed = db.execute(delete(LoginLock).where(*where)
                         .execution_options(synchronize_session="fetch")).rowcount
    db.flush()
    return removed or 0


def _sweep(db: Session, moment: datetime) -> None:
    """Delete rows with no lock in force that have been quiet for a day."""
    cutoff = moment - FORGET_AFTER
    db.execute(delete(LoginLock).where(
        LoginLock.updated_at < cutoff,
        or_(LoginLock.locked_until.is_(None), LoginLock.locked_until < moment),
    ).execution_options(synchronize_session=False))
