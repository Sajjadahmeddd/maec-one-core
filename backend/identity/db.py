"""Engine and session plumbing.

The engine is created on first use rather than at import, so importing the
package (for a migration, a seed, a unit test) never demands a live database.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from . import config

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        url = config.database_url()
        if url.startswith("sqlite"):
            # The unit tests run on an in-memory SQLite; every connection to
            # ":memory:" would otherwise be a different empty database.
            _engine = create_engine(
                url, poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        else:
            _engine = create_engine(url, pool_pre_ping=True)
        _factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def session_factory() -> sessionmaker[Session]:
    engine()
    assert _factory is not None
    return _factory


def get_db(request: Request) -> Generator[Session, None, None]:
    """One session per request.

    The guard has already opened one to read the user and decide whether this
    request may proceed, and it parks it on `request.state`. Reusing it here
    means the route sees the same identity map, so re-reading the same user is
    free rather than a second round trip — and the whole request becomes one
    unit of work rather than two overlapping ones.

    When there is no guarded session — the public /api/auth/* paths — this
    opens and closes its own, as before.
    """
    existing = getattr(request.state, "identity_db", None)
    if existing is not None:
        yield existing          # the middleware owns it; do not close it here
        return

    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


def reset() -> None:
    """Forget the engine so the next use re-reads DATABASE_URL. Tests only."""
    global _engine, _factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _factory = None
