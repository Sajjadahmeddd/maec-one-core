"""Environment for the identity service.

Import this before anything that reads the environment: it loads `.env`
first. Real environment variables take precedence over the file, so on Render
— where there is no `.env` and every value comes from the dashboard — loading
is a no-op and nothing changes.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

_HERE = Path(__file__).resolve().parent          # <root>/backend/identity
REPO_ROOT = _HERE.parents[1]                     # <root>

# Counting directories upward is the pattern that silently disabled the whole
# PostgreSQL test module during the extraction: the count was wrong, no .env
# was found, and load_dotenv's answer to a missing file is to do nothing and
# say nothing. The same count is here, in production config, where being
# wrong means every secret quietly falls back to its default.
#
# So it states what it assumes. This cannot check that .env exists — on
# Render there is none and every value comes from the dashboard — but it can
# check the layout the count depends on, which is the part that moves.
if (REPO_ROOT / "backend" / "identity") != _HERE:
    raise RuntimeError(
        f"identity/config.py expected to be at <root>/backend/identity, but "
        f"is at {_HERE}. REPO_ROOT resolved to {REPO_ROOT}, so .env would "
        f"not be found and every setting would fall back to its default."
    )

# override=False: a value already in the environment wins over the file.
load_dotenv(REPO_ROOT / ".env", override=False)

SESSION_COOKIE = "maec_session"
SESSION_MAX_AGE = 12 * 60 * 60          # one working day

# The CSRF token travels in this header. A cross-site form post cannot set a
# custom header, which is the whole defence; the value is also checked against
# the session so it cannot simply be invented.
CSRF_HEADER = "X-CSRF-Token"


def database_url() -> str:
    """The connection string, with the driver named explicitly.

    Render (and Heroku, and most managed providers) hand out a URL beginning
    `postgresql://` or `postgres://`. SQLAlchemy reads a bare `postgresql://`
    as "use psycopg2", which is not what is installed — this project uses
    psycopg 3. Rewriting the scheme here means a provider's URL can be pasted
    or wired in as-is, rather than every deployment having to remember to
    edit it and one of them eventually not doing so.
    """
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Format: "
            "postgresql+psycopg://user:pass@host:5432/db — see .env.example."
        )
    for scheme in ("postgresql://", "postgres://"):
        if url.startswith(scheme):
            return "postgresql+psycopg://" + url[len(scheme):]
    return url


def session_secret() -> str:
    """Key that signs the session cookie.

    SESSION_SECRET is the name going forward; MAEC_SECRET_KEY is honoured so
    the value Render already generated keeps working until the dashboard is
    updated.

    A generated fallback keeps local development frictionless. On Render it
    is refused outright, because there it has two failure modes and the
    second is vicious: every restart signs everyone out, and — the moment the
    service runs more than one instance — each instance generates a
    *different* secret. Requests round-robin, a session minted on one
    instance fails to validate on another, and users are signed out at
    apparently random intervals. Diagnosing that from the symptom is
    miserable; refusing to boot says it in one line.

    This raises at import rather than at startup because `main.py` reads it
    while building the session middleware, which happens before the lifespan
    handler runs. A check in startup would fire after the generated secret
    was already in use.
    """
    for name in ("SESSION_SECRET", "MAEC_SECRET_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    if on_render():
        raise RuntimeError(
            "SESSION_SECRET is not set. Set it in the Render dashboard — "
            "any long random string. Refusing to start rather than generate "
            "one, because a generated secret differs per instance and signs "
            "users out at random once the service scales past one."
        )
    return secrets.token_urlsafe(32)


def session_secret_configured() -> bool:
    return any(os.environ.get(n, "").strip() for n in ("SESSION_SECRET", "MAEC_SECRET_KEY"))


def on_render() -> bool:
    return bool(os.environ.get("RENDER"))
