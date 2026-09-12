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

REPO_ROOT = Path(__file__).resolve().parents[2]

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
    updated. A generated fallback keeps local development frictionless, at
    the cost of signing everyone out on restart — which is why deployment
    warns when neither was set.
    """
    for name in ("SESSION_SECRET", "MAEC_SECRET_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return secrets.token_urlsafe(32)


def session_secret_configured() -> bool:
    return any(os.environ.get(n, "").strip() for n in ("SESSION_SECRET", "MAEC_SECRET_KEY"))


def on_render() -> bool:
    return bool(os.environ.get("RENDER"))
