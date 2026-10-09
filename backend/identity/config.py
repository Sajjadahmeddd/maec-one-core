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


def _positive_number(name: str, default: float) -> float:
    """A positive number from the environment, or the default when unset.

    A value that is set but unusable refuses to start rather than quietly
    falling back: a typo in a session lifetime should not become the default
    without anyone noticing.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive number, not {raw!r}.")
    return value


# How long a sign-in lasts. OPEN-DECISIONS #5. Read on every use rather than
# once, so a test (or an operator, after a restart) gets what the environment
# says now.
def session_absolute_hours() -> float:
    """The longest a session lives, however busy: a working day."""
    return _positive_number("SESSION_ABSOLUTE_HOURS", 10)


def session_idle_minutes() -> float:
    """How long a session survives with no request at all."""
    return _positive_number("SESSION_IDLE_MINUTES", 120)


# The cookie's own lifetime. The sessions row ends a session; this only stops
# the browser keeping a cookie past the longest a row could last.
SESSION_MAX_AGE = int(session_absolute_hours() * 60 * 60)


def session_cookie_domain() -> str | None:
    """The cookie's Domain attribute, or None for a host-only cookie.

    Production: `.mirageaec.com`, so the browser sends Core's session to every
    app under it and the gate can check it (OPEN-DECISIONS #19). Locally:
    `.maec.local`. Unset keeps the cookie host-only, which is how it has
    always been, so nothing changes until this is set deliberately.

    A browser silently refuses a cookie whose Domain does not cover the host
    that set it. With `.maec.local` configured, sign in at
    http://auth.maec.local:8000 — at http://127.0.0.1:8000 the sign-in
    succeeds and the browser throws the cookie away.
    """
    value = os.environ.get("SESSION_COOKIE_DOMAIN", "").strip().lower()
    if not value:
        return None
    if any(c in value for c in ":/ \t") or "." not in value.strip("."):
        raise RuntimeError(
            f"SESSION_COOKIE_DOMAIN must be a bare domain such as .mirageaec.com, "
            f"not {value!r}.")
    return value


def session_cookie_options() -> dict:
    """Everything SessionMiddleware is built with, in one place, so main.py and
    the tests read the same answer."""
    return {
        "session_cookie": SESSION_COOKIE,
        "max_age": SESSION_MAX_AGE,
        "same_site": "lax",
        # Always Secure on Render. Everywhere else the cookie is marked Secure
        # per request, whenever that request arrived over https — see
        # main.SecureSessionCookie.
        "https_only": on_render(),
        "domain": session_cookie_domain(),
    }

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


# ------------------------------------------------------------------- OIDC
DEFAULT_ISSUER = "https://auth.mirageaec.com"


def oidc_private_key_pem() -> str | None:
    """The RSA private key that signs tokens, as PEM — or None locally.

    From the environment, never the database. Three reasons: Render's
    generateValue cannot produce an RSA key; every instance must sign with
    the same key, so a key generated per process would mint tokens that other
    instances cannot vouch for; and a private key in a table is one SQL
    injection away from being read.

    Refused outright on Render when absent, like SESSION_SECRET, and for the
    same reason raised here rather than in a lifespan handler: `main.py`
    reads it at import, so the refusal precedes any request. Locally None,
    and keys.py generates an ephemeral key and says so.

    A dashboard or a .env file may hold the PEM on one line with literal
    `\\n` sequences; both that and real newlines are accepted.
    """
    value = os.environ.get("OIDC_PRIVATE_KEY", "").strip()
    if value:
        return value.replace("\\n", "\n")
    if on_render():
        raise RuntimeError(
            "OIDC_PRIVATE_KEY is not set. Generate an RSA key of at least 2048 "
            "bits and paste its PEM into the Render dashboard. Refusing to start "
            "rather than generate one, because every instance must sign with the "
            "same key.")
    return None


def oidc_key_id() -> str | None:
    """The configured key id, or None to use the key's RFC 7638 thumbprint."""
    return os.environ.get("OIDC_KEY_ID", "").strip() or None


def oidc_issuer() -> str:
    """The `iss` every token carries and every product checks."""
    return os.environ.get("OIDC_ISSUER", "").strip().rstrip("/") or DEFAULT_ISSUER
