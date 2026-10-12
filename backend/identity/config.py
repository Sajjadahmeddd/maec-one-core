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


# ------------------------------------------------------------ environment
def is_development() -> bool:
    """Is this a developer's machine? Only `MAEC_ENV=development` says so.

    Development is the one place Core may invent what it was not given: a
    session secret and a signing key generated per process. Anywhere else
    those fallbacks are bugs that hide — a generated session secret differs
    per worker and signs people out at random; a generated signing key mints
    tokens nothing else can verify — so Core refuses to start instead.

    Unset, or any other value, is production. Fail safe: a deployment that
    forgets the variable gets the refusals, not the fallbacks. This replaced a
    check for Render's RENDER variable, which a VPS never sets — every
    protection keyed on it was silently off there.
    """
    return os.environ.get("MAEC_ENV", "").strip().lower() == "development"


def environment() -> str:
    return "development" if is_development() else "production"


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
        # Never decided by platform: the cookie is marked Secure on every
        # response to a request that arrived over https — directly, or
        # through a trusted proxy's X-Forwarded-Proto. main.SecureSessionCookie.
        "https_only": False,
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


def core_public_url(fallback: str | None = None) -> str | None:
    """The address people type to reach Core: what a sign-in link starts with.

    `CORE_PUBLIC_URL`, e.g. https://auth.mirageaec.com, or locally
    http://auth.maec.local:8000. The gate builds its login links from it,
    because the request in front of the gate comes from an app's server, and
    that request's own host is not where a browser should be sent. Unset, the
    caller's fallback is used.
    """
    from urllib.parse import urlsplit

    value = os.environ.get("CORE_PUBLIC_URL", "").strip().rstrip("/")
    if not value:
        return fallback.rstrip("/") if fallback else None
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.query:
        raise RuntimeError(
            f"CORE_PUBLIC_URL must be an absolute http(s) address, not {value!r}.")
    return value


def check_production_settings() -> None:
    """Refuse to start in production without what single sign-on needs.

    Outside development (MAEC_ENV), both must be set, or Core stops here:

    * CORE_PUBLIC_URL, and https. Without it the gate builds its sign-in
      links from the address its caller used — http://maec-core:8000 when an
      app asks over the Docker network, which no browser can reach. Over plain
      http the session cookie would never be marked Secure, and HSTS never
      sent, for anyone who follows a link.
    * SESSION_COOKIE_DOMAIN. Without it the cookie stays host-only: sign-in at
      Core works, and every app behind the gate silently sees nobody.

    Development keeps the fallbacks, so a laptop needs neither.
    """
    from urllib.parse import urlsplit

    if is_development():
        return
    url = core_public_url()
    if not url:
        raise RuntimeError(
            "CORE_PUBLIC_URL is not set. In production it must be Core's public "
            "https address, e.g. https://auth.mirageaec.com: without it, sign-in "
            "links are built from the caller's address — http://maec-core:8000 "
            "when an app asks over the Docker network, which no browser can "
            "reach. On a developer's machine, set MAEC_ENV=development instead.")
    if urlsplit(url).scheme != "https":
        raise RuntimeError(
            f"CORE_PUBLIC_URL must be https in production, not {url!r}: sign-in "
            "links would send people to plain http.")
    if not session_cookie_domain():
        raise RuntimeError(
            "SESSION_COOKIE_DOMAIN is not set. In production it must be the "
            "domain every app shares, e.g. .mirageaec.com: without it the "
            "session cookie is host-only and single sign-on silently stops "
            "working. On a developer's machine, set MAEC_ENV=development instead.")


# Long enough that guessing one is not a plan: token_urlsafe(32) gives 43.
MIN_GATE_SECRET = 32


def gate_secrets() -> dict[str, str]:
    """Each app's gate secret, by application key: `GATE_SECRETS`.

        GATE_SECRETS=engineering=<long random string>,timesheet=<another>

    The app's front door sends its secret with every check, so only that app's
    server can ask Core about a browser's cookie. Generate one with
    `python -c "import secrets; print(secrets.token_urlsafe(32))"`. A malformed
    entry or a short secret refuses to start rather than leaving an app with a
    gate anyone could open.
    """
    raw = os.environ.get("GATE_SECRETS", "").strip()
    secrets_by_app: dict[str, str] = {}
    for entry in (item.strip() for item in raw.split(",") if item.strip()):
        key, sep, secret = entry.partition("=")
        key, secret = key.strip(), secret.strip()
        if not sep or not key or not secret:
            raise RuntimeError(
                f"GATE_SECRETS entry {key or entry!r} must look like app_key=secret.")
        if len(secret) < MIN_GATE_SECRET:
            raise RuntimeError(
                f"GATE_SECRETS: the secret for {key!r} is shorter than "
                f"{MIN_GATE_SECRET} characters.")
        if key in secrets_by_app:
            raise RuntimeError(f"GATE_SECRETS names {key!r} twice.")
        secrets_by_app[key] = secret
    return secrets_by_app


def trusted_proxies() -> list[str]:
    """The proxies whose X-Forwarded-For and X-Forwarded-Proto Core believes.

    Only a request whose socket peer is on this list has its client address
    and scheme taken from those headers; from anyone else they are ignored,
    because anyone can send them. Core reads the result through
    `security.client_ip`, never the header itself. OPEN-DECISIONS #6.

    `TRUSTED_PROXIES`, comma-separated addresses or CIDR ranges. Default
    127.0.0.1: an nginx on the same machine. In Docker, nginx reaches Core from
    a container address such as 172.18.0.5, so production must name the Docker
    network's range (e.g. 172.18.0.0/16) or every visitor shares the proxy's
    address — one login rate limit for the whole company.

    `*` is refused: trusting every peer is the same as trusting the header.
    """
    import ipaddress

    raw = os.environ.get("TRUSTED_PROXIES", "").strip() or "127.0.0.1"
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    for entry in entries:
        if entry == "*":
            raise RuntimeError(
                "TRUSTED_PROXIES may not be '*': that believes X-Forwarded-For from "
                "anyone, which is anyone choosing their own address.")
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
        except ValueError as exc:
            raise RuntimeError(
                f"TRUSTED_PROXIES entry {entry!r} is not an IP address or CIDR range.") from exc
    return entries


def session_secret() -> str:
    """Key that signs the session cookie.

    SESSION_SECRET is the name going forward; MAEC_SECRET_KEY is honoured so
    the value Render already generated keeps working until the dashboard is
    updated.

    A generated fallback keeps local development frictionless, and is allowed
    only there (`MAEC_ENV=development`). Anywhere else it is refused outright,
    because it has two failure modes and the second is vicious: every restart
    signs everyone out, and — with more than one worker or instance — each
    generates a *different* secret. Requests round-robin, a session minted by
    one fails to validate on another, and users are signed out at apparently
    random intervals. Diagnosing that from the symptom is miserable; refusing
    to boot says it in one line.

    This raises at import rather than at startup because `main.py` reads it
    while building the session middleware, which happens before the lifespan
    handler runs. A check in startup would fire after the generated secret
    was already in use.
    """
    for name in ("SESSION_SECRET", "MAEC_SECRET_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    if not is_development():
        raise RuntimeError(
            "SESSION_SECRET is not set. Set it to any long random string "
            "(python -c \"import secrets; print(secrets.token_urlsafe(48))\"). "
            "Refusing to start rather than generate one, because a generated "
            "secret differs per worker and signs users out at random. On a "
            "developer's machine, set MAEC_ENV=development instead."
        )
    return secrets.token_urlsafe(32)


def session_secret_configured() -> bool:
    return any(os.environ.get(n, "").strip() for n in ("SESSION_SECRET", "MAEC_SECRET_KEY"))


# ------------------------------------------------------------------- OIDC
DEFAULT_ISSUER = "https://auth.mirageaec.com"


def oidc_private_key_pem() -> str | None:
    """The RSA private key that signs tokens, as PEM — or None locally.

    From the environment, never the database. Three reasons: Render's
    generateValue cannot produce an RSA key; every instance must sign with
    the same key, so a key generated per process would mint tokens that other
    instances cannot vouch for; and a private key in a table is one SQL
    injection away from being read.

    Refused outright when absent outside development, like SESSION_SECRET,
    and for the same reason raised here rather than in a lifespan handler:
    `main.py` reads it at import, so the refusal precedes any request. With
    `MAEC_ENV=development`, None, and keys.py generates an ephemeral key and
    says so.

    A dashboard or a .env file may hold the PEM on one line with literal
    `\\n` sequences; both that and real newlines are accepted.
    """
    value = os.environ.get("OIDC_PRIVATE_KEY", "").strip()
    if value:
        return value.replace("\\n", "\n")
    if not is_development():
        raise RuntimeError(
            "OIDC_PRIVATE_KEY is not set. Generate an RSA key of at least 2048 "
            "bits (see .env.example) and set its PEM. Refusing to start rather "
            "than generate one, because every worker must sign with the same "
            "key. On a developer's machine, set MAEC_ENV=development instead.")
    return None


def oidc_key_id() -> str | None:
    """The configured key id, or None to use the key's RFC 7638 thumbprint."""
    return os.environ.get("OIDC_KEY_ID", "").strip() or None


def oidc_issuer() -> str:
    """The `iss` every token carries and every product checks."""
    return os.environ.get("OIDC_ISSUER", "").strip().rstrip("/") or DEFAULT_ISSUER
