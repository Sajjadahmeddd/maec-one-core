"""The OIDC provider: the endpoints that hand a verified identity to another
service.

Registered in main.py beside the other routers, before the SPA catch-all. A
route registered after the catch-all would be answered with index.html and a
200 — a green status on a broken endpoint. What each path requires is
declared in guard.ROUTES, like every other route.

The rules — clients, redirect targets, codes — live in oauth.py, and the
token's claims in tokens.py. This module translates HTTP to them and back.
"""

from __future__ import annotations

import base64
import binascii
from html import escape
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from . import keys, oauth, tokens
from .db import get_db
from .models import User
from .permissions import audit, entitled, require_user
from .resolution import now

router = APIRouter(tags=["oidc"])

# Cacheable, but briefly. A product that held the key set for hours would not
# see a newly rotated key until its cache expired and would refuse every token
# it signed. Five minutes keeps a per-request fetch off Core without holding a
# stale key set long; rotation (OPEN-DECISIONS #15) publishes the new key
# before it signs, so a verifier that refetches on an unknown kid never waits.
JWKS_MAX_AGE = 300

# The widths of the columns these are stored in.
MAX_STATE = 500
MAX_NONCE = 255

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.get("/.well-known/jwks.json")
def jwks(db: Session = Depends(get_db)):
    """Every published signing key, in JWKS form. Public parameters only."""
    return JSONResponse(
        keys.published_jwks(db),
        headers={"Cache-Control": f"public, max-age={JWKS_MAX_AGE}"},
    )


# ---------------------------------------------------------------- authorize
def _with_params(uri: str, params: dict[str, str]) -> str:
    """The registered URI with these parameters added to any it already has."""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit(parts._replace(query=urlencode(query)))


def _back_to_client(redirect_uri: str, **params: str | None) -> RedirectResponse:
    kept = {key: value for key, value in params.items() if value}
    return RedirectResponse(_with_params(redirect_uri, kept), status_code=302,
                            headers={"Cache-Control": "no-store"})


def _error_page(heading: str, detail: str) -> HTMLResponse:
    """An error Core shows itself, because there is nowhere safe to send the
    browser yet. Every word is a constant here; nothing from the request is
    echoed into the page."""
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MAEC One — {escape(heading)}</title>
<style>
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
         padding: 24px; box-sizing: border-box; background: #f4f6f8; color: #1b2028;
         font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ max-width: 34rem; background: #fff; border: 1px solid #d9dee4;
         border-radius: 8px; padding: 28px 32px; }}
  h1 {{ font-size: 1.15rem; margin: 0 0 .6rem; }}
  p {{ margin: 0 0 1rem; }}
  a {{ color: #1d5c96; }}
</style>
</head>
<body>
<main>
  <h1>{escape(heading)}</h1>
  <p>{escape(detail)}</p>
  <p><a href="/">Go to MAEC One</a></p>
</main>
</body>
</html>"""
    return HTMLResponse(body, status_code=400, headers={"Cache-Control": "no-store"})


@router.get("/oauth/authorize")
def authorize(request: Request, db: Session = Depends(get_db),
              user: User = Depends(require_user)):
    """Hand this person back to a registered client with a one-time code.

    Always reached by a top-level GET: the session cookie is SameSite=Lax,
    which a cross-site POST would not carry. The guard has already required
    a session, an active account and no password change outstanding.
    """
    query = request.query_params
    client_id = query.get("client_id", "")
    redirect_uri = query.get("redirect_uri", "")
    state = query.get("state", "")
    nonce = query.get("nonce", "")
    response_type = query.get("response_type", "")

    # 1. The client. Until it and its redirect target are proven, an error is
    #    a page Core shows — redirecting to an unproven address is the open
    #    redirect this endpoint exists not to be.
    client = oauth.active_client(db, client_id)
    if client is None:
        audit(db, actor=user, action="oauth.authorize", target_type="oauth_client",
              target_id=client_id or None, result="blocked", request=request,
              after={"reason": "unknown or disabled client"})
        return _error_page(
            "This application isn't recognised",
            "The link that brought you here names an application that isn't "
            "registered with MAEC One, or has been switched off. Go back to the "
            "application and try again; if it keeps happening, tell your administrator.")

    application = client.application
    if not oauth.redirect_uri_registered(client, redirect_uri):
        audit(db, actor=user, action="oauth.authorize", target_type="oauth_client",
              target_id=client.client_id, application_id=application.id,
              result="blocked", request=request,
              after={"reason": "redirect_uri is not registered",
                     "redirect_uri": redirect_uri[:MAX_STATE]})
        return _error_page(
            "This sign-in link can't be used",
            "The application asked MAEC One to send you back to an address it "
            "hasn't registered, so you weren't sent anywhere. Tell your "
            "administrator which application you were using.")

    # 2. From here the target is proven, and an error goes back to the client.
    def refuse(error: str, reason: str) -> RedirectResponse:
        audit(db, actor=user, action="oauth.authorize", target_type="oauth_client",
              target_id=client.client_id, application_id=application.id,
              result="blocked", request=request,
              after={"error": error, "reason": reason})
        return _back_to_client(redirect_uri, error=error,
                               state=state if len(state) <= MAX_STATE else None)

    if response_type != "code":
        return refuse("unsupported_response_type", "only the authorization code flow is served")
    if not nonce or len(nonce) > MAX_NONCE:
        return refuse("invalid_request", "nonce is missing or too long")
    if not state or len(state) > MAX_STATE:
        return refuse("invalid_request", "state is missing or too long")

    # 3. Entitlement, re-checked against the database now — not taken from the
    #    session, and not from the launcher's list.
    if not entitled(db, user, application.key):
        return refuse("access_denied", "no entitlement to this application")

    # 4. The code: bound to client, person, application, redirect URI and
    #    nonce; only its hash is stored; thirty seconds to live.
    code = oauth.mint_code(db, client=client, user=user, redirect_uri=redirect_uri,
                           nonce=nonce, state=state)
    audit(db, actor=user, action="oauth.authorize", target_type="oauth_client",
          target_id=client.client_id, application_id=application.id,
          result="success", request=request, commit=False)
    db.commit()
    return _back_to_client(redirect_uri, code=code, state=state)


# -------------------------------------------------------------------- token
def _basic_credentials(header: str) -> tuple[str, str] | None:
    """client_id and secret from an HTTP Basic header, or None if none was sent.

    RFC 6749 §2.3.1 form-encodes both before base64. A malformed header is not
    None: it authenticates as nobody, so it still costs one verification.
    """
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value.strip():
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return "", ""
    client_id, separator, secret = decoded.partition(":")
    if not separator:
        return "", ""
    return unquote_plus(client_id), unquote_plus(secret)


def _token_error(error: str, status: int = 400, *, basic: bool = False) -> JSONResponse:
    headers = dict(NO_STORE)
    if status == 401 and basic:
        headers["WWW-Authenticate"] = 'Basic realm="MAEC One"'
    return JSONResponse({"error": error}, status_code=status, headers=headers)


@router.post("/oauth/token")
def token(request: Request, db: Session = Depends(get_db),
          grant_type: str = Form(""), code: str = Form(""),
          redirect_uri: str = Form(""), client_id: str = Form(""),
          client_secret: str = Form("")):
    """Redeem a code, once, for a signed token. Server-to-server only.

    No session is read and no CSRF header is asked for: the caller is a
    product's backend, which proves who it is with its client secret.
    """
    basic = _basic_credentials(request.headers.get("authorization", ""))
    if basic is not None:
        if client_secret:
            # RFC 6749 §2.3: one authentication method per request.
            return _token_error("invalid_request")
        client_id, client_secret = basic

    def refuse(error: str, reason: str, *, status: int = 400, actor: User | None = None,
               application_id=None) -> JSONResponse:
        audit(db, actor=actor, action="oauth.token", target_type="oauth_client",
              target_id=client_id or None, application_id=application_id,
              result="blocked", request=request, after={"error": error, "reason": reason})
        return _token_error(error, status, basic=basic is not None)

    # 1. The calling service. Constant work: an unknown client id costs the
    #    same argon2 verification as a wrong secret.
    client = oauth.authenticate_client(db, client_id, client_secret)
    if client is None:
        return refuse("invalid_client", "client authentication failed", status=401)
    application = client.application

    if grant_type != "authorization_code":
        return refuse("unsupported_grant_type", f"grant_type {grant_type[:40]!r}",
                      application_id=application.id)

    # 2. The code, consumed in one statement and committed at once: spent now,
    #    whatever follows.
    row = oauth.consume_code(db, code, client_id=client.id, redirect_uri=redirect_uri)
    db.commit()
    if row is None:
        reason = oauth.why_not_redeemable(db, code, client_id=client.id,
                                          redirect_uri=redirect_uri)
        return refuse("invalid_grant", reason, application_id=application.id)

    # 3. The person, re-checked now. Everything the guard would refuse a
    #    session for refuses a token too.
    person = db.get(User, row.user_id)
    if person is None or person.status != "active" or person.must_change_password:
        return refuse("invalid_grant", "account not active, or a password change is outstanding",
                      actor=person, application_id=application.id)

    # 4. Entitlement, re-checked at exchange: a seat revoked since authorize
    #    means no token. The claims come from load(), the function can() uses.
    try:
        claims = tokens.build_claims(db, user=person, application=application,
                                     client=client, nonce=row.nonce)
    except tokens.NotEntitled:
        return refuse("invalid_grant", "no entitlement to this application at exchange",
                      actor=person, application_id=application.id)

    # 5. Never sign with a key JWKS does not publish.
    keys.ensure_published(db)
    access_token = tokens.sign(claims)

    client.last_used_at = now()
    audit(db, actor=person, action="oauth.token", target_type="oauth_client",
          target_id=client.client_id, application_id=application.id,
          result="success", request=request,
          after={"jti": claims["jti"], "exp": claims["exp"], "pv": claims["pv"]},
          commit=False)
    db.commit()
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer",
         "expires_in": claims["exp"] - claims["iat"]},
        headers=NO_STORE,
    )
