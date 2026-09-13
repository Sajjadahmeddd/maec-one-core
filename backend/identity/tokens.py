"""The token a product receives: what it claims, and how it is signed.

The claims are built from `permissions.load()` — the same function `can()`
decides from — so a token carries exactly the inputs Core would have used,
scoped to its audience application and nothing else (OPEN-DECISIONS #11).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import jwt
from sqlalchemy.orm import Session

from . import config, keys
from .models import Application, OAuthClient, User
from .permissions import load
from .resolution import now, to_claims

# Fifteen minutes. Long enough that a product is not back at Core on every
# page; short enough that revocation has a bound an administrator can accept.
#
# The trade, stated: in Core a revoked seat or a suspension bites on the very
# next request, because every request re-reads the rows. A token is a copy of
# the inputs taken at issue — nothing in it changes when the rows do — so in a
# product the same revocation bites within `exp`, at most fifteen minutes.
# `pv` is how a product can learn sooner. OPEN-DECISIONS #16.
TOKEN_TTL = timedelta(minutes=15)


class NotEntitled(Exception):
    """Refused: the person is not entitled to the application at issue time."""


def build_claims(db: Session, *, user: User, application: Application,
                 client: OAuthClient, nonce: str, at: datetime | None = None) -> dict:
    """Everything the token says. Raises NotEntitled rather than mint a token
    for someone who may not use the application."""
    data = load(db, user, application.key)
    if not data.entitled:
        raise NotEntitled(application.key)

    moment = at or now()
    expires = moment + TOKEN_TTL
    # A token never outlives the subscription it was issued under.
    if data.entitled_until is not None and data.entitled_until < expires:
        expires = data.entitled_until

    return {
        "iss": config.oidc_issuer(),
        "sub": str(user.id),
        "email": user.email,
        "name": user.display_name,
        # the freshness epoch: bumped by every change to this person's access
        "pv": user.permissions_version,
        "nonce": nonce,
        "jti": str(uuid.uuid4()),
        "iat": int(moment.timestamp()),
        # floored, so a cap at valid_to can never round past it
        "exp": int(expires.timestamp()),
        # aud, org, entitled, entitled_until, grants, role_permissions, tool_rules
        **to_claims(data),
    }


def sign(claims: dict) -> str:
    """RS256, with the key id in the header so a product picks the right key
    from JWKS. The caller publishes the key first (keys.ensure_published)."""
    material = keys.signing_key()
    return jwt.encode(claims, material.private_pem, algorithm=keys.ALGORITHM,
                      headers={"kid": material.kid})
