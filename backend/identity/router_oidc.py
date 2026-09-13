"""The OIDC provider: the endpoints that hand a verified identity to another
service.

Registered in main.py beside the other routers, before the SPA catch-all. A
route registered after the catch-all would be answered with index.html and a
200 — a green status on a broken endpoint. What each path requires is
declared in guard.ROUTES, like every other route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from . import keys
from .db import get_db

router = APIRouter(tags=["oidc"])

# Cacheable, but briefly. A product that held the key set for hours would not
# see a newly rotated key until its cache expired and would refuse every token
# it signed. Five minutes keeps a per-request fetch off Core without holding a
# stale key set long; rotation (OPEN-DECISIONS #15) publishes the new key
# before it signs, so a verifier that refetches on an unknown kid never waits.
JWKS_MAX_AGE = 300


@router.get("/.well-known/jwks.json")
def jwks(db: Session = Depends(get_db)):
    """Every published signing key, in JWKS form. Public parameters only."""
    return JSONResponse(
        keys.published_jwks(db),
        headers={"Cache-Control": f"public, max-age={JWKS_MAX_AGE}"},
    )
