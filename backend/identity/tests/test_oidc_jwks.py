"""GET /.well-known/jwks.json.

Asserted by body, never by status alone. Every path outside the reserved
namespaces is the SPA, and before the guard's default-deny a mis-registered
route here would have been answered with index.html and a 200.
"""

from __future__ import annotations

import jwt
from sqlalchemy import select

from backend.identity import keys
from backend.identity.models import SigningKey
from backend.identity.router_oidc import JWKS_MAX_AGE

JWKS = "/.well-known/jwks.json"
PRIVATE_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi"}


def test_the_jwks_is_json_naming_the_signing_key(app_client, db):
    """No session needed: app_client has never signed in."""
    keys.ensure_published(db)
    r = app_client.get(JWKS)
    assert r.headers["content-type"].startswith("application/json")
    [key] = r.json()["keys"]
    assert key["kid"] == keys.signing_key().kid
    assert (key["kty"], key["alg"], key["use"]) == ("RSA", "RS256", "sig")
    assert key["n"] and key["e"]
    assert not PRIVATE_PARAMETERS & set(key)
    assert jwt.PyJWK(key).key is not None              # a usable key, not just the right shape


def test_the_published_key_verifies_what_the_signing_key_signs(app_client, db):
    keys.ensure_published(db)
    material = keys.signing_key()
    token = jwt.encode({"sub": "probe"}, material.private_pem, algorithm="RS256",
                       headers={"kid": material.kid})
    [key] = app_client.get(JWKS).json()["keys"]
    assert jwt.get_unverified_header(token)["kid"] == key["kid"]
    assert jwt.decode(token, jwt.PyJWK(key).key, algorithms=["RS256"])["sub"] == "probe"


def test_the_jwks_is_cacheable_briefly(app_client, db):
    keys.ensure_published(db)
    cache = app_client.get(JWKS).headers["cache-control"]
    assert "public" in cache and f"max-age={JWKS_MAX_AGE}" in cache


def test_a_retired_key_is_no_longer_published(app_client, db):
    keys.ensure_published(db)
    row = db.scalar(select(SigningKey))
    row.status = "retired"
    db.commit()
    assert app_client.get(JWKS).json() == {"keys": []}


def test_a_misspelled_well_known_path_is_refused_not_served_the_spa(app_client):
    r = app_client.get("/.well-known/jwks.jsn")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not found."}
