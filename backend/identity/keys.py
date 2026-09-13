"""Core's signing key: the private half that signs tokens, and the public half
JWKS publishes.

The private key comes from the environment — `config.oidc_private_key_pem()`
— and never touches the database. The public half is upserted into
`signing_keys`, because JWKS has to keep publishing a key after it stops
signing, until every token it signed has expired. OPEN-DECISIONS #15.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import config
from .models import SigningKey
from .resolution import now

ALGORITHM = "RS256"
MIN_KEY_BITS = 2048
EPHEMERAL_PREFIX = "ephemeral-"

log = logging.getLogger("maec.identity")


class SigningKeyConflict(RuntimeError):
    """A key id is already published with a different public key."""


@dataclass(frozen=True)
class SigningMaterial:
    kid: str
    public_pem: str
    private_pem: str = field(repr=False)
    # generated for this process because no key was configured — local only
    ephemeral: bool = False


_material: SigningMaterial | None = None


def signing_key() -> SigningMaterial:
    """The key this process signs with. Read once, then cached.

    `main.py` calls this at import, so on Render a missing key refuses to
    start before a single request is served — the same place and the same
    reason as SESSION_SECRET.
    """
    global _material
    if _material is None:
        _material = _from_environment()
    return _material


def reset() -> None:
    """Forget the cached key so the next use re-reads the environment. Tests only."""
    global _material
    _material = None


def thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """RFC 7638 JWK thumbprint: a key id that is a fact about the key."""
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
                           separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _from_environment() -> SigningMaterial:
    pem = config.oidc_private_key_pem()           # raises on Render when absent
    if pem is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=MIN_KEY_BITS)
        ephemeral = True
    else:
        try:
            key = serialization.load_pem_private_key(pem.encode(), password=None)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                "OIDC_PRIVATE_KEY is not a readable unencrypted PEM private key.") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError("OIDC_PRIVATE_KEY must be an RSA key: tokens are signed RS256.")
        if key.key_size < MIN_KEY_BITS:
            raise RuntimeError(
                f"OIDC_PRIVATE_KEY is {key.key_size} bits; at least {MIN_KEY_BITS} are required.")
        ephemeral = False

    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()

    if ephemeral:
        # A configured OIDC_KEY_ID is ignored here on purpose: that name
        # belongs to a real key, and reusing it for a throwaway one would
        # publish two different keys under one id.
        kid = EPHEMERAL_PREFIX + thumbprint(key.public_key())[:32]
        log.warning(
            "identity: OIDC_PRIVATE_KEY is not set — signing with an ephemeral key "
            "(%s) that lasts until this process stops. Tokens it signs will not "
            "verify after a restart. Set OIDC_PRIVATE_KEY to keep one.", kid)
    else:
        kid = config.oidc_key_id() or thumbprint(key.public_key())
    return SigningMaterial(kid=kid, public_pem=public_pem, private_pem=private_pem,
                           ephemeral=ephemeral)


def ensure_published(db: Session, material: SigningMaterial | None = None) -> SigningKey:
    """Make sure JWKS publishes the key that signs. Idempotent; commits.

    Called at startup and again before any token is signed, so Core can never
    hand out a token whose key JWKS does not publish.

    A key id already published with a different public key is refused.
    Verifiers cache keys by id, so two keys under one id means tokens that
    verify against the wrong key, or never. A rotated key needs a new
    OIDC_KEY_ID.
    """
    material = material or signing_key()
    row = db.scalar(select(SigningKey).where(SigningKey.kid == material.kid))
    if row is None:
        row = SigningKey(kid=material.kid, public_pem=material.public_pem,
                         algorithm=ALGORITHM, status="active")
        db.add(row)
        if material.ephemeral:
            # Each restart without a configured key makes a new one. Retire
            # the previous throwaways rather than publishing them forever.
            for stale in db.scalars(select(SigningKey).where(
                    SigningKey.kid.startswith(EPHEMERAL_PREFIX),
                    SigningKey.kid != material.kid,
                    SigningKey.status == "active")).all():
                stale.status, stale.retired_at = "retired", now()
        try:
            db.commit()
        except IntegrityError:
            # Another instance published the same key id at the same moment.
            db.rollback()
            row = db.scalar(select(SigningKey).where(SigningKey.kid == material.kid))
            if row is None:
                raise
    if row.public_pem.strip() != material.public_pem.strip():
        raise SigningKeyConflict(
            f"Signing key id {material.kid!r} is already published with a different "
            "public key. A new key needs a new OIDC_KEY_ID.")
    if row.status != "active":
        raise SigningKeyConflict(
            f"Signing key id {material.kid!r} was retired and cannot sign again. "
            "Configure a new key with a new OIDC_KEY_ID.")
    return row


def public_jwk(public_pem: str, kid: str) -> dict:
    """One key in JWKS form. Public parameters only, by construction."""
    public_key = serialization.load_pem_public_key(public_pem.encode())
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": ALGORITHM,
            "n": jwk["n"], "e": jwk["e"]}


def published_jwks(db: Session) -> dict:
    """Every active key, as a JWKS document."""
    rows = db.scalars(select(SigningKey).where(SigningKey.status == "active")
                      .order_by(SigningKey.created_at)).all()
    return {"keys": [public_jwk(row.public_pem, row.kid) for row in rows]}
