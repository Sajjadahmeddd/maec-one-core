"""Core's signing key (OPEN-DECISIONS #15).

The private key comes from the environment and never reaches the database;
the public half is published. These tests hold both halves of that, and the
refusals that keep one key id from ever naming two keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from backend.identity import keys
from backend.identity.models import SigningKey


def _pem(bits: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


@pytest.fixture
def env(monkeypatch):
    """Each test reads the environment it sets, not a key cached earlier."""
    keys.reset()
    yield monkeypatch
    keys.reset()


# ------------------------------------------------------ from the environment
def test_on_render_a_missing_private_key_refuses_to_start(env):
    env.setenv("RENDER", "true")
    env.delenv("OIDC_PRIVATE_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OIDC_PRIVATE_KEY is not set"):
        keys.signing_key()


def test_locally_a_missing_key_is_generated_and_says_so(env, caplog):
    env.delenv("RENDER", raising=False)
    env.delenv("OIDC_PRIVATE_KEY", raising=False)
    env.setenv("OIDC_KEY_ID", "belongs-to-a-real-key")
    with caplog.at_level(logging.WARNING, logger="maec.identity"):
        material = keys.signing_key()
    assert material.ephemeral is True
    assert material.kid.startswith(keys.EPHEMERAL_PREFIX)    # the real key's id is not borrowed
    assert "ephemeral key" in caplog.text


def test_a_key_pasted_on_one_line_is_accepted(env):
    env.setenv("OIDC_PRIVATE_KEY", _pem().strip().replace("\n", "\\n"))
    env.setenv("OIDC_KEY_ID", "one-line")
    material = keys.signing_key()
    assert material.kid == "one-line" and material.ephemeral is False


def test_a_weak_key_is_refused(env):
    env.setenv("OIDC_PRIVATE_KEY", _pem(1024))
    with pytest.raises(RuntimeError, match="2048"):
        keys.signing_key()


def test_something_that_is_not_a_key_is_refused(env):
    env.setenv("OIDC_PRIVATE_KEY", "not a pem at all")
    with pytest.raises(RuntimeError, match="not a readable"):
        keys.signing_key()


def test_without_a_key_id_the_kid_is_the_rfc7638_thumbprint(env):
    env.setenv("OIDC_PRIVATE_KEY", _pem())
    env.delenv("OIDC_KEY_ID", raising=False)
    material = keys.signing_key()
    jwk = keys.public_jwk(material.public_pem, material.kid)
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
                           separators=(",", ":"), sort_keys=True)
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
    assert material.kid == expected


def test_the_material_never_prints_its_private_half():
    assert "PRIVATE" not in repr(keys.signing_key())


# --------------------------------------------------------------- published
def test_publishing_is_idempotent_and_stores_only_the_public_half(db):
    first = keys.ensure_published(db)
    second = keys.ensure_published(db)
    rows = db.scalars(select(SigningKey)).all()
    assert len(rows) == 1
    assert first.kid == second.kid == keys.signing_key().kid == "test-key"
    assert "BEGIN PUBLIC KEY" in rows[0].public_pem
    assert "PRIVATE" not in rows[0].public_pem


def test_the_published_jwks_carries_public_parameters_only(db):
    keys.ensure_published(db)
    [key] = keys.published_jwks(db)["keys"]
    assert (key["kty"], key["kid"], key["use"], key["alg"]) == ("RSA", "test-key", "sig", "RS256")
    assert key["n"] and key["e"]
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(key)


def test_a_key_id_already_published_with_another_key_is_refused(db, env):
    keys.ensure_published(db)                          # "test-key", the suite's key
    env.setenv("OIDC_PRIVATE_KEY", _pem())             # a different key, same id
    keys.reset()
    with pytest.raises(keys.SigningKeyConflict, match="different public key"):
        keys.ensure_published(db)


def test_a_retired_key_id_cannot_sign_again(db):
    row = keys.ensure_published(db)
    row.status = "retired"
    db.commit()
    with pytest.raises(keys.SigningKeyConflict, match="retired"):
        keys.ensure_published(db)
    assert keys.published_jwks(db) == {"keys": []}


def test_a_new_ephemeral_key_retires_the_last_one(db, env):
    env.delenv("RENDER", raising=False)
    env.delenv("OIDC_PRIVATE_KEY", raising=False)
    first = keys.ensure_published(db).kid
    keys.reset()                                        # a restart, in effect
    second = keys.ensure_published(db).kid
    status = {row.kid: row.status for row in db.scalars(select(SigningKey)).all()}
    assert first != second
    assert status == {first: "retired", second: "active"}
