"""Project Management's password hashes: verified until the first sign-in,
then replaced with argon2id.

Every hash here is built in the test from a made-up password. None is real.

    pbkdf2_sha256$<salt: 32 lowercase hex>$<digest: 64 lowercase hex>

PBKDF2-HMAC-SHA256, 100,000 iterations (not stored in the hash), the salt
hex-decoded to 16 bytes. Exactly that shape, the whole string; anything else
stays "wrong password".
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.identity import security
from backend.identity.models import User

from conftest import ENGINEER_EMAIL

PASSWORD = "Made-Up-Test-Password-7"
SALT = bytes(range(16))                     # a fixed, obviously-fake salt


def promanage_hash(password: str = PASSWORD, salt: bytes = SALT,
                   iterations: int = 100_000) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


# --------------------------------------------------------------- verifying
def test_a_well_formed_hash_verifies_with_the_right_password():
    h = promanage_hash()
    assert security.is_promanage_hash(h)
    assert security.verify_password(PASSWORD, h) is True


def test_the_wrong_password_fails():
    assert security.verify_password("Not-The-Password-1", promanage_hash()) is False


def test_the_iteration_count_is_part_of_the_format():
    """A hash made with any other count is not this format's, and must not verify."""
    other = promanage_hash(iterations=1_000)
    assert security.verify_password(PASSWORD, other) is False


def _malformed():
    good = promanage_hash()
    _, salt, digest = good.split("$")
    raw = bytes.fromhex(digest)
    return {
        "salt too short": f"pbkdf2_sha256${salt[:30]}${digest}",
        "salt too long": f"pbkdf2_sha256${salt}00${digest}",
        "digest too short": f"pbkdf2_sha256${salt}${digest[:62]}",
        "digest too long": f"pbkdf2_sha256${salt}${digest}00",
        "uppercase hex": f"pbkdf2_sha256${salt.upper()}${digest.upper()}",
        "Django-style, with an iteration count": f"pbkdf2_sha256$100000${salt}${digest}",
        "Django-style, base64": f"pbkdf2_sha256$100000${salt}${base64.b64encode(raw).decode()}",
        "base64 digest": f"pbkdf2_sha256${salt}${base64.b64encode(raw).decode()}",
        "another algorithm's name": f"pbkdf2_sha1${salt}${digest}",
        "trailing newline": good + "\n",
        "leading space": " " + good,
        "non-hex character": f"pbkdf2_sha256${salt[:-1]}g${digest}",
        "empty parts": "pbkdf2_sha256$$",
    }


@pytest.mark.parametrize("name", sorted(_malformed()))
def test_a_malformed_variant_is_not_this_format_and_fails(name):
    variant = _malformed()[name]
    assert not security.is_promanage_hash(variant)
    assert security.verify_password(PASSWORD, variant) is False


def test_argon2_and_the_dummy_path_are_unchanged():
    """The existing paths behave exactly as before."""
    argon = security.hash_password(PASSWORD)
    assert security.verify_password(PASSWORD, argon) is True
    assert security.verify_password("wrong", argon) is False
    assert security.verify_password(PASSWORD, None) is False       # unknown address
    assert security.needs_rehash(argon) is False
    assert security.needs_rehash(promanage_hash()) is True


# ------------------------------------------------------ at sign-in
def _carry_over(db, h):
    engineer = db.scalar(select(User).where(User.email == ENGINEER_EMAIL))
    engineer.password_hash = h
    db.commit()


def _sign_in(password):
    from backend.main import app
    return TestClient(app).post("/api/auth/login",
                                json={"email": ENGINEER_EMAIL, "password": password})


def test_a_carried_over_hash_signs_in_and_becomes_argon2id(identity, db):
    _carry_over(db, promanage_hash())
    assert _sign_in(PASSWORD).status_code == 200
    db.expire_all()
    stored = db.scalar(select(User.password_hash).where(User.email == ENGINEER_EMAIL))
    assert stored.startswith("$argon2id$"), "re-hashed at the first sign-in"
    assert not security.is_promanage_hash(stored)
    # and the same password still works, now against argon2id
    assert _sign_in(PASSWORD).status_code == 200


def test_a_wrong_password_against_a_carried_over_hash_changes_nothing(identity, db):
    h = promanage_hash()
    _carry_over(db, h)
    assert _sign_in("Not-The-Password-1").status_code == 401
    db.expire_all()
    assert db.scalar(select(User.password_hash).where(User.email == ENGINEER_EMAIL)) == h


def test_a_malformed_carried_over_hash_cannot_sign_in(identity, db):
    _carry_over(db, _malformed()["Django-style, with an iteration count"])
    assert _sign_in(PASSWORD).status_code == 401
