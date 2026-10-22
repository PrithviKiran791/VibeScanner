"""Mint Firebase-shaped ID tokens with a local RSA key, and a verifier that trusts that key.

The production FirebaseVerifier is used unchanged; only the JWKS fetch is replaced.
"""

from __future__ import annotations

import time
from functools import cache
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from vibeguard.api.auth import FirebaseVerifier

PROJECT_ID = "vibeguard-test"
KID = "test-kid"
ALLOWED_EMAIL = "tester@example.com"


@cache
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@cache
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class StubJWKS:
    """Stands in for jwt.PyJWKClient: knows exactly one key id."""

    def get_signing_key_from_jwt(self, token: str):
        kid = jwt.get_unverified_header(token).get("kid")
        if kid != KID:
            raise jwt.PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')
        return SimpleNamespace(key=signing_key().public_key())


def verifier() -> FirebaseVerifier:
    return FirebaseVerifier(PROJECT_ID, jwks_client=StubJWKS())


def mint(
    email: str = ALLOWED_EMAIL,
    *,
    key: rsa.RSAPrivateKey | None = None,
    kid: str = KID,
    algorithm: str = "RS256",
    drop: tuple[str, ...] = (),
    **overrides,
) -> str:
    now = int(time.time())
    claims = {
        "iss": f"https://securetoken.google.com/{PROJECT_ID}",
        "aud": PROJECT_ID,
        "auth_time": now - 10,
        "iat": now - 10,
        "exp": now + 3600,
        "sub": "uid-123",
        "user_id": "uid-123",
        "email": email,
        "email_verified": True,
        "name": "Test User",
        "firebase": {"sign_in_provider": "google.com"},
    }
    claims.update(overrides)
    for name in drop:
        claims.pop(name, None)
    return jwt.encode(claims, key or signing_key(), algorithm=algorithm, headers={"kid": kid})


def bearer(token: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token or mint()}"}
