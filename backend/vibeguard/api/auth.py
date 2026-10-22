"""Firebase Authentication for the API.

The dashboard signs users in with Google through the Firebase JS SDK and sends the Firebase ID
token as `Authorization: Bearer <token>`. We verify it ourselves, as Firebase documents for
third-party JWT libraries: RS256 signature against Google's published `securetoken` keys,
`aud` = project ID, `iss` = https://securetoken.google.com/<project>, unexpired, issued in
the past, non-empty `sub`, and a verified email. No service-account credentials are needed.

Then an allowlist decides who may use this deployment. Everything fails closed: no project ID
configured means 503, an empty allowlist means 403 for everyone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any, Protocol

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool

from vibeguard.config import Settings, get_settings

log = logging.getLogger(__name__)

FIREBASE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
)
CLOCK_SKEW_S = 60


@dataclass(frozen=True)
class Principal:
    uid: str
    email: str
    name: str | None = None
    picture: str | None = None


# Used when VIBEGUARD_AUTH_DISABLED is set (local devserver only)
DEV_PRINCIPAL = Principal(uid="dev", email="dev@localhost", name="Local developer")


class TokenVerifier(Protocol):
    def verify(self, token: str) -> dict[str, Any]: ...


class InvalidTokenError(Exception):
    pass


class FirebaseVerifier:
    def __init__(self, project_id: str, jwks_client: jwt.PyJWKClient | None = None) -> None:
        self.project_id = project_id
        # Keys are cached and refetched on an unknown `kid` (Google rotates them every few hours)
        self._jwks = jwks_client or jwt.PyJWKClient(
            FIREBASE_JWKS_URL, cache_keys=True, lifespan=3600, timeout=10
        )

    def verify(self, token: str) -> dict[str, Any]:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],  # never trust the token's own `alg`
                audience=self.project_id,
                issuer=f"https://securetoken.google.com/{self.project_id}",
                leeway=CLOCK_SKEW_S,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWKClientError as exc:
            # Unknown key id, or Google's key endpoint unreachable
            raise InvalidTokenError(f"signing key unavailable: {exc}") from None
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from None

        if not claims.get("sub") or len(claims["sub"]) > 128:
            raise InvalidTokenError("invalid subject")
        if "auth_time" in claims and claims["auth_time"] > claims["iat"] + CLOCK_SKEW_S:
            raise InvalidTokenError("auth_time is in the future")
        return claims


@lru_cache
def _verifier(project_id: str) -> FirebaseVerifier:
    return FirebaseVerifier(project_id)


def get_verifier(settings: Annotated[Settings, Depends(get_settings)]) -> TokenVerifier | None:
    """FastAPI dependency; overridden in tests with a verifier backed by a local key."""
    if settings.firebase_project_id is None:
        return None
    return _verifier(settings.firebase_project_id)


def is_allowed(email: str, settings: Settings) -> bool:
    email = email.strip().lower()
    if email in {e.strip().lower() for e in settings.auth_allowed_emails}:
        return True
    domain = email.rpartition("@")[2]
    return domain in {d.strip().lower().lstrip("@") for d in settings.auth_allowed_domains}


async def current_user(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    verifier: Annotated[TokenVerifier | None, Depends(get_verifier)],
) -> Principal:
    if settings.auth_disabled:
        return DEV_PRINCIPAL
    if verifier is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Authentication is not configured on this server (set VIBEGUARD_FIREBASE_PROJECT_ID)",
        )

    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("Sign in required")
    try:
        # Key fetches on a cache miss are blocking HTTP: keep them off the event loop
        claims = await run_in_threadpool(verifier.verify, token.strip())
    except InvalidTokenError as exc:
        log.info("rejected ID token: %s", exc)
        raise _unauthorized("Invalid or expired sign-in; please sign in again") from None

    email = claims.get("email")
    if not email or not claims.get("email_verified"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "A verified email address is required")
    if not is_allowed(email, settings):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"{email} is not allowed to use this VibeGuard deployment"
        )
    return Principal(
        uid=claims["sub"], email=email, name=claims.get("name"), picture=claims.get("picture")
    )


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, message, headers={"WWW-Authenticate": "Bearer"}
    )


CurrentUser = Annotated[Principal, Depends(current_user)]
