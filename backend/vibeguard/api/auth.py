"""Firebase Authentication for the API.

The dashboard signs users in (GitHub, Google or email) through the Firebase JS SDK and sends
the Firebase ID token as `Authorization: Bearer <token>`. We verify it ourselves, as Firebase
documents for third-party JWT libraries: RS256 signature against Google's published
`securetoken` keys, `aud` = project ID, `iss` = https://securetoken.google.com/<project>,
unexpired, issued in the past, non-empty `sub`. No service-account credentials are needed.

Then an allowlist decides who may use this deployment: a verified email (or its domain), or a
GitHub account id for GitHub sign-ins, whose emails Firebase never marks verified. Everything
fails closed: no project ID configured means 503, an empty allowlist means 403 for everyone.
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
    email: str | None
    name: str | None = None
    picture: str | None = None
    github_id: str | None = None


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
        raise _unauthorized("Authentication required to initiate scans.")
    try:
        # Key fetches on a cache miss are blocking HTTP: keep them off the event loop
        claims = await run_in_threadpool(verifier.verify, token.strip())
    except InvalidTokenError as exc:
        log.info("rejected ID token: %s", exc)
        raise _unauthorized("Invalid or expired sign-in; please sign in again") from None

    email = claims.get("email") or None
    verified = bool(email and claims.get("email_verified"))
    # Firebase signs the linked provider accounts into the token: firebase.identities
    identities = (claims.get("firebase") or {}).get("identities") or {}
    github_ids = identities.get("github.com") or []
    github_id = str(github_ids[0]) if github_ids else None

    github_ok = github_id in {i.strip() for i in settings.auth_allowed_github_ids}
    email_ok = verified and is_allowed(email or "", settings)
    if not (github_ok or email_ok):
        if github_id is not None:
            detail = f"GitHub account {github_id} is not allowed to use this VibeGuard deployment"
        elif not verified:
            detail = "A verified email address is required"
        else:
            detail = f"{email} is not allowed to use this VibeGuard deployment"
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)
    return Principal(
        uid=claims["sub"],
        email=email,
        name=claims.get("name"),
        picture=claims.get("picture"),
        github_id=github_id,
    )


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, message, headers={"WWW-Authenticate": "Bearer"}
    )


CurrentUser = Annotated[Principal, Depends(current_user)]
