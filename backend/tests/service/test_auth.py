"""Firebase ID-token authentication: who gets in, who doesn't, and what is recorded."""

import time

import httpx
import jwt as pyjwt
import pytest

from tests.auth_helpers import ALLOWED_EMAIL, bearer, mint, other_key
from vibeguard.api.auth import get_verifier, is_allowed
from vibeguard.config import Settings

PROTECTED = [
    ("GET", "/api/v1/me", None),
    ("GET", "/api/v1/scans", None),
    ("POST", "/api/v1/scans", {"repo_url": "https://github.com/acme/app"}),
    ("GET", "/api/v1/scans/00000000-0000-0000-0000-000000000000", None),
    ("DELETE", "/api/v1/scans/00000000-0000-0000-0000-000000000000", None),
    ("GET", "/api/v1/scans/00000000-0000-0000-0000-000000000000/findings", None),
    ("PATCH", "/api/v1/findings/00000000-0000-0000-0000-000000000000", {"status": "OPEN"}),
    ("POST", "/api/v1/findings/00000000-0000-0000-0000-000000000000/pull-request", None),
]


async def _call(service, method, path, body, headers):
    return await service.client.request(method, path, json=body, headers=headers)


@pytest.mark.parametrize(("method", "path", "body"), PROTECTED)
async def test_every_api_route_requires_sign_in(service, method, path, body):
    # Explicitly empty Authorization overrides the client's default signed-in header
    resp = await _call(service, method, path, body, {"Authorization": ""})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Authentication required to initiate scans."}
    assert service.jobs == []


@pytest.mark.parametrize(
    ("token", "why"),
    [
        (lambda: mint(exp=int(time.time()) - 3600), "expired"),
        (lambda: mint(aud="someone-elses-project"), "wrong audience"),
        (lambda: mint(iss="https://securetoken.google.com/someone-elses-project"), "wrong issuer"),
        (lambda: mint(iss="https://accounts.google.com"), "not a Firebase token"),
        (lambda: mint(key=other_key()), "forged signature"),
        (lambda: mint(kid="unknown-kid"), "unknown signing key"),
        (lambda: mint(sub=""), "empty subject"),
        (lambda: mint(drop=("exp",)), "missing exp"),
        (lambda: mint(iat=int(time.time()) + 3600), "issued in the future"),
        (lambda: mint(auth_time=int(time.time()) + 3600), "authenticated in the future"),
        (lambda: "not.a.jwt", "garbage"),
    ],
)
async def test_bad_tokens_are_rejected(service, token, why):
    resp = await service.client.get("/api/v1/me", headers=bearer(token()))
    assert resp.status_code == 401, why


async def test_hs256_token_is_rejected_algorithm_confusion(service):
    """A token "signed" with HMAC must never be accepted, whatever key material it uses."""
    forged = pyjwt.encode(
        {"sub": "x", "aud": "vibeguard-test", "email": ALLOWED_EMAIL, "email_verified": True},
        "s" * 32,
        algorithm="HS256",
        headers={"kid": "test-kid"},
    )
    assert (await service.client.get("/api/v1/me", headers=bearer(forged))).status_code == 401


async def test_valid_token_identifies_the_user(service):
    resp = await service.client.get("/api/v1/me")
    assert resp.status_code == 200
    assert resp.json() == {
        "uid": "uid-123",
        "email": ALLOWED_EMAIL,
        "name": "Test User",
        "picture": None,
    }


async def test_unverified_email_is_forbidden(service):
    resp = await service.client.get("/api/v1/me", headers=bearer(mint(email_verified=False)))
    assert resp.status_code == 403 and "verified email" in resp.json()["detail"]


async def test_signed_in_but_not_allowlisted_is_forbidden(service):
    resp = await service.client.post(
        "/api/v1/scans",
        json={"repo_url": "https://github.com/acme/app"},
        headers=bearer(mint("stranger@gmail.com")),
    )
    assert resp.status_code == 403 and "not allowed" in resp.json()["detail"]
    assert service.jobs == []


async def test_domain_allowlist(service):
    service.settings.auth_allowed_domains = ["acme.dev"]
    ok = await service.client.get("/api/v1/me", headers=bearer(mint("Dev@ACME.dev")))
    lookalike = await service.client.get("/api/v1/me", headers=bearer(mint("dev@evilacme.dev")))
    assert ok.status_code == 200 and lookalike.status_code == 403


async def test_empty_allowlist_fails_closed(service):
    service.settings.auth_allowed_emails = []
    service.settings.auth_allowed_domains = []
    assert (await service.client.get("/api/v1/me")).status_code == 403


async def test_unconfigured_auth_fails_closed(service):
    app = service.client._transport.app
    app.dependency_overrides.pop(get_verifier)
    service.settings.firebase_project_id = None
    resp = await service.client.get("/api/v1/scans")
    assert resp.status_code == 503 and "not configured" in resp.json()["detail"]


async def test_dev_mode_needs_no_token(service):
    service.settings.auth_disabled = True
    resp = await service.client.get("/api/v1/me", headers={"Authorization": ""})
    assert resp.status_code == 200 and resp.json()["email"] == "dev@localhost"


async def test_scans_record_who_started_them(service, demo_app):
    scan = (await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})).json()
    assert scan["created_by"] == ALLOWED_EMAIL
    listed = (await service.client.get("/api/v1/scans")).json()
    assert listed[0]["created_by"] == ALLOWED_EMAIL


async def test_health_endpoints_and_webhooks_stay_public(service):
    app = service.client._transport.app
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as anon:
        assert (await anon.get("/healthz")).status_code == 200
        assert (await anon.get("/readyz")).status_code == 200
        # Webhooks authenticate with their HMAC signature instead (503 here: no secret set)
        assert (await anon.post("/api/v1/webhooks/github", content=b"{}")).status_code == 503


def test_is_allowed_normalizes_case_and_at_prefix():
    s = Settings(
        _env_file=None, auth_allowed_emails=[" Lead@Acme.dev "], auth_allowed_domains=["@corp.io"]
    )
    assert is_allowed("lead@acme.dev", s)
    assert is_allowed("anyone@CORP.io", s)
    assert not is_allowed("anyone@corp.io.evil.com", s)
