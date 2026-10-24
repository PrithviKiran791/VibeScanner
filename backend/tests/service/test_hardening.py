"""Phase 4: rate limiting, GitHub webhooks, readiness, security headers, body size cap."""

import hashlib
import hmac
import json

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr
from redis.exceptions import ConnectionError as RedisConnectionError

from vibeguard.api.deps import get_redis
from vibeguard.api.ratelimit import rate_limit
from vibeguard.api.webhooks import verify_signature
from vibeguard.config import get_settings
from vibeguard.worker.state import lock_key

SECRET = "webhook-test-secret"


# --- rate limiting -------------------------------------------------------------------------


async def test_scan_creation_is_rate_limited_per_client(service, demo_app):
    service.settings.rate_limit_scans_per_minute = 2
    body = {"repo_url": "https://github.com/acme/app-{}"}
    codes = [
        (await service.client.post("/api/v1/scans", json={"repo_url": body["repo_url"].format(i)}))
        for i in range(3)
    ]
    assert [r.status_code for r in codes] == [202, 202, 429]
    assert 1 <= int(codes[2].headers["retry-after"]) <= 60
    assert "Rate limit exceeded" in codes[2].json()["detail"]

    # Reads are never limited: the dashboard polls them every second
    for _ in range(5):
        assert (await service.client.get("/api/v1/scans")).status_code == 200


async def test_limits_are_per_bucket(service, demo_app):
    service.settings.rate_limit_scans_per_minute = 1
    service.settings.rate_limit_triage_per_minute = 1
    assert (
        await service.client.post("/api/v1/scans", json={"repo_url": "https://github.com/a/b"})
    ).status_code == 202
    missing = "00000000-0000-0000-0000-000000000000"
    # Triage has its own budget, so it still gets through (404 = reached the handler)
    resp = await service.client.patch(f"/api/v1/findings/{missing}", json={"status": "OPEN"})
    assert resp.status_code == 404


async def test_rate_limiter_fails_open_when_redis_is_down(service):
    class BrokenPipeline:
        def incr(self, *_):
            return self

        def expire(self, *_):
            return self

        async def execute(self):
            raise RedisConnectionError("down")

    class BrokenRedis:
        def pipeline(self):
            return BrokenPipeline()

    app = FastAPI()

    @app.post("/limited", dependencies=[Depends(rate_limit("t", lambda s: 1))])
    async def limited():
        return {"ok": True}

    app.dependency_overrides[get_redis] = lambda: BrokenRedis()
    app.dependency_overrides[get_settings] = lambda: service.settings
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        for _ in range(3):  # over the limit of 1, but the counter is unreachable
            assert (await c.post("/limited")).status_code == 200


# --- GitHub webhooks -----------------------------------------------------------------------


def _push(
    ref="refs/heads/main", default="main", deleted=False, url="https://github.com/acme/vibe-app"
):
    return {
        "ref": ref,
        "after": "a" * 40,
        "deleted": deleted,
        "repository": {"html_url": url, "default_branch": default, "full_name": "acme/vibe-app"},
    }


async def _deliver(service, payload, event="push", delivery="d-1", secret=SECRET, signature=None):
    body = json.dumps(payload).encode()
    sig = signature or "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return await service.client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": sig,
        },
    )


@pytest.fixture
def webhooks_on(service):
    service.settings.github_webhook_secret = SecretStr(SECRET)
    return service


async def test_push_to_default_branch_queues_a_github_scan(webhooks_on):
    svc = webhooks_on
    resp = await _deliver(svc, _push())
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "queued" and body["commit"] == "a" * 40
    [job] = svc.jobs
    assert job[0] == body["scan_id"]
    assert job[1] == {"kind": "github", "url": "https://github.com/acme/vibe-app", "path": None}

    # Nobody has scanned this repo by hand, so the push scan has no owner and nobody sees it
    resp = await svc.client.get(f"/api/v1/scans/{body['scan_id']}")
    assert resp.status_code == 404


async def test_push_scan_goes_to_whoever_last_scanned_the_repo(webhooks_on):
    svc = webhooks_on
    manual = await svc.client.post(
        "/api/v1/scans", json={"repo_url": "https://github.com/acme/vibe-app"}
    )
    assert manual.status_code == 202
    svc.redis.delete(lock_key("https://github.com/acme/vibe-app"))  # as if the worker finished

    body = (await _deliver(svc, _push())).json()
    scan = (await svc.client.get(f"/api/v1/scans/{body['scan_id']}")).json()
    assert scan["source_type"] == "GITHUB" and scan["status"] == "QUEUED"
    history = (await svc.client.get("/api/v1/scans")).json()
    assert [s["id"] for s in history] == [body["scan_id"], manual.json()["id"]]


async def test_redelivery_does_not_start_a_second_scan(webhooks_on):
    svc = webhooks_on
    assert (await _deliver(svc, _push(), delivery="same")).status_code == 202
    await svc.run_jobs()
    again = await _deliver(svc, _push(), delivery="same")
    assert again.status_code == 200 and again.json()["status"] == "duplicate"
    assert svc.jobs == []


async def test_push_while_scan_running_reports_existing_scan(webhooks_on):
    svc = webhooks_on
    first = (await _deliver(svc, _push(), delivery="one")).json()
    second = await _deliver(svc, _push(), delivery="two")
    assert second.json() == {"status": "already_running", "scan_id": first["scan_id"]}


@pytest.mark.parametrize(
    ("payload", "event", "reason"),
    [
        (_push(ref="refs/heads/feature"), "push", "not the default branch"),
        (_push(deleted=True), "push", "branch deletion"),
        (_push(url="https://gitlab.com/acme/vibe-app"), "push", "not on github.com"),
        ({}, "issues", "is not handled"),
    ],
)
async def test_irrelevant_deliveries_are_ignored(webhooks_on, payload, event, reason):
    resp = await _deliver(webhooks_on, payload, event=event)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored" and reason in resp.json()["reason"]
    assert webhooks_on.jobs == []


async def test_ping_is_answered(webhooks_on):
    resp = await _deliver(webhooks_on, {"zen": "Keep it logically awesome."}, event="ping")
    assert resp.json() == {"status": "pong"}


@pytest.mark.parametrize("signature", ["sha256=" + "0" * 64, "sha1=abc", ""])
async def test_bad_signatures_are_rejected_before_parsing(webhooks_on, signature):
    resp = await _deliver(webhooks_on, _push(), signature=signature or "x")
    assert resp.status_code == 401
    assert webhooks_on.jobs == []


async def test_wrong_secret_is_rejected(webhooks_on):
    resp = await _deliver(webhooks_on, _push(), secret="not-the-secret")
    assert resp.status_code == 401


async def test_webhooks_disabled_without_secret(service):
    resp = await _deliver(service, _push())
    assert resp.status_code == 503


def test_verify_signature_is_exact():
    body = b'{"a":1}'
    good = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    assert verify_signature("k", body, good)
    assert not verify_signature("k", body + b" ", good)
    assert not verify_signature("k", body, None)


# --- readiness, headers, size cap ----------------------------------------------------------


async def test_readyz_reports_dependencies(service):
    resp = await service.client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "database": "ok", "redis": "ok"}


async def test_security_headers_on_every_response(service):
    for path in ("/healthz", "/api/v1/scans", "/api/v1/scans/not-a-uuid"):
        resp = await service.client.get(path)
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["cache-control"] == "no-store"


async def test_oversized_bodies_are_refused_unread(service):
    huge = b"{" + b" " * (service.settings.max_request_bytes + 10) + b"}"
    resp = await service.client.post(
        "/api/v1/scans", content=huge, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 413


# --- client IP resolution behind proxies ---------------------------------------------------


def _req(peer: str, xff: str | None = None):
    from starlette.requests import Request

    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers})


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.9", "1.2.3.4", "203.0.113.9"),  # untrusted peer: header ignored
        ("172.28.0.10", "198.51.100.7", "198.51.100.7"),  # dashboard proxy vouches
        ("172.28.0.10", "6.6.6.6, 198.51.100.7", "198.51.100.7"),  # spoofed prefix ignored
        ("172.28.0.10", None, "172.28.0.10"),  # proxy without header: proxy itself
        ("172.28.0.10", "not-an-ip", "not-an-ip"),  # garbage is untrusted, still bucketed
    ],
)
def test_client_ip_only_trusts_configured_proxies(peer, xff, expected):
    from vibeguard.api.ratelimit import client_ip
    from vibeguard.config import Settings

    settings = Settings(_env_file=None, trusted_proxies=["172.28.0.10/32"])
    assert client_ip(_req(peer, xff), settings) == expected


def test_no_trusted_proxies_means_socket_peer():
    from vibeguard.api.ratelimit import client_ip
    from vibeguard.config import Settings

    assert client_ip(_req("10.0.0.1", "1.1.1.1"), Settings(_env_file=None)) == "10.0.0.1"
