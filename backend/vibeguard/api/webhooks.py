"""GitHub webhooks: a push to the default branch triggers a scan.

Works for a repository webhook and for a GitHub App (same headers and signature scheme). Set the
webhook's content type to `application/json`, subscribe to "push", and use the same secret as
VIBEGUARD_GITHUB_WEBHOOK_SECRET.

Every delivery is authenticated with HMAC-SHA256 over the raw body before anything is parsed,
and GitHub's delivery GUID is remembered for 24h so a redelivery can't start a second scan.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from vibeguard.api.deps import Dispatcher, get_dispatcher, get_redis
from vibeguard.api.enqueue import QueueUnavailableError, ScanAlreadyRunningError, enqueue_scan
from vibeguard.api.ratelimit import rate_limit
from vibeguard.config import Settings, get_settings
from vibeguard.db.session import get_session
from vibeguard.engine.ingest.workspace import IngestError, parse_github_url
from vibeguard.worker.contracts import ScanOptions, TargetSource

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/webhooks")

DELIVERY_TTL_S = 24 * 60 * 60


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


@router.post(
    "/github",
    dependencies=[Depends(rate_limit("webhooks", lambda s: s.rate_limit_webhooks_per_minute))],
)
async def github_webhook(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    r: Annotated[aioredis.Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
    dispatch: Annotated[Dispatcher, Depends(get_dispatcher)],
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    if settings.github_webhook_secret is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Webhooks are not configured")

    body = await request.body()
    if not verify_signature(
        settings.github_webhook_secret.get_secret_value(), body, x_hub_signature_256
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook signature")

    if x_github_event == "ping":
        return {"status": "pong"}
    if x_github_event != "push":
        return {"status": "ignored", "reason": f"event {x_github_event!r} is not handled"}

    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Payload is not JSON") from None

    if reason := _skip_reason(payload):
        return {"status": "ignored", "reason": reason}

    if x_github_delivery and not await _first_delivery(r, x_github_delivery):
        return {"status": "duplicate", "delivery": x_github_delivery}

    try:
        url = payload["repository"]["html_url"]
        parse_github_url(url)
        target = TargetSource(kind="github", url=url)
    except (KeyError, TypeError, IngestError):
        return {"status": "ignored", "reason": "repository is not on github.com"}

    try:
        scan = await enqueue_scan(target, ScanOptions(), session, r, dispatch)
    except ScanAlreadyRunningError as exc:
        return {"status": "already_running", "scan_id": exc.scan_id}
    except QueueUnavailableError:
        # 503 makes GitHub show the delivery as failed so it can be redelivered
        await _forget_delivery(r, x_github_delivery)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Task queue unavailable") from None

    log.info("push to %s queued scan %s", target.display_name, scan.id)
    response.status_code = status.HTTP_202_ACCEPTED
    return {"status": "queued", "scan_id": str(scan.id), "commit": payload.get("after")}


def _skip_reason(payload: dict[str, Any]) -> str | None:
    repo = payload.get("repository") or {}
    default = repo.get("default_branch")
    if payload.get("deleted"):
        return "branch deletion"
    if not default or payload.get("ref") != f"refs/heads/{default}":
        return f"push to {payload.get('ref')!r}, not the default branch"
    return None


async def _first_delivery(r: aioredis.Redis, delivery: str) -> bool:
    try:
        return bool(await r.set(f"webhook:delivery:{delivery}", "1", nx=True, ex=DELIVERY_TTL_S))
    except RedisError:
        return True  # dedupe is best-effort; the per-repo scan lock still prevents double runs


async def _forget_delivery(r: aioredis.Redis, delivery: str | None) -> None:
    if delivery:
        try:
            await r.delete(f"webhook:delivery:{delivery}")
        except RedisError:
            pass
