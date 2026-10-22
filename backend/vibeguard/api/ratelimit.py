"""Per-client fixed-window rate limits on the expensive endpoints, counted in Redis.

Only writes are limited (starting scans, opening PRs, triage, webhooks): the dashboard polls GET
endpoints every second while a scan runs. If Redis is unreachable the limiter fails open: rate
limiting protects capacity, it is not an auth control, so it must not take the API down with it.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable
from functools import lru_cache
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from redis.exceptions import RedisError

from vibeguard.api.deps import get_redis
from vibeguard.config import Settings, get_settings

log = logging.getLogger(__name__)


def client_ip(request: Request, settings: Settings) -> str:
    """The address to rate-limit: the socket peer, or the client behind a trusted proxy.

    X-Forwarded-For is only read when the peer itself is a trusted proxy (e.g. the dashboard's
    Next.js server). Clients can prepend anything to that header, so it is read right to left,
    skipping trusted hops: the first untrusted address is the one a trusted proxy actually saw.
    """
    peer = request.client.host if request.client else "unknown"
    trusted = _networks(tuple(settings.trusted_proxies))
    if not trusted or not _in(peer, trusted):
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if not _in(hop, trusted):
            return hop
    return peer


@lru_cache
def _networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


def _in(addr: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(addr.removeprefix("::ffff:"))
    except ValueError:
        return False
    return any(ip in n for n in networks)


def rate_limit(
    bucket: str, per_minute: Callable[[Settings], int]
) -> Callable[..., Awaitable[None]]:
    """FastAPI dependency: allow `per_minute(settings)` requests per client per 60s window."""

    async def dependency(
        request: Request,
        r: Annotated[aioredis.Redis, Depends(get_redis)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> None:
        limit = per_minute(settings)
        if not settings.rate_limit_enabled or limit <= 0:
            return
        window = int(time.time() // 60)
        key = f"ratelimit:{bucket}:{client_ip(request, settings)}:{window}"
        try:
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, 60)
            count, _ = await pipe.execute()
        except RedisError:
            log.warning("rate limiter unavailable (Redis error); allowing request")
            return
        if count > limit:
            retry_after = 60 - int(time.time()) % 60
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per minute. Try again shortly.",
                headers={"Retry-After": str(max(1, retry_after))},
            )

    return dependency
