"""FastAPI dependencies. Each is overridable via `app.dependency_overrides` in tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from functools import lru_cache
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import Depends

from vibeguard.config import Settings, get_settings
from vibeguard.integrations.github import GitHubClient

# (scan_id, target_source, options) -> None
Dispatcher = Callable[[str, dict[str, Any], dict[str, Any]], None]


@lru_cache
def _redis() -> aioredis.Redis:
    return aioredis.Redis.from_url(get_settings().redis_url)


def get_redis() -> aioredis.Redis:
    return _redis()


def get_dispatcher() -> Dispatcher:
    from vibeguard.worker.tasks import run_scan_task

    def dispatch(scan_id: str, target: dict[str, Any], options: dict[str, Any]) -> None:
        run_scan_task.delay(scan_id, target, options)

    return dispatch


async def get_github_client(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AsyncIterator[GitHubClient | None]:
    """A GitHubClient for the server's token, or None when no token is configured."""
    if settings.github_token is None:
        yield None
        return
    client = GitHubClient(settings.github_token.get_secret_value())
    try:
        yield client
    finally:
        await client.aclose()
