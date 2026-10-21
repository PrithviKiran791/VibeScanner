"""FastAPI dependencies. Each is overridable via `app.dependency_overrides` in tests."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from typing import Any

import redis.asyncio as aioredis

from vibeguard.config import get_settings

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
