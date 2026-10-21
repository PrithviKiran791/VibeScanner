"""Redis key layout (markdown/backend_schema.md §3): live progress, per-repo lock, package cache."""

from __future__ import annotations

import json
import time

import redis

JOB_TTL_S = 2 * 60 * 60
LOCK_TTL_S = 5 * 60
PACKAGE_TTL_S = 24 * 60 * 60


def job_key(scan_id: str) -> str:
    return f"scan:job:{scan_id}"


def events_channel(scan_id: str) -> str:
    return f"scan:events:{scan_id}"


def lock_key(canonical_target: str) -> str:
    return f"scan:lock:{canonical_target}"


class ProgressReporter:
    """Writes the live-progress hash and publishes each update for WebSocket fan-out (Phase 3)."""

    def __init__(self, r: redis.Redis, scan_id: str, worker_id: str = "") -> None:
        self.r, self.scan_id, self.worker_id = r, scan_id, worker_id

    def update(self, step: str, percentage: int, status: str) -> None:
        self._write("PROGRESS", step=step, percentage=percentage, status=status)

    def finish(self, status: str, **extra: object) -> None:
        event = "SCAN_COMPLETED" if status == "COMPLETED" else "SCAN_FAILED"
        self._write(event, step=status, percentage=100, status=status, **extra)

    def _write(self, event: str, **fields: object) -> None:
        mapping = {k: str(v) for k, v in fields.items()} | {
            "worker_id": self.worker_id,
            "updated_at": str(time.time()),
        }
        key = job_key(self.scan_id)
        pipe = self.r.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, JOB_TTL_S)
        pipe.publish(events_channel(self.scan_id), json.dumps({"type": event, **fields}))
        pipe.execute()


def release_lock(r: redis.Redis, canonical_target: str, scan_id: str) -> None:
    """Delete the lock only if this scan still owns it (WATCH guards against a racing re-lock)."""
    key = lock_key(canonical_target)
    with r.pipeline() as pipe:
        try:
            pipe.watch(key)
            if pipe.get(key) in (scan_id, scan_id.encode()):
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
        except redis.WatchError:
            pass


class RedisExistenceCache:
    """`npm:package:{name}` / `pypi:package:{name}` -> "1" | "0", 24h TTL."""

    def __init__(self, r: redis.Redis) -> None:
        self.r = r

    def get(self, key: str) -> bool | None:
        try:
            v = self.r.get(key)
        except redis.RedisError:
            return None  # cache outage just means more registry calls
        return None if v is None else v in (b"1", "1")

    def set(self, key: str, exists: bool) -> None:
        try:
            self.r.set(key, "1" if exists else "0", ex=PACKAGE_TTL_S)
        except redis.RedisError:
            pass
