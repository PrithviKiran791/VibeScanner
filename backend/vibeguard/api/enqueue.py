"""Shared "start a scan" logic for the REST endpoint and the GitHub webhook."""

from __future__ import annotations

import logging

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vibeguard.api.deps import Dispatcher
from vibeguard.db.models import Repository, Scan, ScanSource, ScanStatus
from vibeguard.worker.contracts import ScanOptions, TargetSource
from vibeguard.worker.state import JOB_TTL_S, LOCK_TTL_S, job_key, lock_key

log = logging.getLogger(__name__)


class ScanAlreadyRunningError(Exception):
    def __init__(self, scan_id: str | None) -> None:
        super().__init__("A scan for this repository is already running")
        self.scan_id = scan_id


class QueueUnavailableError(Exception):
    pass


async def enqueue_scan(
    target: TargetSource,
    options: ScanOptions,
    session: AsyncSession,
    r: aioredis.Redis,
    dispatch: Dispatcher,
    created_by: str | None = None,
) -> Scan:
    canonical = target.canonical

    # One active scan per repo (5 min TTL backstop if a worker dies before releasing it)
    if not await r.set(lock_key(canonical), "pending", nx=True, ex=LOCK_TTL_S):
        existing = await r.get(lock_key(canonical))
        raise ScanAlreadyRunningError(
            existing.decode() if isinstance(existing, bytes) else existing
        )

    try:
        repo = await session.scalar(select(Repository).where(Repository.url == canonical))
        if repo is None:
            repo = Repository(name=target.display_name, url=canonical)
            session.add(repo)
        scan = Scan(
            repository=repo,
            source_type=ScanSource.GITHUB if target.kind == "github" else ScanSource.LOCAL,
            status=ScanStatus.QUEUED,
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            llm_used=False,
            warnings=[],
            created_by=created_by,
        )
        session.add(scan)
        await session.commit()

        sid = str(scan.id)
        await r.set(lock_key(canonical), sid, xx=True, ex=LOCK_TTL_S)
        await r.hset(
            job_key(sid), mapping={"step": "QUEUED", "percentage": "0", "status": "QUEUED"}
        )
        await r.expire(job_key(sid), JOB_TTL_S)
    except Exception:
        await r.delete(lock_key(canonical))
        raise

    try:
        dispatch(sid, target.model_dump(), options.model_dump())
    except Exception:
        log.exception("could not enqueue scan %s", sid)
        scan.status = ScanStatus.FAILED
        scan.error_message = "Task queue unavailable"
        await session.commit()
        await r.delete(lock_key(canonical))
        raise QueueUnavailableError from None

    return scan
