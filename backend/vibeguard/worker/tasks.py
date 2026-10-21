"""`run_scan_task`: clone -> Phase 1 engine -> PostgreSQL, with live progress in Redis."""

from __future__ import annotations

import logging
import os
import socket
import time
import uuid
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
import redis
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.orm import Session, sessionmaker

from vibeguard.config import Settings, get_settings
from vibeguard.db.models import Scan, ScanStatus
from vibeguard.db.persist import persist_result
from vibeguard.db.session import sync_session_factory
from vibeguard.engine.ingest.file_index import RepoTooLargeError
from vibeguard.engine.ingest.workspace import (
    IngestError,
    Workspace,
    github_workspace,
    local_workspace,
)
from vibeguard.engine.llm.provider import LLMProvider
from vibeguard.engine.pipeline import run_scan
from vibeguard.worker.celery_app import SOFT_TIME_LIMIT_S, celery_app
from vibeguard.worker.contracts import ScanOptions, TargetSource, resolve_local_path
from vibeguard.worker.state import ProgressReporter, RedisExistenceCache, release_lock

log = logging.getLogger(__name__)

# Engine stages -> coarse DB status (the fine-grained stage lives in the Redis hash)
STAGE_STATUS = {
    "INDEXING": ScanStatus.ANALYZING_STATIC,
    "ANALYZING_STATIC": ScanStatus.ANALYZING_STATIC,
    "PRUNING": ScanStatus.ANALYZING_STATIC,
    "ANALYZING_LLM": ScanStatus.ANALYZING_LLM,
}
DEADLINE_HEADROOM_S = 5.0


@dataclass
class WorkerDeps:
    settings: Settings
    session_factory: sessionmaker[Session]
    redis: redis.Redis
    provider: LLMProvider | None | Literal["auto"] = "auto"
    registry_transport: httpx.AsyncBaseTransport | None = None


_deps: WorkerDeps | None = None


def get_worker_deps() -> WorkerDeps:
    global _deps
    if _deps is None:
        settings = get_settings()
        _deps = WorkerDeps(
            settings=settings,
            session_factory=sync_session_factory(),
            redis=redis.Redis.from_url(settings.redis_url),
        )
    return _deps


def set_worker_deps(deps: WorkerDeps | None) -> None:
    """Test hook."""
    global _deps
    _deps = deps


@celery_app.task(name="vibeguard.run_scan")
def run_scan_task(scan_id: str, target_source: dict[str, Any], options: dict[str, Any]) -> None:
    execute_scan(
        uuid.UUID(scan_id),
        TargetSource.model_validate(target_source),
        ScanOptions.model_validate(options),
        get_worker_deps(),
    )


def execute_scan(
    scan_id: uuid.UUID, target: TargetSource, options: ScanOptions, deps: WorkerDeps
) -> None:
    started = time.monotonic()
    sid = str(scan_id)
    progress = ProgressReporter(deps.redis, sid, worker_id=f"{socket.gethostname()}:{os.getpid()}")

    with deps.session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            log.error("scan %s not found; dropping job", sid)
            return
        if scan.status.terminal:
            return  # redelivered after completion (acks_late): nothing to do

    try:
        with _open_workspace(target, deps, scan_id, progress) as ws:
            remaining = SOFT_TIME_LIMIT_S - (time.monotonic() - started) - DEADLINE_HEADROOM_S
            engine_settings = deps.settings.model_copy(
                update={
                    "scan_deadline_s": max(1.0, min(deps.settings.scan_deadline_s, remaining)),
                    "registry_check": deps.settings.registry_check and options.registry,
                    "llm_provider": deps.settings.llm_provider if options.llm else "none",
                }
            )
            result = run_scan(
                ws,
                engine_settings,
                provider=deps.provider if options.llm else None,
                progress=_progress_cb(deps, scan_id, progress),
                registry_cache=RedisExistenceCache(deps.redis),
                registry_transport=deps.registry_transport,
            )

        with deps.session_factory() as session, session.begin():
            scan = session.get(Scan, scan_id)
            session.add_all(persist_result(scan, result))
            score = scan.hardening_score
        progress.finish("COMPLETED", hardening_score=score)

    except SoftTimeLimitExceeded:
        _fail(deps, scan_id, progress, f"Scan exceeded the {SOFT_TIME_LIMIT_S}s time limit")
    except (IngestError, RepoTooLargeError) as exc:
        _fail(deps, scan_id, progress, str(exc))
    except Exception:
        log.exception("scan %s crashed", sid)
        _fail(deps, scan_id, progress, "Internal scanner error")
    finally:
        # The clone directory is already gone: each workspace wipes itself in its own finally.
        release_lock(deps.redis, target.canonical, sid)


def _open_workspace(
    target: TargetSource, deps: WorkerDeps, scan_id: uuid.UUID, progress: ProgressReporter
) -> AbstractContextManager[Workspace]:
    if target.kind == "github":
        _set_status(deps, scan_id, ScanStatus.CLONING)
        progress.update("CLONING", 2, ScanStatus.CLONING)
        token = deps.settings.github_token
        return github_workspace(
            target.url or "",
            token=token.get_secret_value() if token else None,
            timeout_s=deps.settings.clone_timeout_s,
            max_bytes=deps.settings.max_clone_bytes,
        )
    # Re-checked here, not just in the API: the queue is not a trust boundary
    return local_workspace(resolve_local_path(target.path or "", deps.settings))


def _progress_cb(deps: WorkerDeps, scan_id: uuid.UUID, progress: ProgressReporter):
    current: list[ScanStatus | None] = [None]

    def cb(stage: str, pct: int) -> None:
        status = STAGE_STATUS.get(stage)
        if status is not None and status != current[0]:
            _set_status(deps, scan_id, status)
            current[0] = status
        progress.update(stage, pct, current[0] or ScanStatus.ANALYZING_STATIC)

    return cb


def _set_status(deps: WorkerDeps, scan_id: uuid.UUID, status: ScanStatus) -> None:
    with deps.session_factory() as session, session.begin():
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = status


def _fail(deps: WorkerDeps, scan_id: uuid.UUID, progress: ProgressReporter, message: str) -> None:
    with deps.session_factory() as session, session.begin():
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = ScanStatus.FAILED
            scan.error_message = message
            scan.completed_at = datetime.now(UTC)
    progress.finish("FAILED", error=message)
