"""Service-level fixtures: SQLite (migrated with Alembic) + fakeredis + the real Celery task.

No Docker needed. Set VIBEGUARD_TEST_DATABASE_URL to a PostgreSQL URL to run the same suite
against the docker-compose database instead.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import pytest
from alembic import command
from alembic.config import Config

from tests.auth_helpers import ALLOWED_EMAIL, PROJECT_ID, bearer, verifier
from tests.conftest import HALLUCINATED, FakeProvider, registry_transport
from vibeguard.api.auth import get_verifier
from vibeguard.api.deps import get_dispatcher, get_redis
from vibeguard.api.main import create_app
from vibeguard.config import Settings, get_settings
from vibeguard.db.session import (
    async_engine,
    async_session_factory,
    sync_engine,
    sync_session_factory,
)
from vibeguard.engine.llm.schemas import LLMFinding
from vibeguard.worker.tasks import WorkerDeps, run_scan_task, set_worker_deps

BACKEND = Path(__file__).resolve().parents[2]


def idor_finding() -> LLMFinding:
    return LLMFinding(
        title="IDOR On User Fetch",
        severity="CRITICAL",
        category="Broken Access Control",
        cwe_id="CWE-639",
        file_path="app/api/user/[id]/route.ts",
        line_start=5,
        line_end=5,
        vulnerable_code="const user = await prisma.user.findUnique({ where: { id: params.id } });",
        suggested_patch=(
            "  const session = await auth();\n"
            "  if (session?.user?.id !== params.id) return new Response(null, { status: 403 });\n"
            "  const user = await prisma.user.findUnique({ where: { id: params.id } });"
        ),
        description="Anyone can read any user. The URL id is never checked against the session.",
    )


def migrate(url: str, reset: bool = False) -> None:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.attributes["url"] = url
    if reset:
        # A shared PostgreSQL database: start every test from an empty schema. Going through
        # the migrations also exercises downgrade (including enum type drops) on real Postgres.
        command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@dataclass
class Service:
    client: httpx.AsyncClient
    settings: Settings
    redis: fakeredis.FakeRedis
    jobs: list[tuple[str, dict[str, Any], dict[str, Any]]] = field(default_factory=list)
    fail_dispatch: bool = False

    async def run_jobs(self) -> None:
        """Execute queued jobs through the real Celery task, off the event loop like a worker."""
        while self.jobs:
            job = self.jobs.pop(0)
            await asyncio.to_thread(run_scan_task.apply, args=job)


@pytest.fixture
def db_url(tmp_path) -> str:
    shared = os.environ.get("VIBEGUARD_TEST_DATABASE_URL")
    url = shared or f"sqlite:///{tmp_path.as_posix()}/vg.db"
    migrate(url, reset=bool(shared))
    yield url
    # Engines are cached per URL; a shared URL must not reuse pools across event loops
    sync_engine(url).dispose()
    sync_engine.cache_clear()
    async_engine.cache_clear()


@pytest.fixture
async def service(db_url, demo_app):
    settings = Settings(
        _env_file=None,
        database_url=db_url,
        llm_provider="none",
        allow_local_paths=True,
        local_scan_root=demo_app.parent,
        # Auth is ON for every service test: requests carry a token minted by tests.auth_helpers
        firebase_project_id=PROJECT_ID,
        auth_allowed_emails=[ALLOWED_EMAIL],
    )
    server = fakeredis.FakeServer()
    sync_redis = fakeredis.FakeRedis(server=server)
    async_redis = fakeredis.FakeAsyncRedis(server=server)

    set_worker_deps(
        WorkerDeps(
            settings=settings,
            session_factory=sync_session_factory(db_url),
            redis=sync_redis,
            provider=FakeProvider([idor_finding()]),
            registry_transport=registry_transport({HALLUCINATED}),
        )
    )

    app = create_app()
    svc: Service

    async def _session():
        async with async_session_factory(db_url)() as s:
            yield s

    def _dispatcher():
        def dispatch(scan_id, target, options):
            if svc.fail_dispatch:
                raise ConnectionError("broker down")
            svc.jobs.append((scan_id, target, options))

        return dispatch

    from vibeguard.db.session import get_session

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_redis] = lambda: async_redis
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_dispatcher] = _dispatcher
    app.dependency_overrides[get_verifier] = verifier

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=bearer()
    ) as client:
        svc = Service(client=client, settings=settings, redis=sync_redis)
        yield svc

    set_worker_deps(None)
    await async_engine(db_url).dispose()
