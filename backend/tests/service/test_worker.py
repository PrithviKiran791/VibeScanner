import contextlib
import uuid

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import create_engine, func, select

from vibeguard.db.models import Base, Finding, Scan, ScanStatus
from vibeguard.db.session import sync_session_factory, sync_url
from vibeguard.engine.ingest.workspace import Workspace
from vibeguard.worker import tasks
from vibeguard.worker.contracts import ScanOptions, TargetSource


async def _queued(service, demo_app) -> str:
    resp = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    return resp.json()["id"]


def test_migration_matches_models(db_url):
    engine = create_engine(sync_url(db_url))
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


async def test_redelivered_job_is_a_noop(service, demo_app):
    sid = await _queued(service, demo_app)
    job = service.jobs[0]
    await service.run_jobs()
    service.jobs.append(job)  # acks_late redelivery after a crash
    await service.run_jobs()

    with sync_session_factory(service.settings.database_url)() as s:
        count = s.scalar(select(func.count()).where(Finding.scan_id == uuid.UUID(sid)))
    assert count == 7


async def test_soft_time_limit_fails_cleanly(service, demo_app, monkeypatch):
    sid = await _queued(service, demo_app)

    def slow(*_a, **_kw):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(tasks, "run_scan", slow)
    await service.run_jobs()
    scan = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    assert scan["status"] == "FAILED" and "time limit" in scan["error_message"]


async def test_github_target_goes_through_cloning(service, demo_app, monkeypatch):
    seen: dict = {}

    @contextlib.contextmanager
    def fake_clone(url, token=None, timeout_s=30, max_bytes=None):
        seen.update(url=url, timeout_s=timeout_s, max_bytes=max_bytes)
        with sync_session_factory(service.settings.database_url)() as s:
            seen["status_during_clone"] = s.scalars(select(Scan.status)).all()
        yield Workspace(root=demo_app, target="acme/vibe-app", commit_hash="a" * 40)

    monkeypatch.setattr(tasks, "github_workspace", fake_clone)
    resp = await service.client.post(
        "/api/v1/scans",
        json={"repo_url": "https://github.com/Acme/Vibe-App", "options": {"llm": False}},
    )
    sid = resp.json()["id"]
    assert resp.json()["source_type"] == "GITHUB"
    assert resp.json()["target"] == "https://github.com/acme/vibe-app"
    await service.run_jobs()

    assert seen["status_during_clone"] == [ScanStatus.CLONING]
    assert seen["timeout_s"] == service.settings.clone_timeout_s
    assert seen["max_bytes"] == service.settings.max_clone_bytes
    scan = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    assert scan["status"] == "COMPLETED" and scan["commit_hash"] == "a" * 40
    assert scan["llm_used"] is False and scan["counts"]["total"] == 6


def test_missing_scan_is_dropped(service):
    tasks.execute_scan(
        uuid.uuid4(),
        TargetSource(kind="local", path="."),
        ScanOptions(),
        tasks.get_worker_deps(),
    )
