"""Single-process dev stack: no Docker, no Postgres, no Redis.

    python -m vibeguard.devserver            # http://127.0.0.1:8000

Runs the real FastAPI app with SQLite (migrated by Alembic), an in-memory Redis (fakeredis)
and the real scan task on a background thread instead of Celery. Local-path scans are enabled
under the current directory. Never use this in production.
"""

from __future__ import annotations

import argparse
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import fakeredis
import uvicorn
from alembic import command
from alembic.config import Config

from vibeguard.api.deps import get_dispatcher, get_redis
from vibeguard.api.main import create_app
from vibeguard.config import Settings, get_settings
from vibeguard.db.session import async_session_factory, get_session, sync_session_factory
from vibeguard.worker.tasks import WorkerDeps, run_scan_task, set_worker_deps

BACKEND = Path(__file__).resolve().parents[1]
log = logging.getLogger("vibeguard.devserver")


def build_app(root: Path):
    db_url = (
        os.environ.get("VIBEGUARD_DATABASE_URL")
        or f"sqlite:///{(BACKEND / '.dev' / 'vibeguard.db').as_posix()}"
    )
    if db_url.startswith("sqlite:///"):
        Path(db_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.attributes["url"] = db_url
    command.upgrade(cfg, "head")

    configured = Settings()
    settings = Settings(
        database_url=db_url,
        allow_local_paths=True,
        local_scan_root=root.resolve(),
        # No Firebase project configured -> run open, for local hacking only
        auth_disabled=configured.firebase_project_id is None,
    )
    server = fakeredis.FakeServer()
    set_worker_deps(
        WorkerDeps(
            settings=settings,
            session_factory=sync_session_factory(db_url),
            redis=fakeredis.FakeRedis(server=server),
        )
    )
    async_redis = fakeredis.FakeAsyncRedis(server=server)
    pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")

    def dispatcher():
        def dispatch(scan_id, target, options):
            pool.submit(run_scan_task.apply, args=(scan_id, target, options))

        return dispatch

    async def session():
        async with async_session_factory(db_url)() as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = session
    app.dependency_overrides[get_redis] = lambda: async_redis
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_dispatcher] = dispatcher
    return app, settings


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Allowed local scan root")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    app, settings = build_app(args.root)
    log.info("database: %s", settings.database_url)
    log.info("local scans allowed under: %s", settings.local_scan_root)
    log.info("LLM provider: %s (%s)", settings.llm_provider, settings.resolved_llm_model)
    if settings.auth_disabled:
        log.warning(
            "AUTH DISABLED: no VIBEGUARD_FIREBASE_PROJECT_ID set, every request acts as dev@localhost. "
            "Local use only."
        )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
