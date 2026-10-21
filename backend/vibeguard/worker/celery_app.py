from celery import Celery

from vibeguard.config import get_settings

SOFT_TIME_LIMIT_S = 60  # PRD NFR: max 60s per job
HARD_TIME_LIMIT_S = 75  # SIGKILL backstop if the soft limit is swallowed

settings = get_settings()

celery_app = Celery("vibeguard", broker=settings.redis_url, include=["vibeguard.worker.tasks"])
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,  # results live in PostgreSQL, progress in Redis
    task_acks_late=True,  # a worker crash re-delivers the job; the task is idempotent
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # scans are heavy; don't hoard them
    task_soft_time_limit=SOFT_TIME_LIMIT_S,
    task_time_limit=HARD_TIME_LIMIT_S,
    broker_connection_retry_on_startup=True,
)
