"""Celery application factory."""

from celery import Celery
from server.config import settings

celery_app = Celery(
    "claude_scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "server.tasks.scan_tasks",
        "server.tasks.discovery_tasks",
        "server.tasks.enrichment_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "server.tasks.scan_tasks.*":        {"queue": "scans"},
        "server.tasks.discovery_tasks.*":   {"queue": "discovery"},
        "server.tasks.enrichment_tasks.*":  {"queue": "enrichment"},
    },
    task_soft_time_limit=600,   # 10 minutes per task before SoftTimeLimitExceeded
    task_time_limit=900,        # 15 minutes hard kill
)
