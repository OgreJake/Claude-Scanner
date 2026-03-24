"""
Celery tasks for background scan execution.

Each task runs a single device scan. Parallelism is achieved by dispatching
one task per ScanTarget at job creation time.
"""

from __future__ import annotations

import asyncio
import logging

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded

from server.db.database import AsyncSessionLocal
from server.db.models import ScanStatus, ScanTarget
from server.core.scan_engine import ScanEngine

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(
    bind=True,
    name="server.tasks.scan_tasks.scan_device",
    max_retries=2,
    default_retry_delay=30,
    queue="scans",
)
def scan_device(
    self,
    scan_target_id: str,
    override_username: str | None = None,
    override_password: str | None = None,
) -> dict:
    """Scan a single device (one ScanTarget)."""
    logger.info("Starting device scan: scan_target_id=%s", scan_target_id)
    try:
        _run_async(_scan_device_async(
            scan_target_id,
            override_username=override_username,
            override_password=override_password,
        ))
        return {"status": "completed", "scan_target_id": scan_target_id}
    except SoftTimeLimitExceeded:
        logger.warning("Scan timed out for target %s", scan_target_id)
        _run_async(_mark_target_failed(scan_target_id, "Scan timed out"))
        return {"status": "timeout", "scan_target_id": scan_target_id}
    except Exception as exc:
        logger.exception("Scan failed for target %s: %s", scan_target_id, exc)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            _run_async(_mark_target_failed(scan_target_id, str(exc)))
            return {"status": "failed", "scan_target_id": scan_target_id}


async def _scan_device_async(
    scan_target_id: str,
    override_username: str | None = None,
    override_password: str | None = None,
) -> None:
    engine = ScanEngine()
    try:
        async with AsyncSessionLocal() as db:
            await engine.scan_device(
                db=db,
                scan_target_id=scan_target_id,
                override_username=override_username,
                override_password=override_password,
            )
            await db.commit()
    finally:
        await engine.close()


async def _mark_target_failed(scan_target_id: str, error: str) -> None:
    from datetime import datetime
    async with AsyncSessionLocal() as db:
        from sqlalchemy import update
        await db.execute(
            update(ScanTarget)
            .where(ScanTarget.id == scan_target_id)
            .values(
                status=ScanStatus.failed,
                error_message=error,
                completed_at=datetime.utcnow(),
            )
        )
        await db.commit()
