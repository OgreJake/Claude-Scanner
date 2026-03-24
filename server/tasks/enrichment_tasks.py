"""Celery tasks for asynchronous vulnerability enrichment."""

from __future__ import annotations

import asyncio
import logging

from celery import shared_task

from server.db.database import AsyncSessionLocal
from server.core.enrichment import VulnerabilityEnrichmentService

logger = logging.getLogger(__name__)


@shared_task(
    name="server.tasks.enrichment_tasks.refresh_epss_scores",
    queue="enrichment",
)
def refresh_epss_scores() -> dict:
    """Refresh EPSS scores for all CVEs in the vulnerability database."""
    async def _run():
        svc = VulnerabilityEnrichmentService()
        try:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                from server.db.models import Vulnerability
                result = await db.execute(
                    select(Vulnerability.id).where(
                        Vulnerability.id.like("CVE-%")
                    )
                )
                cve_ids = [row[0] for row in result.all()]
                if cve_ids:
                    await svc.attach_epss_scores(db, cve_ids)
                    await db.commit()
                return {"refreshed": len(cve_ids)}
        finally:
            await svc.close()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()


@shared_task(
    name="server.tasks.enrichment_tasks.refresh_stale_cves",
    queue="enrichment",
)
def refresh_stale_cves(max_cves: int = 500) -> dict:
    """Re-fetch CVEs whose NVD data is older than VULN_CACHE_TTL_HOURS."""
    async def _run():
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import select
        from server.db.models import Vulnerability
        from server.config import settings

        svc = VulnerabilityEnrichmentService()
        try:
            async with AsyncSessionLocal() as db:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.VULN_CACHE_TTL_HOURS)
                result = await db.execute(
                    select(Vulnerability.id)
                    .where(
                        Vulnerability.id.like("CVE-%"),
                        Vulnerability.last_fetched_at < cutoff,
                    )
                    .limit(max_cves)
                )
                stale_ids = [row[0] for row in result.all()]
                for cve_id in stale_ids:
                    await svc.get_or_fetch_cve(db, cve_id, force_refresh=True)
                await db.commit()
                return {"refreshed": len(stale_ids)}
        finally:
            await svc.close()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()
