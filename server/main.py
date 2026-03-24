"""FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from server.config import settings
from server.api.routes import auth, devices, scans, vulnerabilities, reports

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    logger.info("Starting %s v%s", settings.APP_TITLE, settings.APP_VERSION)

    # Sync benchmark definitions to DB on startup
    try:
        from server.db.database import AsyncSessionLocal
        from server.core.audit import sync_benchmarks_to_db
        async with AsyncSessionLocal() as db:
            count = await sync_benchmarks_to_db(db)
            await db.commit()
            logger.info("Synced %d benchmark checks to database", count)
    except Exception as exc:
        logger.warning("Benchmark sync failed (non-fatal): %s", exc)

    yield
    logger.info("Shutting down %s", settings.APP_TITLE)


app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description="Enterprise vulnerability scanner for fleet device management",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(scans.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "version": settings.APP_VERSION}
