"""Scan job management routes — create, list, get, cancel, progress."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from server.api.deps import CurrentUser, DBSession
from server.db.models import (
    Device, DiscoveryJob, ScanJob, ScanStatus, ScanTarget, ScanType, device_group_members,
)
from server.tasks.celery_app import celery_app  # noqa: F401 — registers app as current
from server.tasks.scan_tasks import scan_device
from server.tasks.discovery_tasks import run_discovery

router = APIRouter(prefix="/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanJobCreate(BaseModel):
    name: str
    scan_type: ScanType = ScanType.full
    device_ids: list[str] = []
    group_ids: list[str] = []    # expanded server-side; merged with device_ids
    config: dict[str, Any] = {}


class ScanJobResponse(BaseModel):
    id: str
    name: str
    scan_type: str
    status: str
    total_devices: int
    completed_devices: int
    failed_devices: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: str

    class Config:
        from_attributes = True


class ScanTargetResponse(BaseModel):
    id: str
    device_id: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class ScanJobDetail(ScanJobResponse):
    targets: list[ScanTargetResponse]


class DiscoveryCreate(BaseModel):
    name: str
    target_ranges: list[str]       # ["10.0.0.0/24", "192.168.1.0/24"]
    methods: list[str] = ["tcp"]
    ports: list[int] = [22, 80, 443, 445, 3389, 5985]


class DiscoveryResponse(BaseModel):
    id: str
    name: str
    target_ranges: list[str]
    status: str
    devices_found: int
    created_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    db: DBSession,
    current_user: CurrentUser,
) -> ScanJob:
    # Expand group_ids → device_ids
    all_device_ids: set[str] = set(payload.device_ids)
    if payload.group_ids:
        rows = await db.execute(
            select(device_group_members.c.device_id).where(
                device_group_members.c.group_id.in_(payload.group_ids)
            )
        )
        all_device_ids.update(row[0] for row in rows.all())

    if not all_device_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No devices selected — provide device_ids or group_ids",
        )

    # Verify all resolved devices exist
    result = await db.execute(
        select(Device).where(Device.id.in_(all_device_ids))
    )
    devices = result.scalars().all()
    found_ids = {d.id for d in devices}
    missing = all_device_ids - found_ids
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(s) not found: {', '.join(missing)}",
        )
    resolved_ids = list(found_ids)

    job = ScanJob(
        name=payload.name,
        scan_type=payload.scan_type,
        created_by=current_user.id,
        config=payload.config,
        total_devices=len(resolved_ids),
        status=ScanStatus.pending,
    )
    db.add(job)
    await db.flush()

    # Create one ScanTarget per device and dispatch Celery tasks
    for device_id in resolved_ids:
        target = ScanTarget(
            scan_job_id=job.id,
            device_id=device_id,
            status=ScanStatus.pending,
        )
        db.add(target)
        await db.flush()

        task = scan_device.apply_async(
            kwargs={"scan_target_id": target.id},
            queue="scans",
        )
        target.celery_task_id = task.id

    job.status = ScanStatus.running
    job.started_at = datetime.utcnow()
    await db.flush()
    return job


@router.get("", response_model=list[ScanJobResponse])
async def list_scans(
    db: DBSession,
    current_user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    scan_status: Optional[str] = Query(None, alias="status"),
) -> list[ScanJob]:
    q = select(ScanJob)
    if scan_status:
        q = q.where(ScanJob.status == scan_status)
    q = q.order_by(ScanJob.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanJobDetail)
async def get_scan(scan_id: str, db: DBSession, current_user: CurrentUser) -> ScanJob:
    result = await db.execute(
        select(ScanJob)
        .options(selectinload(ScanJob.targets))
        .where(ScanJob.id == scan_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return job


@router.post("/{scan_id}/cancel", response_model=ScanJobResponse)
async def cancel_scan(scan_id: str, db: DBSession, current_user: CurrentUser) -> ScanJob:
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if job.status not in (ScanStatus.pending, ScanStatus.running):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan is not active")

    # Revoke pending Celery tasks
    targets_result = await db.execute(
        select(ScanTarget).where(
            ScanTarget.scan_job_id == scan_id,
            ScanTarget.status == ScanStatus.pending,
        )
    )
    for target in targets_result.scalars().all():
        if target.celery_task_id:
            celery_app.control.revoke(target.celery_task_id, terminate=False)
        target.status = ScanStatus.cancelled

    job.status = ScanStatus.cancelled
    job.completed_at = datetime.utcnow()
    await db.flush()
    return job


# ---------------------------------------------------------------------------
# Discovery routes
# ---------------------------------------------------------------------------

@router.post("/discovery", response_model=DiscoveryResponse, status_code=status.HTTP_201_CREATED)
async def create_discovery(
    payload: DiscoveryCreate,
    db: DBSession,
    current_user: CurrentUser,
) -> DiscoveryJob:
    job = DiscoveryJob(
        name=payload.name,
        target_ranges=payload.target_ranges,
        methods=payload.methods,
        ports=payload.ports,
        created_by=current_user.id,
        status=ScanStatus.pending,
    )
    db.add(job)
    await db.flush()

    task = run_discovery.apply_async(
        kwargs={"discovery_job_id": job.id},
        queue="discovery",
    )
    job.celery_task_id = task.id
    job.status = ScanStatus.running
    await db.flush()
    return job


@router.get("/discovery/{job_id}", response_model=DiscoveryResponse)
async def get_discovery(job_id: str, db: DBSession, current_user: CurrentUser) -> DiscoveryJob:
    result = await db.execute(select(DiscoveryJob).where(DiscoveryJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery job not found")
    return job
