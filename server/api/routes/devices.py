"""Device management routes — CRUD, bulk import, credential assignment."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, IPvAnyAddress, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from server.api.deps import CurrentUser, DBSession
from server.db.models import Device, DeviceStatus, DiscoveryMethod, OSType

router = APIRouter(prefix="/devices", tags=["devices"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: OSType = OSType.unknown
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    ssh_port: int = 22
    winrm_port: int = 5985
    winrm_use_ssl: bool = False
    credential_ref: Optional[str] = None
    agent_endpoint: Optional[str] = None
    tags: dict[str, Any] = {}
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[OSType] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    ssh_port: Optional[int] = None
    winrm_port: Optional[int] = None
    winrm_use_ssl: Optional[bool] = None
    credential_ref: Optional[str] = None
    agent_endpoint: Optional[str] = None
    tags: Optional[dict[str, Any]] = None
    notes: Optional[str] = None


class DeviceResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str
    os_name: Optional[str]
    os_version: Optional[str]
    architecture: Optional[str]
    kernel_version: Optional[str]
    ssh_port: int
    winrm_port: int
    credential_ref: Optional[str]
    agent_installed: bool
    agent_version: Optional[str]
    agent_last_seen: Optional[datetime]
    tags: dict
    status: str
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_scanned_at: Optional[datetime]
    open_finding_count: Optional[int] = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def _coerce_ip(cls, v: object) -> str:
        return str(v)

    class Config:
        from_attributes = True


class DeviceListResponse(BaseModel):
    items: list[DeviceResponse]
    total: int
    page: int
    page_size: int


class BulkImportRow(BaseModel):
    hostname: str
    ip_address: str
    os_type: str = "unknown"
    credential_ref: Optional[str] = None
    tags: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=DeviceListResponse)
async def list_devices(
    db: DBSession,
    current_user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    os_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
) -> DeviceListResponse:
    q = select(Device)
    if os_type:
        q = q.where(Device.os_type == os_type)
    if status_filter:
        q = q.where(Device.status == status_filter)
    if search:
        q = q.where(
            Device.hostname.ilike(f"%{search}%")
            | Device.ip_address.cast(str).ilike(f"%{search}%")
        )

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size).order_by(Device.hostname)
    result = await db.execute(q)
    devices = result.scalars().all()
    return DeviceListResponse(items=devices, total=total, page=page, page_size=page_size)


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    db: DBSession,
    current_user: CurrentUser,
) -> Device:
    # Check for duplicate
    result = await db.execute(
        select(Device).where(
            (Device.hostname == payload.hostname) | (Device.ip_address == payload.ip_address)
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device with this hostname or IP already exists")

    device = Device(**payload.model_dump())
    db.add(device)
    await db.flush()
    return device


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: str, db: DBSession, current_user: CurrentUser) -> Device:
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str,
    payload: DeviceUpdate,
    db: DBSession,
    current_user: CurrentUser,
) -> Device:
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(device, field, value)
    device.updated_at = datetime.utcnow()
    await db.flush()
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: str,
    db: DBSession,
    current_user: CurrentUser,
) -> None:
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    await db.delete(device)


@router.post("/bulk-import", status_code=status.HTTP_200_OK)
async def bulk_import_devices(
    rows: list[BulkImportRow],
    db: DBSession,
    current_user: CurrentUser,
) -> dict:
    """Import a list of devices. Skips duplicates by IP address."""
    created = 0
    skipped = 0
    for row in rows:
        result = await db.execute(select(Device).where(Device.ip_address == row.ip_address))
        if result.scalar_one_or_none():
            skipped += 1
            continue
        os_type_val = OSType.unknown
        try:
            os_type_val = OSType(row.os_type.lower())
        except ValueError:
            pass
        db.add(Device(
            hostname=row.hostname,
            ip_address=row.ip_address,
            os_type=os_type_val,
            credential_ref=row.credential_ref,
            tags=row.tags,
            discovery_method=DiscoveryMethod.import_csv,
        ))
        created += 1

    await db.flush()
    return {"created": created, "skipped": skipped}
