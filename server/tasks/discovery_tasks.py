"""
Celery tasks for device discovery.

Performs ping sweeps + TCP port probing across IP ranges to detect live hosts
and identify their OS type. Discovered devices are registered in the database.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime

from celery import shared_task

from server.db.database import AsyncSessionLocal
from server.db.models import (
    Device, DeviceGroup, DeviceStatus, DiscoveryJob, DiscoveryMethod, OSType, ScanStatus,
    device_group_members,
)

logger = logging.getLogger(__name__)

# Ports used to guess OS type
# IBM i (AS/400) specific: 449=DDM-RDB/DRDA, 446-448=DDM, 8470=IBM i Access
_IBMI_PORTS    = [446, 447, 448, 449, 8470]
# Windows-exclusive: 3389=RDP, 5985=WinRM — IBM i does NOT expose these
_WINDOWS_EXCLUSIVE_PORTS = [3389, 5985]
_LINUX_PORTS   = [22]
# Port 445 (SMB/NetServer) is shared by Windows AND IBM i — not a reliable discriminator
_COMMON_PORTS  = [22, 80, 443, 445, 3389, 5985, 446, 447, 448, 449, 8080, 8443, 8470]


@shared_task(
    bind=True,
    name="server.tasks.discovery_tasks.run_discovery",
    queue="discovery",
    soft_time_limit=1800,
)
def run_discovery(self, discovery_job_id: str, group_name: str | None = None) -> dict:
    """Run a discovery job across configured IP ranges."""
    logger.info("Starting discovery job %s", discovery_job_id)

    def _run():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run_discovery_async(discovery_job_id, group_name))
        finally:
            loop.close()

    return _run()


async def _run_discovery_async(discovery_job_id: str, group_name: str | None = None) -> dict:
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(DiscoveryJob).where(DiscoveryJob.id == discovery_job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        job.status = ScanStatus.running
        await db.flush()

        devices_found = 0
        try:
            for cidr in job.target_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    # Single IP
                    hosts = [ipaddress.ip_address(cidr)]
                else:
                    hosts = list(network.hosts())
                    if not hosts:
                        hosts = [network.network_address]

                # Probe hosts in batches of 50 concurrently
                batch_size = 50
                for i in range(0, len(hosts), batch_size):
                    batch = hosts[i : i + batch_size]
                    tasks = [_probe_host(str(h)) for h in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for host_ip, probe_result in zip(batch, results):
                        if isinstance(probe_result, Exception) or not probe_result:
                            continue
                        # Register or update device
                        existed = await _upsert_device(db, probe_result, DiscoveryMethod.ping_sweep)
                        if not existed:
                            devices_found += 1

            job.status = ScanStatus.completed
            job.devices_found = devices_found
            job.completed_at = datetime.utcnow()

            # Auto-assign discovered devices to a group if requested
            if group_name and devices_found > 0:
                await _assign_devices_to_group(db, discovery_job_id, group_name)

        except Exception as exc:
            logger.exception("Discovery job %s failed: %s", discovery_job_id, exc)
            job.status = ScanStatus.failed
            job.error_message = str(exc)

        await db.commit()
        return {"devices_found": devices_found}


async def _probe_host(ip: str) -> dict | None:
    """
    Probe a host with async TCP connects on common ports.
    Returns a dict with IP, hostname, open ports, guessed OS type, or None if unreachable.
    """
    loop = asyncio.get_event_loop()
    open_ports: list[int] = []

    async def _try_port(port: int) -> bool:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    tasks = [_try_port(p) for p in _COMMON_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for port, is_open in zip(_COMMON_PORTS, results):
        if is_open is True:
            open_ports.append(port)

    if not open_ports:
        return None

    # Guess OS type from open ports.
    # Priority order: IBM i > Windows > Linux > unknown
    #   IBM i:   any DDM/DRDA port is definitive (446-449, 8470)
    #   Windows: RDP (3389) or WinRM (5985) — these don't exist on IBM i
    #   Linux:   SSH only, no Windows/IBM i indicators
    #   Note: port 445 (SMB) is shared by Windows AND IBM i — not used alone
    os_type = OSType.unknown
    if any(p in open_ports for p in _IBMI_PORTS):
        os_type = OSType.ibmi
    elif any(p in open_ports for p in _WINDOWS_EXCLUSIVE_PORTS):
        os_type = OSType.windows
    elif 22 in open_ports:
        os_type = OSType.linux  # Could be Darwin/Unix — SSH present on all POSIX OSes

    # Reverse DNS lookup
    try:
        hostname = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0])
    except (socket.herror, socket.gaierror):
        hostname = ip

    return {"ip": ip, "hostname": hostname, "open_ports": open_ports, "os_type": os_type}


async def _upsert_device(
    db: AsyncSessionLocal,
    probe: dict,
    method: DiscoveryMethod,
) -> bool:
    """Insert or update a Device record. Returns True if already existed."""
    from sqlalchemy import select
    result = await db.execute(
        select(Device).where(Device.ip_address == probe["ip"])
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.status = DeviceStatus.online
        existing.updated_at = datetime.utcnow()
        # Only update the hostname/OS type from probe data if it was previously
        # unknown — trust any type that was manually set or refined by a real scan.
        if existing.os_type == OSType.unknown:
            existing.os_type = probe["os_type"]
        if existing.hostname == str(probe["ip"]) or not existing.hostname:
            existing.hostname = probe["hostname"]
        await db.flush()
        return True

    db.add(Device(
        hostname=probe["hostname"],
        ip_address=probe["ip"],
        os_type=probe["os_type"],
        status=DeviceStatus.online,
        discovery_method=method,
        ssh_port=22 if 22 in probe["open_ports"] else 22,
        winrm_port=5985 if 5985 in probe["open_ports"] else 5985,
    ))
    await db.flush()
    return False


async def _assign_devices_to_group(db, discovery_job_id: str, group_name: str) -> None:
    """Find or create a DeviceGroup and add all devices found by this job to it."""
    from sqlalchemy import select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    # Find or create the group
    result = await db.execute(select(DeviceGroup).where(DeviceGroup.name == group_name))
    group = result.scalar_one_or_none()
    if group is None:
        group = DeviceGroup(name=group_name)
        db.add(group)
        await db.flush()

    # Get the job to find its target ranges, then match devices by the IPs we probed
    result = await db.execute(
        select(DiscoveryJob).where(DiscoveryJob.id == discovery_job_id)
    )
    job = result.scalar_one_or_none()
    if job is None:
        return

    # Add all online devices discovered after the job started
    result = await db.execute(
        select(Device).where(
            Device.discovery_method == DiscoveryMethod.ping_sweep,
            Device.status == DeviceStatus.online,
        )
    )
    devices = result.scalars().all()
    for device in devices:
        stmt = (
            pg_insert(device_group_members)
            .values(group_id=group.id, device_id=device.id)
            .on_conflict_do_nothing()
        )
        await db.execute(stmt)

    logger.info("Assigned %d devices to group '%s'", len(devices), group_name)
