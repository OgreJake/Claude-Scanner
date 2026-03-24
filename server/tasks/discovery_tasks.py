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
    Device, DeviceStatus, DiscoveryJob, DiscoveryMethod, OSType, ScanStatus,
)

logger = logging.getLogger(__name__)

# Ports used to guess OS type
_LINUX_PORTS = [22]
_WINDOWS_PORTS = [445, 3389, 5985]
_COMMON_PORTS = [22, 80, 443, 445, 3389, 5985, 8080, 8443]


@shared_task(
    bind=True,
    name="server.tasks.discovery_tasks.run_discovery",
    queue="discovery",
    soft_time_limit=1800,
)
def run_discovery(self, discovery_job_id: str) -> dict:
    """Run a discovery job across configured IP ranges."""
    logger.info("Starting discovery job %s", discovery_job_id)

    def _run():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run_discovery_async(discovery_job_id))
        finally:
            loop.close()

    return _run()


async def _run_discovery_async(discovery_job_id: str) -> dict:
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

    # Guess OS type from open ports
    os_type = OSType.unknown
    if any(p in open_ports for p in _WINDOWS_PORTS):
        os_type = OSType.windows
    elif 22 in open_ports:
        os_type = OSType.linux  # Could be Darwin/Unix, SSH is present on all

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
