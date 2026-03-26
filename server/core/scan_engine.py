"""
Scan engine — orchestrates agentless and agent-based scans.

Responsibilities:
  1. Resolve credentials via CredentialManager
  2. Connect to target via appropriate transport (SSH / WinRM / Agent HTTP)
  3. Run OS-specific collectors
  4. Parse collected data
  5. Correlate packages/services against vulnerability DB (NVD/OSV)
  6. Write findings to PostgreSQL
  7. Report progress back to the ScanTarget record

This module contains the core business logic. Celery tasks in
server/tasks/scan_tasks.py call into this module.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from server.config import settings
from server.core.credentials import CredentialManager, CredentialNotFoundError
from server.core.enrichment import VulnerabilityEnrichmentService
from server.core.transport import SSHTransport, WinRMTransport, TransportError
from server.core.parsers import (
    LinuxParser, WindowsParser, DarwinParser, UnixParser,
    ParsedPackage, ParsedOSInfo,
)
from server.db.models import (
    Device, Finding, FindingStatus, FindingType,
    Package, ScanJob, ScanStatus, ScanTarget, Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity from CVSS helpers
# ---------------------------------------------------------------------------

def _severity_for_score(cvss: Optional[float], epss: Optional[float]) -> Severity:
    """Compute effective severity, boosting based on EPSS if critical probability."""
    if cvss is None:
        return Severity.unknown
    if cvss >= 9.0:
        return Severity.critical
    if cvss >= 7.0:
        # Boost to critical if EPSS says exploitation is very likely
        if epss and epss >= 0.9:
            return Severity.critical
        return Severity.high
    if cvss >= 4.0:
        return Severity.medium
    if cvss > 0.0:
        return Severity.low
    return Severity.none


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------

_PARSERS = {
    "linux":   LinuxParser(),
    "windows": WindowsParser(),
    "darwin":  DarwinParser(),
    "unix":    UnixParser(),
}


# ---------------------------------------------------------------------------
# Agent HTTP client (for agent-based scans)
# ---------------------------------------------------------------------------

class AgentClient:
    """Communicates with the Go scanner agent deployed on a target host."""

    def __init__(self, endpoint: str, token: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=endpoint,
            headers={"Authorization": f"Bearer {token}"},
            timeout=120.0,
            verify=False,  # Agent uses self-signed cert; verify via token auth
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def collect_packages(self) -> dict[str, Any]:
        resp = await self._client.post("/api/v1/collect/packages")
        resp.raise_for_status()
        return resp.json()

    async def collect_os_info(self) -> dict[str, Any]:
        resp = await self._client.post("/api/v1/collect/osinfo")
        resp.raise_for_status()
        return resp.json()

    async def run_benchmark(self, benchmark_id: str) -> dict[str, Any]:
        resp = await self._client.post("/api/v1/benchmark/run", json={"benchmark_id": benchmark_id})
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

class ScanEngine:
    def __init__(self) -> None:
        self.cred_manager = CredentialManager()
        self.enrichment = VulnerabilityEnrichmentService()

    async def close(self) -> None:
        await self.cred_manager.close()
        await self.enrichment.close()

    async def scan_device(
        self,
        db: AsyncSession,
        scan_target_id: str,
        override_username: Optional[str] = None,
        override_password: Optional[str] = None,
    ) -> None:
        """
        Main entry point for scanning a single device.
        Called from Celery task or directly from API for immediate scans.
        """
        # Load scan target and device
        result = await db.execute(
            select(ScanTarget).where(ScanTarget.id == scan_target_id)
        )
        target = result.scalar_one_or_none()
        if target is None:
            logger.error("ScanTarget %s not found", scan_target_id)
            return

        result = await db.execute(select(Device).where(Device.id == target.device_id))
        device = result.scalar_one_or_none()
        if device is None:
            logger.error("Device %s not found for scan target %s", target.device_id, scan_target_id)
            return

        result = await db.execute(select(ScanJob).where(ScanJob.id == target.scan_job_id))
        scan_job = result.scalar_one_or_none()

        # Update status to running
        target.status = ScanStatus.running
        target.started_at = datetime.utcnow()
        await db.flush()

        try:
            if device.agent_installed and device.agent_endpoint:
                await self._scan_via_agent(db, device, target, scan_job)
            else:
                await self._scan_agentless(
                    db, device, target, scan_job,
                    override_username=override_username,
                    override_password=override_password,
                )

            target.status = ScanStatus.completed
            target.completed_at = datetime.utcnow()
            device.last_scanned_at = datetime.utcnow()

        except CredentialNotFoundError as exc:
            logger.warning("No credentials for %s: %s", device.hostname, exc)
            target.status = ScanStatus.failed
            target.error_message = f"Credential error: {exc}"
        except TransportError as exc:
            logger.warning("Transport error for %s: %s", device.hostname, exc)
            target.status = ScanStatus.failed
            target.error_message = f"Connection error: {exc}"
        except Exception as exc:
            logger.exception("Unexpected error scanning %s", device.hostname)
            target.status = ScanStatus.failed
            target.error_message = f"Unexpected error: {exc}"
        finally:
            await db.flush()
            await self._update_job_progress(db, target.scan_job_id)

    async def _update_job_progress(self, db: AsyncSession, scan_job_id: str) -> None:
        """Recount completed/failed targets and update ScanJob."""
        result = await db.execute(
            select(ScanTarget).where(ScanTarget.scan_job_id == scan_job_id)
        )
        targets = result.scalars().all()
        completed = sum(1 for t in targets if t.status == ScanStatus.completed)
        failed = sum(1 for t in targets if t.status == ScanStatus.failed)
        total = len(targets)
        all_done = all(
            t.status in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled)
            for t in targets
        )
        await db.execute(
            update(ScanJob)
            .where(ScanJob.id == scan_job_id)
            .values(
                completed_devices=completed,
                failed_devices=failed,
                total_devices=total,
                status=ScanStatus.completed if all_done else ScanStatus.running,
                completed_at=datetime.utcnow() if all_done else None,
            )
        )

    async def _scan_agentless(
        self,
        db: AsyncSession,
        device: Device,
        target: ScanTarget,
        scan_job: Optional[ScanJob],
        override_username: Optional[str] = None,
        override_password: Optional[str] = None,
    ) -> None:
        """Run agentless scan via SSH or WinRM."""
        ip_address = str(device.ip_address)
        creds = await self.cred_manager.get_credentials(
            hostname=device.hostname,
            ip_address=ip_address,
            credential_ref=device.credential_ref,
            os_type=device.os_type.value if device.os_type else "linux",
            override_username=override_username,
            override_password=override_password,
        )

        os_type = device.os_type.value if device.os_type else "linux"
        parser = _PARSERS.get(os_type, _PARSERS["linux"])

        if os_type == "windows":
            transport = WinRMTransport(
                host=ip_address,
                port=device.winrm_port,
                username=creds.username,
                password=creds.password or "",
                use_ssl=device.winrm_use_ssl,
                auth_method=creds.winrm_auth_type,
                connect_timeout=settings.SCAN_TIMEOUT,
            )
        else:
            transport = SSHTransport(
                host=ip_address,
                port=device.ssh_port,
                username=creds.username,
                password=creds.password,
                private_key=creds.ssh_key,
                key_passphrase=creds.ssh_key_passphrase,
                connect_timeout=settings.SCAN_TIMEOUT,
            )

        async with transport:
            # 1. Collect OS info + update device record
            os_info = await self._collect_os_info(transport, parser, device)
            if os_info:
                await self._update_device_os_info(db, device, os_info)

            # 2. Collect packages
            scan_type = scan_job.scan_type.value if scan_job else "full"
            if scan_type in ("full", "packages", "quick"):
                packages = await self._collect_packages(transport, parser)
                await self._store_packages(db, device, target, packages)
                pkg_findings = await self.enrichment.enrich_packages(
                    db,
                    [{"name": p.name, "version": p.version, "package_manager": p.package_manager}
                     for p in packages],
                )
                await self._store_findings(db, device, target, pkg_findings)

            await db.flush()

    async def _scan_via_agent(
        self,
        db: AsyncSession,
        device: Device,
        target: ScanTarget,
        scan_job: Optional[ScanJob],
    ) -> None:
        """Run scan via the deployed Go agent."""
        agent = AgentClient(
            endpoint=device.agent_endpoint,
            token=settings.AGENT_TOKEN,
        )
        try:
            os_data = await agent.collect_os_info()
            pkg_data = await agent.collect_packages()

            packages = [
                ParsedPackage(
                    name=p["name"],
                    version=p["version"],
                    arch=p.get("arch", ""),
                    package_manager=p.get("package_manager", ""),
                    vendor=p.get("vendor", ""),
                    cpe=p.get("cpe", ""),
                )
                for p in pkg_data.get("packages", [])
            ]
            await self._store_packages(db, device, target, packages)
            pkg_findings = await self.enrichment.enrich_packages(
                db,
                [{"name": p.name, "version": p.version, "package_manager": p.package_manager}
                 for p in packages],
            )
            await self._store_findings(db, device, target, pkg_findings)
        finally:
            await agent.close()

    async def _collect_os_info(
        self,
        transport: Any,
        parser: Any,
        device: Device,
    ) -> Optional[ParsedOSInfo]:
        commands = parser.os_info_commands()
        outputs: dict[str, str] = {}
        for cmd in commands:
            try:
                result = await transport.run(cmd, timeout=30)
                outputs[cmd] = result.stdout
            except TransportError as exc:
                logger.debug("OS info command failed on %s: %s", device.hostname, exc)
        return parser.parse_os_info(outputs) if outputs else None

    async def _collect_packages(self, transport: Any, parser: Any) -> list[ParsedPackage]:
        commands = parser.package_commands()
        outputs: dict[str, str] = {}
        # Run package collection commands concurrently
        async def run_cmd(cmd: str) -> tuple[str, str]:
            try:
                result = await transport.run(cmd, timeout=120)
                return cmd, result.stdout
            except TransportError:
                return cmd, ""

        results = await asyncio.gather(*[run_cmd(cmd) for cmd in commands])
        outputs = dict(results)
        return parser.parse_packages(outputs)

    async def _update_device_os_info(
        self,
        db: AsyncSession,
        device: Device,
        info: ParsedOSInfo,
    ) -> None:
        if info.os_name:
            device.os_name = info.os_name
        if info.os_version:
            device.os_version = info.os_version
        if info.os_build:
            device.os_build = info.os_build
        if info.architecture:
            device.architecture = info.architecture
        if info.kernel_version:
            device.kernel_version = info.kernel_version
        from server.db.models import DeviceStatus
        device.status = DeviceStatus.online
        await db.flush()

    async def _store_packages(
        self,
        db: AsyncSession,
        device: Device,
        target: ScanTarget,
        packages: list[ParsedPackage],
    ) -> None:
        for pkg in packages:
            db.add(Package(
                device_id=device.id,
                scan_target_id=target.id,
                name=pkg.name,
                version=pkg.version,
                arch=pkg.arch,
                package_manager=pkg.package_manager,
                vendor=pkg.vendor,
                cpe=pkg.cpe or None,
            ))
        await db.flush()

    async def _store_findings(
        self,
        db: AsyncSession,
        device: Device,
        target: ScanTarget,
        raw_findings: list[dict[str, Any]],
    ) -> None:
        if not raw_findings:
            return

        cve_ids = [f["vulnerability_id"] for f in raw_findings]
        await self.enrichment.attach_epss_scores(db, cve_ids)

        from sqlalchemy import select as sa_select
        from server.db.models import EPSSScore, Vulnerability as VulnModel

        for finding_data in raw_findings:
            vuln_id = finding_data["vulnerability_id"]

            # Get EPSS score if available
            epss_result = await db.execute(
                sa_select(EPSSScore).where(EPSSScore.cve_id == vuln_id)
            )
            epss = epss_result.scalar_one_or_none()

            vuln_result = await db.execute(
                sa_select(VulnModel).where(VulnModel.id == vuln_id)
            )
            vuln = vuln_result.scalar_one_or_none()

            epss_score = epss.epss_score if epss else None
            epss_pct = epss.percentile if epss else None
            cvss = vuln.cvss_v3_score if vuln else None
            severity = (
                _severity_for_score(cvss, epss_score)
                if vuln else Severity.unknown
            )

            # Upsert finding (may already exist from a prior scan)
            existing_result = await db.execute(
                sa_select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.vulnerability_id == vuln_id,
                    Finding.affected_component == finding_data.get("package_name", ""),
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                existing.last_seen = datetime.utcnow()
                existing.epss_score = epss_score
                existing.epss_percentile = epss_pct
                existing.cvss_score = cvss
                existing.severity = severity
            else:
                db.add(Finding(
                    device_id=device.id,
                    scan_target_id=target.id,
                    vulnerability_id=vuln_id,
                    finding_type=FindingType.package,
                    status=FindingStatus.open,
                    severity=severity,
                    affected_component=finding_data.get("package_name", ""),
                    affected_version=finding_data.get("version", ""),
                    epss_score=epss_score,
                    epss_percentile=epss_pct,
                    cvss_score=cvss,
                ))

        await db.flush()
