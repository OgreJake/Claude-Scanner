"""
CIS Benchmark audit engine.

Loads benchmark definitions from YAML files in /benchmarks/<os>/<file>.yaml
and runs checks against a connected host via transport.
Results are stored in ComplianceResultRecord.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from server.core.transport.base import BaseTransport, TransportError
from server.db.models import (
    BenchmarkCheck, CheckType, ComplianceResult, ComplianceResultRecord,
    OSType, Severity,
)

logger = logging.getLogger(__name__)

BENCHMARKS_DIR = Path(__file__).parent.parent.parent / "benchmarks"


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def load_benchmarks(os_type: str) -> list[dict[str, Any]]:
    """Load all benchmark check definitions for a given OS type."""
    os_dir = BENCHMARKS_DIR / os_type
    if not os_dir.exists():
        logger.warning("No benchmark directory for OS type: %s", os_type)
        return []

    checks: list[dict[str, Any]] = []
    for yaml_file in sorted(os_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "checks" in data:
                checks.extend(data["checks"])
        except Exception as exc:
            logger.warning("Failed to load benchmark file %s: %s", yaml_file, exc)
    return checks


async def sync_benchmarks_to_db(db: AsyncSession) -> int:
    """
    Load all benchmark YAML files and upsert BenchmarkCheck records.
    Returns the number of checks synced.
    """
    from sqlalchemy import select
    count = 0
    for os_type in ("linux", "windows", "macos", "unix"):
        checks = load_benchmarks(os_type)
        for check_data in checks:
            check_id = check_data.get("id", "")
            if not check_id:
                continue

            result = await db.execute(
                select(BenchmarkCheck).where(BenchmarkCheck.id == check_id)
            )
            existing = result.scalar_one_or_none()

            severity_str = check_data.get("severity", "medium").lower()
            severity_map = {
                "critical": Severity.critical,
                "high": Severity.high,
                "medium": Severity.medium,
                "low": Severity.low,
            }
            severity = severity_map.get(severity_str, Severity.medium)

            check_type_str = check_data.get("check_type", "command").lower()
            check_type_map = {
                "command":      CheckType.command,
                "file_exists":  CheckType.file_exists,
                "file_content": CheckType.file_content,
                "registry":     CheckType.registry,
                "service":      CheckType.service,
            }
            check_type = check_type_map.get(check_type_str, CheckType.command)

            os_type_map = {
                "linux":   OSType.linux,
                "windows": OSType.windows,
                "macos":   OSType.darwin,
                "unix":    OSType.unix,
            }

            fields = {
                "benchmark_name":    check_data.get("benchmark_name", ""),
                "benchmark_version": check_data.get("benchmark_version", "1.0"),
                "section":           check_data.get("section", ""),
                "title":             check_data.get("title", ""),
                "description":       check_data.get("description"),
                "rationale":         check_data.get("rationale"),
                "remediation":       check_data.get("remediation"),
                "severity":          severity,
                "os_type":           os_type_map.get(os_type, OSType.unknown),
                "os_versions":       check_data.get("os_versions", []),
                "check_type":        check_type,
                "check_command":     check_data.get("check_command"),
                "expected_output":   check_data.get("expected_output"),
                "expected_regex":    check_data.get("expected_regex"),
                "level":             check_data.get("level", 1),
            }

            if existing:
                for k, v in fields.items():
                    setattr(existing, k, v)
            else:
                db.add(BenchmarkCheck(id=check_id, **fields))
            count += 1

    await db.flush()
    return count


# ---------------------------------------------------------------------------
# Audit runner
# ---------------------------------------------------------------------------

class AuditEngine:
    """Runs CIS benchmark checks against a connected host."""

    async def run_checks(
        self,
        db: AsyncSession,
        transport: BaseTransport,
        device_id: str,
        scan_target_id: str,
        os_type: str,
        os_version: str = "",
        level: int = 1,
    ) -> list[ComplianceResultRecord]:
        """
        Run all applicable CIS checks for the device's OS type and level.
        Returns the list of ComplianceResultRecord objects written to DB.
        """
        from sqlalchemy import select
        result = await db.execute(
            select(BenchmarkCheck).where(
                BenchmarkCheck.os_type == OSType(os_type),
                BenchmarkCheck.level <= level,
            )
        )
        checks = result.scalars().all()

        records: list[ComplianceResultRecord] = []
        # Run up to 10 checks concurrently to avoid overwhelming the host
        semaphore = asyncio.Semaphore(10)

        async def _run_check(check: BenchmarkCheck) -> ComplianceResultRecord:
            async with semaphore:
                return await self._evaluate_check(
                    db, transport, check, device_id, scan_target_id
                )

        results = await asyncio.gather(
            *[_run_check(c) for c in checks],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                logger.warning("Check evaluation failed: %s", r)
            else:
                records.append(r)

        await db.flush()
        return records

    async def _evaluate_check(
        self,
        db: AsyncSession,
        transport: BaseTransport,
        check: BenchmarkCheck,
        device_id: str,
        scan_target_id: str,
    ) -> ComplianceResultRecord:
        result_val = ComplianceResult.error
        actual_output = ""

        try:
            if check.check_type == CheckType.command:
                result_val, actual_output = await self._run_command_check(transport, check)
            elif check.check_type == CheckType.file_exists:
                result_val, actual_output = await self._run_file_exists_check(transport, check)
            elif check.check_type == CheckType.file_content:
                result_val, actual_output = await self._run_file_content_check(transport, check)
            elif check.check_type == CheckType.registry:
                result_val, actual_output = await self._run_registry_check(transport, check)
            elif check.check_type == CheckType.service:
                result_val, actual_output = await self._run_service_check(transport, check)
        except TransportError as exc:
            result_val = ComplianceResult.error
            actual_output = str(exc)
        except Exception as exc:
            result_val = ComplianceResult.error
            actual_output = f"Unexpected error: {exc}"

        record = ComplianceResultRecord(
            device_id=device_id,
            scan_target_id=scan_target_id,
            check_id=check.id,
            result=result_val,
            actual_output=actual_output[:4096] if actual_output else None,
            scanned_at=datetime.utcnow(),
        )
        db.add(record)
        return record

    async def _run_command_check(
        self,
        transport: BaseTransport,
        check: BenchmarkCheck,
    ) -> tuple[ComplianceResult, str]:
        if not check.check_command:
            return ComplianceResult.error, "No command defined"

        cmd_result = await transport.run(check.check_command, timeout=30)
        output = cmd_result.stdout.strip()

        if check.expected_regex:
            match = re.search(check.expected_regex, output, re.MULTILINE | re.IGNORECASE)
            passed = bool(match)
        elif check.expected_output:
            passed = check.expected_output.strip().lower() in output.lower()
        else:
            # No expected output = check passes if exit code is 0
            passed = cmd_result.succeeded

        return (ComplianceResult.passed if passed else ComplianceResult.failed), output

    async def _run_file_exists_check(
        self,
        transport: BaseTransport,
        check: BenchmarkCheck,
    ) -> tuple[ComplianceResult, str]:
        if not check.check_command:
            return ComplianceResult.error, "No file path defined"

        result = await transport.run(
            f"test -f {check.check_command} && echo EXISTS || echo MISSING"
        )
        output = result.stdout.strip()
        passed = "EXISTS" in output
        return (ComplianceResult.passed if passed else ComplianceResult.failed), output

    async def _run_file_content_check(
        self,
        transport: BaseTransport,
        check: BenchmarkCheck,
    ) -> tuple[ComplianceResult, str]:
        if not check.check_command:
            return ComplianceResult.error, "No file path defined"

        result = await transport.run(f"cat {check.check_command} 2>/dev/null", timeout=30)
        output = result.stdout

        if check.expected_regex:
            passed = bool(re.search(check.expected_regex, output, re.MULTILINE))
        elif check.expected_output:
            passed = check.expected_output in output
        else:
            passed = bool(output.strip())

        return (ComplianceResult.passed if passed else ComplianceResult.failed), output[:2048]

    async def _run_registry_check(
        self,
        transport: BaseTransport,
        check: BenchmarkCheck,
    ) -> tuple[ComplianceResult, str]:
        """Windows registry check via PowerShell."""
        if not check.check_command:
            return ComplianceResult.error, "No registry path defined"

        ps_cmd = f"(Get-ItemProperty -Path '{check.check_command}' -ErrorAction SilentlyContinue)"
        result = await transport.run(ps_cmd, timeout=30)
        output = result.stdout.strip()

        if check.expected_regex:
            passed = bool(re.search(check.expected_regex, output, re.MULTILINE | re.IGNORECASE))
        elif check.expected_output:
            passed = check.expected_output in output
        else:
            passed = bool(output) and result.succeeded

        return (ComplianceResult.passed if passed else ComplianceResult.failed), output

    async def _run_service_check(
        self,
        transport: BaseTransport,
        check: BenchmarkCheck,
    ) -> tuple[ComplianceResult, str]:
        """Check that a service is in a specific state (running/stopped)."""
        if not check.check_command:
            return ComplianceResult.error, "No service name defined"

        # Try systemd first, fall back to service command
        result = await transport.run(
            f"systemctl is-active {check.check_command} 2>/dev/null || "
            f"service {check.check_command} status 2>&1 | head -3"
        )
        output = result.stdout.strip()

        expected = (check.expected_output or "").lower()
        if expected:
            passed = expected in output.lower()
        else:
            # Default: check that service is NOT active (disabled)
            passed = "inactive" in output.lower() or "stopped" in output.lower()

        return (ComplianceResult.passed if passed else ComplianceResult.failed), output
