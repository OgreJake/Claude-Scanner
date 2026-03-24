"""
SQLAlchemy ORM models for Claude Scanner.

All UUIDs are generated server-side. Timestamps are stored as UTC.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSON, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class OSType(str, PyEnum):
    linux   = "linux"
    windows = "windows"
    darwin  = "darwin"
    unix    = "unix"
    unknown = "unknown"


class DeviceStatus(str, PyEnum):
    online  = "online"
    offline = "offline"
    unknown = "unknown"


class ScanType(str, PyEnum):
    full      = "full"       # packages + network + config
    network   = "network"    # ports, services, network CVEs
    packages  = "packages"   # installed software CVEs
    config    = "config"     # CIS benchmark compliance
    quick     = "quick"      # agentless, packages only


class ScanStatus(str, PyEnum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"
    cancelled = "cancelled"


class Severity(str, PyEnum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    none     = "none"
    unknown  = "unknown"


class FindingStatus(str, PyEnum):
    open           = "open"
    acknowledged   = "acknowledged"
    false_positive = "false_positive"
    resolved       = "resolved"


class FindingType(str, PyEnum):
    package = "package"
    network = "network"
    config  = "config"


class VulnSource(str, PyEnum):
    nvd  = "nvd"
    osv  = "osv"
    both = "both"


class ComplianceResult(str, PyEnum):
    passed         = "pass"
    failed         = "fail"
    error          = "error"
    not_applicable = "not_applicable"


class CheckType(str, PyEnum):
    command      = "command"
    file_exists  = "file_exists"
    file_content = "file_content"
    registry     = "registry"
    service      = "service"


class DiscoveryMethod(str, PyEnum):
    manual    = "manual"
    ping_sweep = "ping_sweep"
    nmap      = "nmap"
    arp       = "arp"
    import_csv = "import_csv"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_jobs: Mapped[list[ScanJob]] = relationship("ScanJob", back_populates="created_by_user")
    discovery_jobs: Mapped[list[DiscoveryJob]] = relationship("DiscoveryJob", back_populates="created_by_user")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    os_type: Mapped[OSType] = mapped_column(Enum(OSType), default=OSType.unknown, nullable=False)
    os_name: Mapped[str | None] = mapped_column(String(255))        # e.g. "Ubuntu 22.04 LTS"
    os_version: Mapped[str | None] = mapped_column(String(128))
    os_build: Mapped[str | None] = mapped_column(String(128))
    architecture: Mapped[str | None] = mapped_column(String(32))    # x86_64, arm64, ...
    kernel_version: Mapped[str | None] = mapped_column(String(128))

    # Connectivity
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    winrm_port: Mapped[int] = mapped_column(Integer, default=5985, nullable=False)
    winrm_use_ssl: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # 1Password credential reference
    # Stores the 1Password item UUID or "vault/item" path
    credential_ref: Mapped[str | None] = mapped_column(String(512))

    # Agent
    agent_installed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    agent_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_endpoint: Mapped[str | None] = mapped_column(String(512))  # https://host:9443

    # Metadata
    tags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    discovery_method: Mapped[DiscoveryMethod] = mapped_column(Enum(DiscoveryMethod), default=DiscoveryMethod.manual)
    status: Mapped[DeviceStatus] = mapped_column(Enum(DeviceStatus), default=DeviceStatus.unknown, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_targets: Mapped[list[ScanTarget]] = relationship("ScanTarget", back_populates="device")
    packages: Mapped[list[Package]] = relationship("Package", back_populates="device")
    network_services: Mapped[list[NetworkService]] = relationship("NetworkService", back_populates="device")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="device")
    compliance_results: Mapped[list[ComplianceResultRecord]] = relationship("ComplianceResultRecord", back_populates="device")

    __table_args__ = (
        UniqueConstraint("hostname", "ip_address", name="uq_device_hostname_ip"),
        Index("ix_device_os_type", "os_type"),
        Index("ix_device_status", "status"),
    )


# ---------------------------------------------------------------------------
# Scan Jobs
# ---------------------------------------------------------------------------

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False, index=True)

    created_by: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    created_by_user: Mapped[User] = relationship("User", back_populates="scan_jobs")

    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    celery_task_id: Mapped[str | None] = mapped_column(String(255))

    total_devices: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_devices: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_devices: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    targets: Mapped[list[ScanTarget]] = relationship("ScanTarget", back_populates="scan_job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_job_status", "status"),
        Index("ix_scan_job_created_at", "created_at"),
    )


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_job_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("devices.id"), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_job: Mapped[ScanJob] = relationship("ScanJob", back_populates="targets")
    device: Mapped[Device] = relationship("Device", back_populates="scan_targets")
    packages: Mapped[list[Package]] = relationship("Package", back_populates="scan_target")
    network_services: Mapped[list[NetworkService]] = relationship("NetworkService", back_populates="scan_target")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="scan_target")
    compliance_results: Mapped[list[ComplianceResultRecord]] = relationship("ComplianceResultRecord", back_populates="scan_target")


# ---------------------------------------------------------------------------
# Packages (installed software inventory)
# ---------------------------------------------------------------------------

class Package(Base):
    __tablename__ = "packages"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("devices.id"), nullable=False, index=True)
    scan_target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_targets.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    arch: Mapped[str | None] = mapped_column(String(32))
    package_manager: Mapped[str | None] = mapped_column(String(64))  # dpkg, rpm, brew, msi, ...
    vendor: Mapped[str | None] = mapped_column(String(255))
    cpe: Mapped[str | None] = mapped_column(String(512), index=True)  # CPE 2.3 URI
    install_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    device: Mapped[Device] = relationship("Device", back_populates="packages")
    scan_target: Mapped[ScanTarget] = relationship("ScanTarget", back_populates="packages")

    __table_args__ = (
        Index("ix_package_device_name_version", "device_id", "name", "version"),
    )


# ---------------------------------------------------------------------------
# Network Services
# ---------------------------------------------------------------------------

class NetworkService(Base):
    __tablename__ = "network_services"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("devices.id"), nullable=False, index=True)
    scan_target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_targets.id"), nullable=False)

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)   # tcp / udp
    state: Mapped[str] = mapped_column(String(16), nullable=False)     # open / filtered / closed
    service_name: Mapped[str | None] = mapped_column(String(128))
    service_product: Mapped[str | None] = mapped_column(String(255))
    service_version: Mapped[str | None] = mapped_column(String(255))
    service_extra: Mapped[str | None] = mapped_column(String(512))
    banner: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(String(512), index=True)
    ssl_info: Mapped[dict[str, Any] | None] = mapped_column(JSON)      # cert expiry, ciphers, ...
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    device: Mapped[Device] = relationship("Device", back_populates="network_services")
    scan_target: Mapped[ScanTarget] = relationship("ScanTarget", back_populates="network_services")

    __table_args__ = (
        Index("ix_netservice_device_port_proto", "device_id", "port", "protocol"),
    )


# ---------------------------------------------------------------------------
# Vulnerability Knowledge Base
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    """
    Cached CVE / GHSA records from NVD and OSV.
    Re-fetched when stale (configurable TTL).
    """
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # CVE-XXXX-XXXXX or GHSA-xxx
    source: Mapped[VulnSource] = mapped_column(Enum(VulnSource), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.unknown, nullable=False, index=True)

    # CVSS v3
    cvss_v3_score: Mapped[float | None] = mapped_column(Float)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_v3_source: Mapped[str | None] = mapped_column(String(128))

    # CVSS v2 (legacy)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float)
    cvss_v2_vector: Mapped[str | None] = mapped_column(String(128))

    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_cpes: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_packages: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)  # OSV format
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    epss_score: Mapped[EPSSScore | None] = relationship("EPSSScore", back_populates="vulnerability", uselist=False)
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="vulnerability")

    __table_args__ = (
        Index("ix_vuln_severity", "severity"),
        Index("ix_vuln_last_fetched", "last_fetched_at"),
    )


class EPSSScore(Base):
    """
    Exploit Prediction Scoring System score for a CVE.
    Updated daily from FIRST.org.
    """
    __tablename__ = "epss_scores"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    cve_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)     # 0.0 – 1.0 exploitation probability
    percentile: Mapped[float] = mapped_column(Float, nullable=False)     # 0.0 – 1.0 relative to all CVEs
    model_version: Mapped[str | None] = mapped_column(String(32))
    scored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    vulnerability: Mapped[Vulnerability] = relationship("Vulnerability", back_populates="epss_score")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding(Base):
    """
    A vulnerability finding linking a Device, a ScanTarget, and a Vulnerability.
    """
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("devices.id"), nullable=False, index=True)
    scan_target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_targets.id"), nullable=False, index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerabilities.id"), nullable=False, index=True)

    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open, nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, index=True)

    affected_component: Mapped[str | None] = mapped_column(String(512))  # package name or service
    affected_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))

    # Snapshot values at time of finding (EPSS/CVSS change over time)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    cvss_score: Mapped[float | None] = mapped_column(Float)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)

    device: Mapped[Device] = relationship("Device", back_populates="findings")
    scan_target: Mapped[ScanTarget] = relationship("ScanTarget", back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship("Vulnerability", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("device_id", "vulnerability_id", "affected_component", name="uq_finding_device_vuln_component"),
        Index("ix_finding_severity_status", "severity", "status"),
        Index("ix_finding_epss", "epss_score"),
    )


# ---------------------------------------------------------------------------
# CIS Benchmark
# ---------------------------------------------------------------------------

class BenchmarkCheck(Base):
    """CIS benchmark check definition (loaded from YAML files at startup)."""
    __tablename__ = "benchmark_checks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "linux.1.1.1"
    benchmark_name: Mapped[str] = mapped_column(String(255), nullable=False)
    benchmark_version: Mapped[str] = mapped_column(String(32), nullable=False)
    section: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    os_type: Mapped[OSType] = mapped_column(Enum(OSType), nullable=False, index=True)
    os_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    check_type: Mapped[CheckType] = mapped_column(Enum(CheckType), nullable=False)
    check_command: Mapped[str | None] = mapped_column(Text)
    expected_output: Mapped[str | None] = mapped_column(Text)
    expected_regex: Mapped[str | None] = mapped_column(Text)
    level: Mapped[int] = mapped_column(Integer, default=1)  # CIS Level 1 or 2

    compliance_results: Mapped[list[ComplianceResultRecord]] = relationship("ComplianceResultRecord", back_populates="check")


class ComplianceResultRecord(Base):
    __tablename__ = "compliance_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("devices.id"), nullable=False, index=True)
    scan_target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_targets.id"), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(64), ForeignKey("benchmark_checks.id"), nullable=False, index=True)
    result: Mapped[ComplianceResult] = mapped_column(Enum(ComplianceResult), nullable=False)
    actual_output: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    device: Mapped[Device] = relationship("Device", back_populates="compliance_results")
    scan_target: Mapped[ScanTarget] = relationship("ScanTarget", back_populates="compliance_results")
    check: Mapped[BenchmarkCheck] = relationship("BenchmarkCheck", back_populates="compliance_results")

    __table_args__ = (
        Index("ix_compliance_device_check", "device_id", "check_id"),
    )


# ---------------------------------------------------------------------------
# Device Discovery
# ---------------------------------------------------------------------------

class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_ranges: Mapped[list[str]] = mapped_column(JSON, nullable=False)  # ["10.0.0.0/24", ...]
    methods: Mapped[list[str]] = mapped_column(JSON, default=list)          # ["ping", "nmap"]
    ports: Mapped[list[int]] = mapped_column(JSON, default=list)            # ports to probe
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    created_by_user: Mapped[User] = relationship("User", back_populates="discovery_jobs")
    devices_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
