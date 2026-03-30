"""Vulnerability and findings routes."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from server.api.deps import CurrentUser, DBSession
from server.db.models import (
    EPSSScore, Finding, FindingStatus, FindingType,
    Severity, Vulnerability,
)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class VulnerabilityResponse(BaseModel):
    id: str
    source: str
    title: Optional[str]
    description: Optional[str]
    severity: str
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    cvss_v2_score: Optional[float]
    cwe_ids: list[str]
    published_at: Optional[datetime]
    modified_at: Optional[datetime]
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    device_id: str
    vulnerability_id: str
    finding_type: str
    status: str
    severity: str
    affected_component: Optional[str]
    affected_version: Optional[str]
    fixed_version: Optional[str]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    cvss_score: Optional[float]
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    notes: Optional[str] = None


class FindingSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    open: int
    acknowledged: int
    false_positive: int
    resolved: int


# ---------------------------------------------------------------------------
# Vulnerability routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    db: DBSession,
    current_user: CurrentUser,
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> list[Vulnerability]:
    q = select(Vulnerability)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if search:
        q = q.where(
            Vulnerability.id.ilike(f"%{search}%")
            | Vulnerability.description.ilike(f"%{search}%")
        )
    q = q.order_by(Vulnerability.cvss_v3_score.desc().nullslast())
    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/summary", response_model=FindingSummary)
async def get_findings_summary(db: DBSession, current_user: CurrentUser) -> FindingSummary:
    result = await db.execute(
        select(
            Finding.severity,
            Finding.status,
            func.count(Finding.id).label("cnt"),
        ).group_by(Finding.severity, Finding.status)
    )
    rows = result.all()

    summary: dict = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "open": 0, "acknowledged": 0, "false_positive": 0, "resolved": 0,
    }
    for row in rows:
        summary["total"] += row.cnt
        summary[row.severity.value] = summary.get(row.severity.value, 0) + row.cnt
        summary[row.status.value] = summary.get(row.status.value, 0) + row.cnt

    return FindingSummary(**summary)


# ---------------------------------------------------------------------------
# Findings routes  (MUST be declared before /{vuln_id} to avoid route shadowing)
# ---------------------------------------------------------------------------

@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(
    db: DBSession,
    current_user: CurrentUser,
    device_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None, alias="status"),
    finding_type: Optional[str] = Query(None, alias="type"),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
) -> list[Finding]:
    q = select(Finding)
    if device_id:
        q = q.where(Finding.device_id == device_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if finding_status:
        q = q.where(Finding.status == finding_status)
    if finding_type:
        q = q.where(Finding.finding_type == finding_type)
    if min_epss is not None:
        q = q.where(Finding.epss_score >= min_epss)
    q = (
        q.order_by(Finding.epss_score.desc().nullslast(), Finding.cvss_score.desc().nullslast())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(q)
    return result.scalars().all()


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: DBSession,
    current_user: CurrentUser,
) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if payload.status:
        finding.status = payload.status
        if payload.status == FindingStatus.resolved:
            finding.resolved_at = datetime.utcnow()
    if payload.notes is not None:
        finding.notes = payload.notes
    await db.flush()
    return finding


@router.get("/top-epss", response_model=list[FindingResponse])
async def top_epss_findings(
    db: DBSession,
    current_user: CurrentUser,
    limit: int = Query(20, ge=1, le=100),
) -> list[Finding]:
    """Return open findings ranked by EPSS score (exploitation probability)."""
    result = await db.execute(
        select(Finding)
        .where(Finding.status == FindingStatus.open, Finding.epss_score.isnot(None))
        .order_by(Finding.epss_score.desc())
        .limit(limit)
    )
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Single-vulnerability lookup  (parametric route — MUST be last to avoid
# shadowing the fixed paths /findings, /summary, /top-epss above)
# ---------------------------------------------------------------------------

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: str, db: DBSession, current_user: CurrentUser) -> Vulnerability:
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return vuln
