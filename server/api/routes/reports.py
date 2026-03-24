"""Report generation routes — PDF and CSV exports."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from server.api.deps import CurrentUser, DBSession
from server.db.models import Finding, FindingStatus, ScanJob
from sqlalchemy import select

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/findings/csv")
async def export_findings_csv(
    db: DBSession,
    current_user: CurrentUser,
    device_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None, alias="status"),
    scan_id: Optional[str] = Query(None),
) -> StreamingResponse:
    """Export vulnerability findings as CSV."""
    from server.reports.csv_gen import generate_findings_csv

    q = select(Finding)
    if device_id:
        q = q.where(Finding.device_id == device_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if finding_status:
        q = q.where(Finding.status == finding_status)
    if scan_id:
        q = q.where(Finding.scan_target_id.in_(
            select(Finding.scan_target_id).join(Finding.scan_target).where(
                Finding.scan_target.has(scan_job_id=scan_id)
            )
        ))
    q = q.order_by(Finding.epss_score.desc().nullslast())
    result = await db.execute(q)
    findings = result.scalars().all()

    csv_content = generate_findings_csv(findings)
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/scans/{scan_id}/pdf")
async def export_scan_pdf(
    scan_id: str,
    db: DBSession,
    current_user: CurrentUser,
) -> Response:
    """Generate a PDF report for a completed scan."""
    from server.reports.pdf_gen import generate_scan_report_pdf

    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    pdf_bytes = await generate_scan_report_pdf(db, job)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan-report-{scan_id[:8]}.pdf"},
    )


@router.get("/compliance/{device_id}/csv")
async def export_compliance_csv(
    device_id: str,
    db: DBSession,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Export CIS benchmark compliance results for a device as CSV."""
    from server.reports.csv_gen import generate_compliance_csv
    from server.db.models import ComplianceResultRecord
    from sqlalchemy import select

    result = await db.execute(
        select(ComplianceResultRecord).where(ComplianceResultRecord.device_id == device_id)
    )
    records = result.scalars().all()
    csv_content = generate_compliance_csv(records)
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=compliance-{device_id[:8]}.csv"},
    )
