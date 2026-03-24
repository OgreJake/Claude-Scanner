"""
PDF report generator using ReportLab.

Generates a structured scan report with:
  - Executive summary (severity breakdown, top risks by EPSS)
  - Per-device findings with CVE details
  - Compliance summary
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import TYPE_CHECKING, Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

if TYPE_CHECKING:
    from server.db.models import ScanJob

# Severity color mapping
SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#65a30d"),
    "none":     colors.HexColor("#6b7280"),
    "unknown":  colors.HexColor("#9ca3af"),
}


def _severity_color(severity: str) -> Any:
    return SEVERITY_COLORS.get(severity.lower(), colors.grey)


async def generate_scan_report_pdf(db: AsyncSession, scan_job: "ScanJob") -> bytes:
    """Generate a full PDF report for a scan job."""
    from server.db.models import Device, Finding, ScanTarget, Vulnerability, EPSSScore

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Claude Scanner Report — {scan_job.name}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "title", parent=styles["Title"], fontSize=24, spaceAfter=12
    )
    h1_style = ParagraphStyle(
        "h1", parent=styles["Heading1"], fontSize=16, spaceAfter=8, spaceBefore=16
    )
    h2_style = ParagraphStyle(
        "h2", parent=styles["Heading2"], fontSize=12, spaceAfter=6, spaceBefore=10
    )
    body_style = styles["Normal"]

    elements = []

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------
    elements.append(Spacer(1, 2 * cm))
    elements.append(Paragraph("Claude Scanner", ParagraphStyle("brand", parent=title_style, textColor=colors.HexColor("#1d4ed8"))))
    elements.append(Paragraph("Vulnerability Scan Report", title_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb")))
    elements.append(Spacer(1, 0.5 * cm))

    meta = [
        ["Scan Name:", scan_job.name],
        ["Scan Type:", scan_job.scan_type.value.title()],
        ["Status:", scan_job.status.value.title()],
        ["Devices Scanned:", str(scan_job.total_devices)],
        ["Completed Devices:", str(scan_job.completed_devices)],
        ["Failed Devices:", str(scan_job.failed_devices)],
        ["Started:", scan_job.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan_job.started_at else "—"],
        ["Completed:", scan_job.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan_job.completed_at else "—"],
        ["Report Generated:", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    meta_table = Table(meta, colWidths=[4 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(PageBreak())

    # ------------------------------------------------------------------
    # Executive Summary — findings by severity
    # ------------------------------------------------------------------
    elements.append(Paragraph("Executive Summary", h1_style))

    target_result = await db.execute(
        select(ScanTarget).where(ScanTarget.scan_job_id == scan_job.id)
    )
    targets = target_result.scalars().all()
    target_ids = [t.id for t in targets]

    if target_ids:
        summary_result = await db.execute(
            select(Finding.severity, func.count(Finding.id).label("cnt"))
            .where(Finding.scan_target_id.in_(target_ids))
            .group_by(Finding.severity)
        )
        summary_rows = summary_result.all()
    else:
        summary_rows = []

    severity_counts = {row.severity.value: row.cnt for row in summary_rows}
    total_findings = sum(severity_counts.values())

    elements.append(Paragraph(f"Total findings: <b>{total_findings}</b>", body_style))
    elements.append(Spacer(1, 0.3 * cm))

    sev_data = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "none", "unknown"):
        cnt = severity_counts.get(sev, 0)
        if cnt > 0:
            sev_data.append([sev.title(), str(cnt)])

    sev_table = Table(sev_data, colWidths=[5 * cm, 3 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 0.5 * cm))

    # Top 10 by EPSS
    if target_ids:
        top_result = await db.execute(
            select(Finding)
            .where(
                Finding.scan_target_id.in_(target_ids),
                Finding.epss_score.isnot(None),
            )
            .order_by(Finding.epss_score.desc())
            .limit(10)
        )
        top_findings = top_result.scalars().all()

        if top_findings:
            elements.append(Paragraph("Top 10 Findings by EPSS Score (Exploitation Probability)", h2_style))
            top_data = [["CVE ID", "Component", "Severity", "CVSS", "EPSS", "Percentile"]]
            for f in top_findings:
                top_data.append([
                    f.vulnerability_id,
                    (f.affected_component or "")[:30],
                    f.severity.value.title(),
                    f"{f.cvss_score:.1f}" if f.cvss_score else "—",
                    f"{f.epss_score:.4f}" if f.epss_score else "—",
                    f"{f.epss_percentile:.1%}" if f.epss_percentile else "—",
                ])
            top_table = Table(top_data, colWidths=[3.5*cm, 4*cm, 2.5*cm, 1.5*cm, 2*cm, 2.5*cm])
            top_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(top_table)

    elements.append(PageBreak())

    # ------------------------------------------------------------------
    # Per-device findings
    # ------------------------------------------------------------------
    elements.append(Paragraph("Findings by Device", h1_style))

    for target in targets:
        device_result = await db.execute(
            select(Device).where(Device.id == target.device_id)
        )
        device = device_result.scalar_one_or_none()
        if not device:
            continue

        findings_result = await db.execute(
            select(Finding)
            .where(Finding.scan_target_id == target.id)
            .order_by(Finding.epss_score.desc().nullslast(), Finding.cvss_score.desc().nullslast())
        )
        device_findings = findings_result.scalars().all()

        device_label = f"{device.hostname} ({device.ip_address}) — {device.os_name or device.os_type.value}"
        elements.append(Paragraph(device_label, h2_style))
        elements.append(Paragraph(
            f"Status: {target.status.value.title()} | Findings: {len(device_findings)}",
            body_style,
        ))

        if not device_findings:
            elements.append(Paragraph("<i>No findings for this device.</i>", body_style))
            elements.append(Spacer(1, 0.3 * cm))
            continue

        rows = [["CVE ID", "Component", "Version", "Sev", "CVSS", "EPSS", "Status"]]
        for f in device_findings:
            rows.append([
                f.vulnerability_id,
                (f.affected_component or "")[:25],
                (f.affected_version or "")[:15],
                f.severity.value.upper()[:4],
                f"{f.cvss_score:.1f}" if f.cvss_score else "—",
                f"{f.epss_score:.4f}" if f.epss_score else "—",
                f.status.value.title(),
            ])

        t = Table(rows, colWidths=[3.5*cm, 3.5*cm, 2.5*cm, 1.5*cm, 1.5*cm, 2*cm, 2*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.5 * cm))

    doc.build(elements)
    return buffer.getvalue()
