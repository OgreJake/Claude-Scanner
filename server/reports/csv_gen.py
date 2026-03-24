"""CSV export generators for findings and compliance results."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from server.db.models import ComplianceResultRecord, Finding


def generate_findings_csv(findings: list["Finding"]) -> str:
    """Generate CSV export of vulnerability findings."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    writer.writerow([
        "Finding ID",
        "Device ID",
        "CVE / Vuln ID",
        "Type",
        "Status",
        "Severity",
        "CVSS v3 Score",
        "EPSS Score",
        "EPSS Percentile",
        "Affected Component",
        "Affected Version",
        "Fixed Version",
        "First Seen",
        "Last Seen",
        "Resolved At",
        "Notes",
    ])

    for f in findings:
        writer.writerow([
            f.id,
            f.device_id,
            f.vulnerability_id,
            f.finding_type.value if f.finding_type else "",
            f.status.value if f.status else "",
            f.severity.value if f.severity else "",
            f.cvss_score or "",
            f.epss_score or "",
            f.epss_percentile or "",
            f.affected_component or "",
            f.affected_version or "",
            f.fixed_version or "",
            f.first_seen.isoformat() if f.first_seen else "",
            f.last_seen.isoformat() if f.last_seen else "",
            f.resolved_at.isoformat() if f.resolved_at else "",
            f.notes or "",
        ])

    return output.getvalue()


def generate_compliance_csv(records: list["ComplianceResultRecord"]) -> str:
    """Generate CSV export of CIS compliance results."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    writer.writerow([
        "Result ID",
        "Device ID",
        "Check ID",
        "Result",
        "Actual Output",
        "Scanned At",
    ])

    for r in records:
        writer.writerow([
            r.id,
            r.device_id,
            r.check_id,
            r.result.value if r.result else "",
            (r.actual_output or "").replace("\n", " ")[:500],
            r.scanned_at.isoformat() if r.scanned_at else "",
        ])

    return output.getvalue()
