"""
Alerts module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Converts Findings produced by the Security Engine into persisted Alert rows
when a Finding's severity meets or exceeds the user's configured threshold.
"""
from app.database import db, Finding, Alert

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def generate_alerts_for_scan(scan_result, user, min_severity="medium"):
    """Create Alert rows for every Finding on scan_result at/above min_severity.
    Returns the list of created Alert objects."""
    threshold = SEVERITY_RANK.get(min_severity, 1)
    created = []
    for finding in scan_result.findings:
        if SEVERITY_RANK.get(finding.severity, 0) >= threshold:
            alert = Alert(
                finding_id=finding.id,
                user_id=user.id,
                severity=finding.severity,
                message=f"[{finding.rule_id}] {finding.rule_name}: {finding.file_path}",
            )
            db.session.add(alert)
            created.append(alert)
    db.session.commit()
    return created
