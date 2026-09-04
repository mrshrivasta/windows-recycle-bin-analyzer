"""
Reports module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Generates CSV export of real findings for a given scan (or all scans for a
user). Kept dependency-free (stdlib csv) so it works in any environment.
"""
import csv
import io
from app.database import db, ScanResult, Finding


def export_findings_csv(user_id, scan_id=None):
    query = (
        db.session.query(Finding, ScanResult)
        .join(ScanResult, Finding.scan_id == ScanResult.id)
        .filter(ScanResult.user_id == user_id)
    )
    if scan_id:
        query = query.filter(ScanResult.id == scan_id)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "scan_id", "target_path", "rule_id", "rule_name", "severity",
        "file_path", "permissions_octal", "owner_uid", "owner_gid", "detected_at",
    ])
    for finding, scan in query.all():
        writer.writerow([
            scan.id, scan.target_path, finding.rule_id, finding.rule_name,
            finding.severity, finding.file_path, finding.permissions_octal,
            finding.owner_uid, finding.owner_gid, finding.detected_at,
        ])
    buffer.seek(0)
    return buffer.getvalue()
