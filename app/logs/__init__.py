"""
Logs module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Read-side helpers over the ScanResult table — this project treats every
persisted scan run as the audit log. No separate log files are fabricated;
everything traces back to real scan executions.
"""
from app.database import db, ScanResult


def get_scan_history(user_id, limit=50):
    return (
        ScanResult.query.filter_by(user_id=user_id)
        .order_by(ScanResult.started_at.desc())
        .limit(limit)
        .all()
    )


def get_scan_detail(scan_id, user_id):
    return ScanResult.query.filter_by(id=scan_id, user_id=user_id).first()
