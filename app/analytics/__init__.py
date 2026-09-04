"""
Analytics module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Pure aggregation over REAL rows already stored in the database (scan history,
findings, alerts, incidents). Produces the data structures consumed by the
Chart.js visualisations in the Analytics/Reports pages. No synthetic numbers.
"""
from sqlalchemy import func
from app.database import db, ScanResult, Finding, Alert, Incident


def severity_breakdown(user_id):
    """Pie/Doughnut chart data: count of findings per severity for this user."""
    rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .join(ScanResult, Finding.scan_id == ScanResult.id)
        .filter(ScanResult.user_id == user_id)
        .group_by(Finding.severity)
        .all()
    )
    return {severity: count for severity, count in rows}


def findings_by_rule(user_id):
    """Bar chart data: count of findings per detection rule for this user."""
    rows = (
        db.session.query(Finding.rule_name, func.count(Finding.id))
        .join(ScanResult, Finding.scan_id == ScanResult.id)
        .filter(ScanResult.user_id == user_id)
        .group_by(Finding.rule_name)
        .order_by(func.count(Finding.id).desc())
        .all()
    )
    return {rule: count for rule, count in rows}


def scans_over_time(user_id):
    """Line chart data: number of scans run per day for this user."""
    rows = (
        db.session.query(func.date(ScanResult.started_at), func.count(ScanResult.id))
        .filter(ScanResult.user_id == user_id)
        .group_by(func.date(ScanResult.started_at))
        .order_by(func.date(ScanResult.started_at))
        .all()
    )
    return {str(day): count for day, count in rows}


def incident_status_counts(user_id):
    """Radar/polar chart data: incidents grouped by status."""
    rows = (
        db.session.query(Incident.status, func.count(Incident.id))
        .filter(Incident.user_id == user_id)
        .group_by(Incident.status)
        .all()
    )
    return {status: count for status, count in rows}


def summary_counters(user_id):
    """Top-of-dashboard stat tiles — all real counts from the DB."""
    total_scans = db.session.query(func.count(ScanResult.id)).filter(ScanResult.user_id == user_id).scalar() or 0
    total_findings = (
        db.session.query(func.count(Finding.id))
        .join(ScanResult, Finding.scan_id == ScanResult.id)
        .filter(ScanResult.user_id == user_id)
        .scalar()
        or 0
    )
    total_alerts = db.session.query(func.count(Alert.id)).filter(Alert.user_id == user_id).scalar() or 0
    open_incidents = (
        db.session.query(func.count(Incident.id))
        .filter(Incident.user_id == user_id, Incident.status.in_(["open", "investigating"]))
        .scalar()
        or 0
    )
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "total_alerts": total_alerts,
        "open_incidents": open_incidents,
    }
