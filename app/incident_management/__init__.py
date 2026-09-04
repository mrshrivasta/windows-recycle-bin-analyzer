"""
Incident Management module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Lets a user promote an Alert into a tracked Incident with status/priority
workflow: open -> investigating -> resolved -> closed.
"""
from datetime import datetime
from app.database import db, Incident


VALID_STATUSES = ["open", "investigating", "resolved", "closed"]
VALID_PRIORITIES = ["low", "medium", "high", "critical"]


def create_incident_from_alert(alert, user, title=None, priority="medium"):
    incident = Incident(
        alert_id=alert.id,
        user_id=user.id,
        title=title or alert.message[:200],
        status="open",
        priority=priority if priority in VALID_PRIORITIES else "medium",
    )
    db.session.add(incident)
    db.session.commit()
    return incident


def update_incident_status(incident, new_status, notes=None):
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")
    incident.status = new_status
    incident.updated_at = datetime.utcnow()
    if notes:
        incident.notes = (incident.notes or "") + f"\n[{datetime.utcnow().isoformat()}] {notes}"
    if new_status == "resolved":
        incident.resolved_at = datetime.utcnow()
    db.session.commit()
    return incident
