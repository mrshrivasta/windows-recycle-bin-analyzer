"""
Database module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

SQLAlchemy models backing every module of this project (auth, security engine,
detection rules, logs, alerts, incident management, analytics, reports, settings).
All data persisted here comes from REAL filesystem scans — nothing is mocked.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    scans = db.relationship("ScanResult", backref="user", lazy=True, cascade="all, delete-orphan")
    settings = db.relationship("UserSettings", backref="user", uselist=False, cascade="all, delete-orphan")

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)


class ScanResult(db.Model):
    """One execution of the Security Engine (a 'scan run')."""
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_path = db.Column(db.String(500), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    files_scanned = db.Column(db.Integer, default=0)
    dirs_scanned = db.Column(db.Integer, default=0)
    errors_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="running")  # running, completed, failed

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")


class Finding(db.Model):
    """A single detection-rule hit produced by the Security Engine (real data)."""
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_results.id"), nullable=False)
    rule_id = db.Column(db.String(50), nullable=False)
    rule_name = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    file_path = db.Column(db.String(1000), nullable=False)
    permissions_octal = db.Column(db.String(10))
    owner_uid = db.Column(db.Integer)
    owner_gid = db.Column(db.Integer)
    description = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    alert = db.relationship("Alert", backref="finding", uselist=False, cascade="all, delete-orphan")


class Alert(db.Model):
    """Alert generated from a Finding based on severity thresholds."""
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("findings.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)

    incident = db.relationship("Incident", backref="alert", uselist=False, cascade="all, delete-orphan")


class Incident(db.Model):
    """Incident Management: a tracked, human-owned response to one or more alerts."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open, investigating, resolved, closed
    priority = db.Column(db.String(20), default="medium")
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    default_scan_path = db.Column(db.String(500), default="")
    scan_depth_limit = db.Column(db.Integer, default=8)
    exclude_paths = db.Column(db.Text, default="")
    alert_on_severity = db.Column(db.String(20), default="medium")
    email_notifications = db.Column(db.Boolean, default=False)
