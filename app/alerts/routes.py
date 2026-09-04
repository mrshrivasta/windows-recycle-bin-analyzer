"""
Alerts page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.database import db, Alert
from app.incident_management import create_incident_from_alert

alerts_bp = Blueprint("alerts", __name__, template_folder="../templates")


@alerts_bp.route("/alerts")
@login_required
def index():
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)


@alerts_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge(alert_id):
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    alert.acknowledged = True
    db.session.commit()
    flash("Alert acknowledged.", "success")
    return redirect(url_for("alerts.index"))


@alerts_bp.route("/alerts/<int:alert_id>/escalate", methods=["POST"])
@login_required
def escalate(alert_id):
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    priority = request.form.get("priority", "medium")
    create_incident_from_alert(alert, current_user, priority=priority)
    flash("Incident created from alert.", "success")
    return redirect(url_for("incidents.index"))
