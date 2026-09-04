"""
Analytics page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app.analytics import severity_breakdown, findings_by_rule, scans_over_time, incident_status_counts

analytics_bp = Blueprint("analytics", __name__, template_folder="../templates")


@analytics_bp.route("/analytics")
@login_required
def index():
    return render_template("analytics.html")


@analytics_bp.route("/analytics/data")
@login_required
def data():
    """JSON endpoint feeding Chart.js — every number is a real DB aggregate."""
    return jsonify({
        "severity_breakdown": severity_breakdown(current_user.id),
        "findings_by_rule": findings_by_rule(current_user.id),
        "scans_over_time": scans_over_time(current_user.id),
        "incident_status_counts": incident_status_counts(current_user.id),
    })
