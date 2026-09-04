"""
Incident Management page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.database import Incident
from app.incident_management import update_incident_status

incidents_bp = Blueprint("incidents", __name__, template_folder="../templates")


@incidents_bp.route("/incidents")
@login_required
def index():
    incidents = Incident.query.filter_by(user_id=current_user.id).order_by(Incident.created_at.desc()).all()
    return render_template("incidents.html", incidents=incidents)


@incidents_bp.route("/incidents/<int:incident_id>/update", methods=["POST"])
@login_required
def update(incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first_or_404()
    new_status = request.form.get("status", incident.status)
    notes = request.form.get("notes", "")
    try:
        update_incident_status(incident, new_status, notes)
        flash("Incident updated.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("incidents.index"))
