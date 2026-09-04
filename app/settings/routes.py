"""
Settings page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.settings import get_or_create_settings, update_settings

settings_bp = Blueprint("settings", __name__, template_folder="../templates")


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        update_settings(
            current_user,
            default_scan_path=request.form.get("default_scan_path"),
            scan_depth_limit=int(request.form.get("scan_depth_limit", 6) or 6),
            exclude_paths=request.form.get("exclude_paths"),
            alert_on_severity=request.form.get("alert_on_severity"),
            email_notifications=bool(request.form.get("email_notifications")),
        )
        flash("Settings saved.", "success")
        return redirect(url_for("settings.index"))

    settings = get_or_create_settings(current_user)
    return render_template("settings.html", settings=settings)
