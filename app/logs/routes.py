"""
Logs page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from app.logs import get_scan_history, get_scan_detail

logs_bp = Blueprint("logs", __name__, template_folder="../templates")


@logs_bp.route("/logs")
@login_required
def index():
    scans = get_scan_history(current_user.id, limit=100)
    return render_template("logs.html", scans=scans)


@logs_bp.route("/logs/<int:scan_id>")
@login_required
def detail(scan_id):
    scan = get_scan_detail(scan_id, current_user.id)
    if not scan:
        abort(404)
    return render_template("scan_detail.html", scan=scan)
