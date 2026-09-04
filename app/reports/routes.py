"""
Reports page routes — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, Response
from flask_login import login_required, current_user
from app.reports import export_findings_csv
from app.logs import get_scan_history

reports_bp = Blueprint("reports", __name__, template_folder="../templates")


@reports_bp.route("/reports")
@login_required
def index():
    scans = get_scan_history(current_user.id, limit=100)
    return render_template("reports.html", scans=scans)


@reports_bp.route("/reports/export.csv")
@reports_bp.route("/reports/export/<int:scan_id>.csv")
@login_required
def export_csv(scan_id=None):
    csv_data = export_findings_csv(current_user.id, scan_id=scan_id)
    filename = f"findings_scan_{scan_id}.csv" if scan_id else "findings_all.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
