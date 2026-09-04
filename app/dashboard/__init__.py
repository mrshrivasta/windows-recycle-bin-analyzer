"""
Dashboard module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.database import db, ScanResult, Finding
from app.security_engine import ScanEngine
from app.alerts import generate_alerts_for_scan
from app.analytics import summary_counters
from app.logs import get_scan_history
from app.settings import get_or_create_settings

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../templates")


@dashboard_bp.route("/", methods=["GET"])
@login_required
def index():
    counters = summary_counters(current_user.id)
    recent_scans = get_scan_history(current_user.id, limit=5)
    return render_template("dashboard.html", counters=counters, recent_scans=recent_scans)


@dashboard_bp.route("/scan/run", methods=["POST"])
@login_required
def run_scan():
    """Trigger a REAL, synchronous scan of a real directory for Recycle Bin
    $I/$R metadata files using the Security Engine."""
    target_path = request.form.get("target_path", "").strip() or "."
    settings = get_or_create_settings(current_user)
    excludes = [p.strip() for p in (settings.exclude_paths or "").split(",") if p.strip()]

    scan = ScanResult(user_id=current_user.id, target_path=target_path, status="running")
    db.session.add(scan)
    db.session.commit()

    try:
        engine = ScanEngine(
            target_path,
            max_depth=settings.scan_depth_limit or 8,
            excludes=excludes,
            max_files=20000,
        )
        result = engine.run()

        for f in result["findings"]:
            finding = Finding(
                scan_id=scan.id,
                rule_id=f["rule_id"],
                rule_name=f["rule_name"],
                severity=f["severity"],
                file_path=f["file_path"],
                permissions_octal=f["permissions_octal"],
                owner_uid=f["owner_uid"],
                owner_gid=f["owner_gid"],
                description=f["description"],
            )
            db.session.add(finding)

        scan.files_scanned = result["files_scanned"]
        scan.dirs_scanned = result["dirs_scanned"]
        scan.errors_count = result["errors_count"]
        scan.status = "completed"
        from datetime import datetime
        scan.finished_at = datetime.utcnow()
        db.session.commit()

        generate_alerts_for_scan(scan, current_user, min_severity=settings.alert_on_severity or "medium")
        flash(
            f"Scan complete: {result['files_scanned']} files scanned, "
            f"{len(result['findings'])} findings.",
            "success",
        )
    except (PermissionError, FileNotFoundError, NotADirectoryError) as exc:
        scan.status = "failed"
        db.session.commit()
        flash(f"Scan failed: {exc}", "error")

    return redirect(url_for("dashboard.index"))
