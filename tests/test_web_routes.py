import os
import struct
import tempfile
import shutil
from datetime import datetime, timedelta

FILETIME_EPOCH_DELTA = 11644473600
FILETIME_TICKS_PER_SECOND = 10_000_000


def _datetime_to_filetime(dt):
    unix_seconds = (dt - datetime(1970, 1, 1)).total_seconds()
    return int((unix_seconds + FILETIME_EPOCH_DELTA) * FILETIME_TICKS_PER_SECOND)


def _make_recycle_bin_dir():
    """Build a real temp directory containing a real, spec-conformant
    version-2 $I metadata file (with a matching $R file) that will trigger
    WRB-001 (sensitive extension) and WRB-002 (recoverable content)."""
    tmpdir = tempfile.mkdtemp()
    original_path = r"C:\Users\tester\Documents\vault.kdbx"
    name_len = len(original_path)
    deleted_time = datetime.utcnow() - timedelta(hours=1)
    header = struct.pack("<qqqi", 2, 4096, _datetime_to_filetime(deleted_time), name_len)
    data = header + original_path.encode("utf-16-le")

    i_path = os.path.join(tmpdir, "$IZZ9999.kdbx")
    with open(i_path, "wb") as fh:
        fh.write(data)
    r_path = os.path.join(tmpdir, "$RZZ9999.kdbx")
    with open(r_path, "wb") as fh:
        fh.write(b"recovered vault bytes")

    return tmpdir


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = _make_recycle_bin_dir()
    try:
        # Run a real scan against a real temp dir containing a real $I file.
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert tmpdir.encode() in resp.data

        # Alerts page should load (finding severity should trigger an alert)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"WRB-001" in resp.data or b"WRB-002" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
