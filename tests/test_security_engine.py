"""Tests for the Security Engine and Detection Rules — run against REAL
temp filesystem paths, with real spec-conformant `$I` metadata bytes built
with struct.pack and written to disk (no mocking of file I/O)."""
import os
import struct
import tempfile
import shutil
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, filetime_to_datetime
from app.detection_rules import (
    rule_sensitive_file_extension,
    rule_recoverable_content_present,
    rule_mass_deletion_cluster,
    rule_deleted_shortly_after_modification,
    rule_unrecognized_version,
    rule_content_already_purged,
)

FILETIME_EPOCH_DELTA = 11644473600
FILETIME_TICKS_PER_SECOND = 10_000_000


def datetime_to_filetime(dt):
    unix_seconds = (dt - datetime(1970, 1, 1)).total_seconds()
    filetime_seconds = unix_seconds + FILETIME_EPOCH_DELTA
    return int(filetime_seconds * FILETIME_TICKS_PER_SECOND)


def build_v1_bytes(file_size, deleted_time, original_path):
    """Build real, spec-conformant version-1 $I bytes: 8+8+8 header then a
    fixed 520-byte (260 WCHAR) UTF-16LE NUL-terminated/padded path."""
    header = struct.pack("<qqq", 1, file_size, datetime_to_filetime(deleted_time))
    path_bytes = original_path.encode("utf-16-le")
    padded = path_bytes + b"\x00" * (520 - len(path_bytes))
    assert len(padded) == 520
    return header + padded


def build_v2_bytes(file_size, deleted_time, original_path):
    """Build real, spec-conformant version-2 $I bytes: 8+8+8+4 header then a
    variable-length UTF-16LE path of exactly FileNameLength characters."""
    path_bytes = original_path.encode("utf-16-le")
    name_len = len(original_path)
    header = struct.pack("<qqqi", 2, file_size, datetime_to_filetime(deleted_time), name_len)
    return header + path_bytes


def write_i_file(directory, suffix, data):
    path = os.path.join(directory, f"$I{suffix}")
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def write_r_file(directory, suffix, content=b"recovered content"):
    path = os.path.join(directory, f"$R{suffix}")
    with open(path, "wb") as fh:
        fh.write(content)
    return path


# ---------------------------------------------------------------------------
# Rule-level unit tests with synthetic context dicts
# ---------------------------------------------------------------------------

def test_rule_sensitive_file_extension_detects_kdbx():
    context = {"i_file_path": "/x/$IABC.dat", "original_path": r"C:\Users\bob\Documents\vault.kdbx"}
    result = rule_sensitive_file_extension(context)
    assert result is not None
    assert result["rule_id"] == "WRB-001"


def test_rule_sensitive_file_extension_ignores_normal_file():
    context = {"i_file_path": "/x/$IABC.dat", "original_path": r"C:\Users\bob\Documents\report.docx"}
    assert rule_sensitive_file_extension(context) is None


def test_rule_sensitive_file_extension_detects_password_in_name():
    context = {"i_file_path": "/x/$IABC.dat", "original_path": r"C:\Users\bob\Desktop\my_password_list.txt"}
    result = rule_sensitive_file_extension(context)
    assert result is not None


def test_rule_recoverable_content_present():
    context = {"i_file_path": "/x/$IABC.dat", "r_file_path": "/x/$RABC.dat"}
    result = rule_recoverable_content_present(context)
    assert result["rule_id"] == "WRB-002"

    context_no_r = {"i_file_path": "/x/$IABC.dat", "r_file_path": None}
    assert rule_recoverable_content_present(context_no_r) is None


def test_rule_mass_deletion_cluster_threshold():
    base_context = {
        "i_file_path": "/x/$IABC.dat",
        "deleted_time": datetime(2026, 1, 1, 12, 0, 0),
    }
    below = dict(base_context, cluster_peer_count=4)
    at = dict(base_context, cluster_peer_count=5)
    assert rule_mass_deletion_cluster(below) is None
    assert rule_mass_deletion_cluster(at) is not None


def test_rule_deleted_shortly_after_modification():
    deleted = datetime(2026, 1, 1, 12, 0, 30)
    mtime = datetime(2026, 1, 1, 12, 0, 0)
    context = {
        "i_file_path": "/x/$IABC.dat",
        "original_path": r"C:\Users\bob\Documents\secret_report.docx",
        "deleted_time": deleted,
        "i_file_mtime": mtime,
    }
    result = rule_deleted_shortly_after_modification(context)
    assert result is not None
    assert result["rule_id"] == "WRB-004"

    far_context = dict(context, i_file_mtime=datetime(2025, 1, 1, 12, 0, 0))
    assert rule_deleted_shortly_after_modification(far_context) is None


def test_rule_unrecognized_version():
    context = {"i_file_path": "/x/$IABC.dat", "recognized": False, "version": 3, "raw_error": "bad"}
    result = rule_unrecognized_version(context)
    assert result["rule_id"] == "WRB-005"

    ok_context = {"i_file_path": "/x/$IABC.dat", "recognized": True, "version": 1}
    assert rule_unrecognized_version(ok_context) is None


def test_rule_content_already_purged():
    context = {"i_file_path": "/x/$IABC.dat", "recognized": True, "r_file_path": None, "original_path": "foo.txt"}
    result = rule_content_already_purged(context)
    assert result["rule_id"] == "WRB-006"

    with_r = dict(context, r_file_path="/x/$RABC.dat")
    assert rule_content_already_purged(with_r) is None


def test_filetime_conversion_roundtrip():
    dt = datetime(2024, 6, 15, 10, 30, 0)
    ft = datetime_to_filetime(dt)
    back = filetime_to_datetime(ft)
    assert abs((back - dt).total_seconds()) < 1


# ---------------------------------------------------------------------------
# Engine-level tests: real bytes, real files, real ScanEngine.run()
# ---------------------------------------------------------------------------

def test_engine_parses_v1_sensitive_file_with_recoverable_content():
    tmpdir = tempfile.mkdtemp()
    try:
        deleted_time = datetime.utcnow() - timedelta(days=1)
        data = build_v1_bytes(2048, deleted_time, r"C:\Users\alice\Documents\vault.kdbx")
        write_i_file(tmpdir, "AB1234.kdbx", data)
        write_r_file(tmpdir, "AB1234.kdbx")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WRB-001" in rule_ids
        assert "WRB-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_v2_variable_length_path():
    tmpdir = tempfile.mkdtemp()
    try:
        deleted_time = datetime.utcnow() - timedelta(days=2)
        original_path = r"C:\Users\bob\Downloads\normal_report_with_a_long_name.pdf"
        data = build_v2_bytes(4096, deleted_time, original_path)
        write_i_file(tmpdir, "CD5678.pdf", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        # No $R file written -> content already purged
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WRB-006" in rule_ids
        assert "WRB-002" not in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_v2_no_matching_r_file_flags_purged():
    tmpdir = tempfile.mkdtemp()
    try:
        deleted_time = datetime.utcnow() - timedelta(days=5)
        data = build_v2_bytes(100, deleted_time, r"C:\Users\carol\Desktop\notes.txt")
        write_i_file(tmpdir, "EF9999.txt", data)
        # deliberately no $R file

        engine = ScanEngine(tmpdir)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WRB-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_malformed_unrecognized_version_reported_not_crashed():
    tmpdir = tempfile.mkdtemp()
    try:
        # Bogus version field (99) — should be caught, not crash the scan.
        data = struct.pack("<qqq", 99, 10, 0) + b"\x00" * 520
        write_i_file(tmpdir, "GH0000.bin", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WRB-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_truncated_file_does_not_crash_scan():
    tmpdir = tempfile.mkdtemp()
    try:
        # Only 10 bytes — claims version 1 but is far too short.
        data = struct.pack("<q", 1) + b"\x00\x00"
        write_i_file(tmpdir, "IJ1111.dat", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 1
        assert isinstance(result["findings"], list)
    finally:
        shutil.rmtree(tmpdir)


def test_engine_mass_deletion_cluster_detected():
    tmpdir = tempfile.mkdtemp()
    try:
        base_time = datetime.utcnow() - timedelta(days=1)
        # 6 files deleted within a 60-second window -> cluster of 5+ peers each.
        for i in range(6):
            deleted_time = base_time + timedelta(seconds=i * 5)
            data = build_v2_bytes(500, deleted_time, rf"C:\Users\dave\Downloads\file{i}.tmp")
            write_i_file(tmpdir, f"CL{i:04d}.tmp", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 6
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert rule_ids.count("WRB-003") == 6
    finally:
        shutil.rmtree(tmpdir)


def test_engine_no_mass_deletion_cluster_when_spread_out():
    tmpdir = tempfile.mkdtemp()
    try:
        base_time = datetime.utcnow() - timedelta(days=10)
        for i in range(6):
            deleted_time = base_time + timedelta(hours=i * 3)
            data = build_v2_bytes(500, deleted_time, rf"C:\Users\erin\Downloads\spread{i}.tmp")
            write_i_file(tmpdir, f"SP{i:04d}.tmp", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "WRB-003" not in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_deleted_shortly_after_modification_via_mtime():
    tmpdir = tempfile.mkdtemp()
    try:
        deleted_time = datetime.utcnow()
        data = build_v1_bytes(1024, deleted_time, r"C:\Users\frank\Documents\quarterly_report.docx")
        path = write_i_file(tmpdir, "KL2222.docx", data)
        # $I file's own mtime is the real filesystem write time, which just
        # happened -> very close to deleted_time (well within 120s window).

        engine = ScanEngine(tmpdir)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WRB-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_directory_with_no_i_files_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "regular_file.txt"), "w") as fh:
            fh.write("hello")

        engine = ScanEngine(tmpdir)
        result = engine.run()
        assert result["files_scanned"] == 0
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_engine_nested_directories_are_walked():
    tmpdir = tempfile.mkdtemp()
    try:
        nested = os.path.join(tmpdir, "SID-1-2-3", "sub")
        os.makedirs(nested)
        deleted_time = datetime.utcnow() - timedelta(days=3)
        data = build_v2_bytes(50, deleted_time, r"C:\Users\gina\Desktop\deep.txt")
        write_i_file(nested, "MN3333.txt", data)

        engine = ScanEngine(tmpdir)
        result = engine.run()
        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] >= 2
    finally:
        shutil.rmtree(tmpdir)
