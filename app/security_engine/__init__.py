"""
Security Engine — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Walks a REAL directory tree on the host filesystem looking for `$I*` Recycle
Bin metadata files (as found under `$Recycle.Bin\\{SID}\\` on a Windows
volume, or any exported/mounted copy of that folder) and real-parses their
actual bytes per the documented on-disk format:

Version 1 (Vista through Windows 7/8):
    offset 0   int64  Version              (== 1)
    offset 8   int64  FileSize             (original deleted file size, bytes)
    offset 16  int64  DeletedTime          (FILETIME: 100ns ticks since 1601-01-01 UTC)
    offset 24  520B   OriginalFilePath     (UTF-16LE, fixed 260 WCHAR, NUL-padded)
    total: 544 bytes

Version 2 (Windows 10 1809+):
    offset 0   int64  Version              (== 2)
    offset 8   int64  FileSize
    offset 16  int64  DeletedTime          (FILETIME)
    offset 24  int32  FileNameLength       (character count of path that follows)
    offset 28  ...    OriginalFilePath     (UTF-16LE, FileNameLength wchars, variable length)

For every `$I` file successfully or partially parsed, the engine also
real-checks (os.path.exists) whether a matching `$R` file — same directory,
same random suffix after the 2-character `$I`/`$R` prefix — is present on
disk, since that is the actual recoverable file content.

No sample/mock data is ever generated. Malformed, truncated, or
unrecognized-version `$I` files are caught per-file and counted in
errors_count/parse-notes; they never crash the whole scan.
"""
import os
import struct
import time
from datetime import datetime, timedelta

from app.detection_rules import ALL_RULES

DEFAULT_EXCLUDES = set()

# FILETIME epoch (1601-01-01 UTC) to Unix epoch (1970-01-01 UTC), in seconds.
_FILETIME_EPOCH_DELTA = 11644473600
_FILETIME_TICKS_PER_SECOND = 10_000_000

# Batch/mass-deletion clustering window used by WRB-003.
MASS_DELETION_WINDOW_SECONDS = 60
MASS_DELETION_MIN_CLUSTER = 5

V1_HEADER_SIZE = 24          # Version + FileSize + DeletedTime
V1_PATH_FIELD_SIZE = 520     # fixed 260 UTF-16LE wchars
V1_TOTAL_SIZE = V1_HEADER_SIZE + V1_PATH_FIELD_SIZE

V2_HEADER_SIZE = 28          # Version + FileSize + DeletedTime + FileNameLength


def filetime_to_datetime(filetime_int):
    """Real conversion of a Windows FILETIME (100ns ticks since 1601-01-01 UTC)
    into a Python datetime (UTC). Returns None for an out-of-range value."""
    try:
        seconds = filetime_int / _FILETIME_TICKS_PER_SECOND
        unix_seconds = seconds - _FILETIME_EPOCH_DELTA
        return datetime(1970, 1, 1) + timedelta(seconds=unix_seconds)
    except (OverflowError, OSError, ValueError):
        return None


def parse_dollar_i_file(path):
    """Real-parse the raw bytes of a single `$I` metadata file.

    Returns a dict:
        {
            "version": int or None,
            "file_size": int or None,
            "deleted_time": datetime or None,
            "original_path": str or None,
            "recognized": bool,
            "raw_error": str or None,
        }
    Never raises — malformed input yields recognized=False with raw_error set.
    """
    info = {
        "version": None,
        "file_size": None,
        "deleted_time": None,
        "original_path": None,
        "recognized": False,
        "raw_error": None,
    }
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        info["raw_error"] = f"could not read file: {exc}"
        return info

    if len(data) < 8:
        info["raw_error"] = "file too short to contain a version field"
        return info

    version = struct.unpack("<q", data[0:8])[0]
    info["version"] = version

    if version == 1:
        if len(data) < V1_TOTAL_SIZE:
            info["raw_error"] = (
                f"truncated version-1 record (need {V1_TOTAL_SIZE} bytes, got {len(data)})"
            )
            return info
        file_size, deleted_time_raw = struct.unpack("<qq", data[8:24])
        path_bytes = data[V1_HEADER_SIZE:V1_TOTAL_SIZE]
        try:
            original_path = path_bytes.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
        except UnicodeDecodeError as exc:
            info["raw_error"] = f"could not decode original path: {exc}"
            return info

        info["file_size"] = file_size
        info["deleted_time"] = filetime_to_datetime(deleted_time_raw)
        info["original_path"] = original_path
        info["recognized"] = True
        return info

    if version == 2:
        if len(data) < V2_HEADER_SIZE:
            info["raw_error"] = (
                f"truncated version-2 header (need {V2_HEADER_SIZE} bytes, got {len(data)})"
            )
            return info
        file_size, deleted_time_raw, name_len = struct.unpack("<qqi", data[8:28])
        if name_len < 0:
            info["raw_error"] = "negative FileNameLength in version-2 header"
            return info
        expected_bytes = name_len * 2
        path_bytes = data[V2_HEADER_SIZE:V2_HEADER_SIZE + expected_bytes]
        if len(path_bytes) < expected_bytes:
            info["raw_error"] = (
                f"truncated version-2 path (need {expected_bytes} bytes, got {len(path_bytes)})"
            )
            # Still attempt a best-effort decode of what we have.
        try:
            original_path = path_bytes.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except UnicodeDecodeError as exc:
            info["raw_error"] = f"could not decode original path: {exc}"
            return info

        info["file_size"] = file_size
        info["deleted_time"] = filetime_to_datetime(deleted_time_raw)
        info["original_path"] = original_path
        info["recognized"] = True
        return info

    info["raw_error"] = f"unrecognized Version field value: {version}"
    return info


def find_matching_r_file(i_file_path):
    """Real os.path.exists check for the `$R` companion of a `$I` file — same
    directory, `$I` -> `$R` prefix swap, identical remainder of the filename."""
    directory, filename = os.path.split(i_file_path)
    if len(filename) < 2 or filename[0] != "$" or filename[1] != "I":
        return None
    r_filename = "$R" + filename[2:]
    r_path = os.path.join(directory, r_filename)
    return r_path if os.path.exists(r_path) else None


class ScanEngine:
    """Real, synchronous scan of a directory tree for Recycle Bin `$I`
    metadata files. Every finding reflects bytes actually parsed from disk —
    nothing is simulated."""

    def __init__(self, target_path, max_depth=8, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

        # Accumulated across the whole run, used for WRB-003 mass-deletion
        # cluster detection (real per-file cluster membership).
        self._parsed_records = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real filesystem walk + real binary parse. Returns summary dict."""
        start = time.time()
        self._walk(self.target_path, depth=0)
        self._apply_cross_scan_rules()
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                self._walk(full_path, depth + 1)
                continue

            name = entry.name
            if len(name) >= 2 and name[0] == "$" and name[1] == "I":
                self._process_i_file(full_path)
                self.files_scanned += 1

    def _process_i_file(self, path):
        try:
            record = parse_dollar_i_file(path)
        except Exception:
            self.errors_count += 1
            return

        try:
            i_stat = os.stat(path)
        except OSError:
            i_stat = None

        r_path = find_matching_r_file(path)

        record["i_file_path"] = path
        record["r_file_path"] = r_path
        record["i_file_mtime"] = (
            datetime.utcfromtimestamp(i_stat.st_mtime) if i_stat else None
        )

        if not record["recognized"]:
            self.errors_count += 1

        self._parsed_records.append(record)
        self._apply_per_file_rules(record)

    def _apply_per_file_rules(self, record):
        """Apply the rules that only need this single record's data (WRB-001,
        WRB-002, WRB-004, WRB-005, WRB-006). WRB-003 needs the full-run
        cluster and is applied afterwards in _apply_cross_scan_rules."""
        context = self._build_context(record)
        for rule in ALL_RULES:
            if rule.__name__ == "rule_mass_deletion_cluster":
                continue
            self._run_rule(rule, context)

    def _apply_cross_scan_rules(self):
        """Real cross-record mass-deletion clustering: group every real
        parsed deletion timestamp collected during this run() call and check
        real per-file cluster membership within a 60-second window shared by
        5+ OTHER files."""
        from app.detection_rules import rule_mass_deletion_cluster

        timestamps = [
            (idx, rec["deleted_time"])
            for idx, rec in enumerate(self._parsed_records)
            if rec.get("deleted_time") is not None
        ]

        for idx, ts in timestamps:
            others_in_window = 0
            for other_idx, other_ts in timestamps:
                if other_idx == idx:
                    continue
                delta = abs((ts - other_ts).total_seconds())
                if delta <= MASS_DELETION_WINDOW_SECONDS:
                    others_in_window += 1
            record = self._parsed_records[idx]
            context = self._build_context(record)
            context["cluster_peer_count"] = others_in_window
            self._run_rule(rule_mass_deletion_cluster, context)

    def _build_context(self, record):
        return {
            "i_file_path": record.get("i_file_path"),
            "r_file_path": record.get("r_file_path"),
            "i_file_mtime": record.get("i_file_mtime"),
            "version": record.get("version"),
            "file_size": record.get("file_size"),
            "deleted_time": record.get("deleted_time"),
            "original_path": record.get("original_path"),
            "recognized": record.get("recognized"),
            "raw_error": record.get("raw_error"),
        }

    def _run_rule(self, rule, context):
        try:
            result = rule(context)
        except Exception:
            self.errors_count += 1
            return
        if result:
            result["file_path"] = context["i_file_path"]
            result["permissions_octal"] = _summarize(context)
            result["owner_uid"] = None
            result["owner_gid"] = None
            self.findings.append(result)


def _summarize(context):
    """Repurposed field: holds a compact human-readable summary of the real
    parsed original filename + size instead of a permission mode."""
    original_path = context.get("original_path") or "?"
    name = original_path.rsplit("\\", 1)[-1] if original_path else "?"
    size = context.get("file_size")
    size_txt = f"{size}B" if isinstance(size, int) and size >= 0 else "?"
    return f"{name} ({size_txt})"
