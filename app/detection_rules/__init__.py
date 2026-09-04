"""
Detection Rules — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL parsed `$I` record (built by app.security_engine
from actual bytes read off disk) and returns a Finding dict if the condition
is met. Rules are pure functions of a `context` dict so they can be unit
tested in isolation with synthetic context dicts, independent of the engine.

context dict shape (see ScanEngine._build_context):
    {
        "i_file_path": str,            # path to the $I metadata file itself
        "r_file_path": str or None,    # path to matching $R file, if present
        "i_file_mtime": datetime,      # real mtime of the $I file on disk
        "version": int or None,        # parsed header Version field
        "file_size": int or None,      # real original deleted-file size
        "deleted_time": datetime or None,  # real parsed FILETIME deletion time
        "original_path": str or None,  # real parsed original file path
        "recognized": bool,            # True if version 1 or 2 was parsed
        "raw_error": str or None,      # parse-note for malformed input
        "cluster_peer_count": int,     # only set for rule_mass_deletion_cluster
    }
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SENSITIVE_EXTENSIONS = (
    ".kdbx", ".pgp", ".pfx", ".p12", ".pem", "wallet.dat", ".env",
)
SENSITIVE_NAME_PATTERNS = ("password", "credential", "secret")

DOCUMENT_EXTENSIONS = (
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt",
    ".csv", ".odt", ".ods",
)


def rule_sensitive_file_extension(context):
    """WRB-001: The real parsed original file path has a sensitive-looking
    extension or filename pattern (password managers, PGP/PFX/PEM key
    material, crypto wallets, .env secrets, or names containing
    password/credential/secret). High-value forensic evidence of a
    deliberately deleted sensitive artifact."""
    original_path = context.get("original_path")
    if not original_path:
        return None
    lowered = original_path.lower()
    hit = None
    for ext in SENSITIVE_EXTENSIONS:
        if lowered.endswith(ext):
            hit = ext
            break
    if hit is None:
        for pattern in SENSITIVE_NAME_PATTERNS:
            if pattern in lowered:
                hit = pattern
                break
    if hit is None:
        return None
    return {
        "rule_id": "WRB-001",
        "rule_name": "Deleted Sensitive File Evidence",
        "severity": SEVERITY_HIGH,
        "description": (
            f"The Recycle Bin metadata at {context['i_file_path']} records a deleted "
            f"file whose original path is '{original_path}', matching sensitive "
            f"pattern '{hit}'. This is forensic evidence a sensitive file was deleted."
        ),
    }


def rule_recoverable_content_present(context):
    """WRB-002: A matching real `$R` file exists on disk next to the `$I`
    metadata file — the actual deleted file content has not been purged yet
    and is still recoverable. Useful for triaging which deletions to recover
    first before the content is permanently gone."""
    if not context.get("r_file_path"):
        return None
    return {
        "rule_id": "WRB-002",
        "rule_name": "Recoverable Deleted Content Present",
        "severity": SEVERITY_MEDIUM,
        "description": (
            f"A matching $R content file was found at {context['r_file_path']} for "
            f"metadata {context['i_file_path']} — the deleted file's actual bytes "
            f"are still recoverable on disk."
        ),
    }


def rule_mass_deletion_cluster(context):
    """WRB-003: This file's real parsed DeletedTime falls within an
    unusually narrow 60-second window shared by 5 or more OTHER real `$I`
    files scanned in the same run — evidence of a batch or mass-deletion
    event (e.g. a folder emptied, or anti-forensic cleanup) rather than
    routine individual deletions."""
    deleted_time = context.get("deleted_time")
    peer_count = context.get("cluster_peer_count", 0)
    if deleted_time is None:
        return None
    from app.security_engine import MASS_DELETION_MIN_CLUSTER
    if peer_count < MASS_DELETION_MIN_CLUSTER:
        return None
    return {
        "rule_id": "WRB-003",
        "rule_name": "Mass-Deletion Cluster",
        "severity": SEVERITY_LOW,
        "description": (
            f"{context['i_file_path']} was deleted at {deleted_time.isoformat()}Z, "
            f"within a 60-second window shared by {peer_count} other deleted files "
            f"in this scan — consistent with a batch/mass deletion."
        ),
    }


def rule_deleted_shortly_after_modification(context):
    """WRB-004: The real original file path indicates a sensitive source
    location (Documents, Desktop, or Recent/Downloads with a document-like
    extension) AND the real DeletedTime is very close to the $I file's own
    real filesystem mtime — i.e. the item was deleted shortly after it was
    last touched. This pattern is consistent with intentional
    destruction-after-use rather than routine cleanup of old files."""
    original_path = context.get("original_path")
    deleted_time = context.get("deleted_time")
    i_file_mtime = context.get("i_file_mtime")
    if not original_path or deleted_time is None or i_file_mtime is None:
        return None

    lowered = original_path.lower()
    is_sensitive_source = bool(re.search(r"\\users\\[^\\]+\\documents\\", lowered)) or "\\desktop\\" in lowered
    if not is_sensitive_source:
        has_doc_ext = any(lowered.endswith(ext) for ext in DOCUMENT_EXTENSIONS)
        in_recent_or_downloads = "recent" in lowered or "downloads" in lowered
        is_sensitive_source = has_doc_ext and in_recent_or_downloads

    if not is_sensitive_source:
        return None

    delta_seconds = abs((i_file_mtime - deleted_time).total_seconds())
    if delta_seconds > 120:
        return None

    return {
        "rule_id": "WRB-004",
        "rule_name": "Deleted Shortly After Modification",
        "severity": SEVERITY_MEDIUM,
        "description": (
            f"'{original_path}' was deleted at {deleted_time.isoformat()}Z, only "
            f"{delta_seconds:.0f}s from the $I metadata file's own mtime — the item "
            f"appears to have been deleted shortly after being last used, from a "
            f"sensitive source location."
        ),
    }


def rule_unrecognized_version(context):
    """WRB-005: The `$I` file's own header Version field did not match either
    known value (1 or 2). Reported as an informational parse-note rather than
    a crash — the metadata file may be corrupted, from an unsupported OS
    version, or not a genuine Recycle Bin record at all."""
    if context.get("recognized"):
        return None
    if context.get("version") is None:
        return None
    return {
        "rule_id": "WRB-005",
        "rule_name": "Unrecognized Metadata Version",
        "severity": SEVERITY_LOW,
        "description": (
            f"{context['i_file_path']} declares Version={context.get('version')}, "
            f"which is neither 1 nor 2. Parse note: {context.get('raw_error')}"
        ),
    }


def rule_content_already_purged(context):
    """WRB-006: A `$I` metadata file was found with NO matching `$R` file
    present — the recoverable content has already been purged (Recycle Bin
    emptied) or the entry expired. Still real forensic evidence that a
    specific, named file WAS deleted (name/size/time all known) even though
    its content can no longer be recovered from this location."""
    if not context.get("recognized"):
        return None
    if context.get("r_file_path"):
        return None
    return {
        "rule_id": "WRB-006",
        "rule_name": "Content Already Purged",
        "severity": SEVERITY_LOW,
        "description": (
            f"{context['i_file_path']} has no matching $R file — the content of "
            f"'{context.get('original_path')}' has already been purged, but the "
            f"deletion itself (name, size, time) remains provable from this metadata."
        ),
    }


ALL_RULES = [
    rule_sensitive_file_extension,
    rule_recoverable_content_present,
    rule_mass_deletion_cluster,
    rule_deleted_shortly_after_modification,
    rule_unrecognized_version,
    rule_content_already_purged,
]
