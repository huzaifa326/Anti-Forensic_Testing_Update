"""
CyberForensX — Log Collector
Module: acquisition/log_collector.py

Collects critical Linux log files:
  - /var/log/syslog
  - /var/log/auth.log

Files are copied to storage/raw/logs/ with a timestamp suffix.
Each copy is immediately hashed and recorded in the database.
"""

import os
import shutil
import logging
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SYSLOG_PATH, AUTHLOG_PATH, RAW_LOGS_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _timestamp_label() -> str:
    """Return a UTC timestamp string suitable for filenames."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _copy_log(source_path: str, artifact_type: str,
              case_id: str, investigator: str) -> dict | None:
    """
    Copy a single log file to storage/raw/logs/, compute its hash,
    and record it in the database.

    Args:
        source_path:   Absolute path to the original log file.
        artifact_type: Label for database (e.g. 'syslog', 'auth_log').
        case_id:       Active forensic case identifier.
        investigator:  Name of the investigator running the collection.

    Returns:
        Hash record dict if successful, None if source file not found.
    """
    if not os.path.isfile(source_path):
        logger.warning("Log file not found, skipping: %s", source_path)
        return None

    os.makedirs(RAW_LOGS_DIR, exist_ok=True)

    basename    = os.path.basename(source_path)
    dest_name   = f"{basename}_{_timestamp_label()}"
    dest_path   = os.path.join(RAW_LOGS_DIR, dest_name)

    try:
        shutil.copy2(source_path, dest_path)
    except PermissionError:
        logger.error("Permission denied to read %s. Are you running as root/sudo?", source_path)
        return None
    logger.info("Collected log: %s → %s", source_path, dest_path)

    # Hash immediately after copy — before any analysis touches the file
    hash_record = hash_artifact(dest_path)

    # Record in database
    artifact = Artifact(
        case_id       = case_id,
        artifact_name = dest_name,
        artifact_type = artifact_type,
        file_path     = dest_path,
        sha256_hash   = hash_record["sha256"],
        notes         = f"Copied from {source_path}"
    )
    artifact_id = insert_artifact(artifact)

    # Chain-of-custody entry
    entry = CustodyEntry(
        case_id      = case_id,
        artifact_id  = artifact_id,
        action       = "collected",
        performed_by = investigator,
        notes        = f"Log copied from {source_path}"
    )
    insert_custody_entry(entry)

    return {**hash_record, "artifact_id": artifact_id, "artifact_type": artifact_type}


def collect_syslog(case_id: str, investigator: str) -> dict | None:
    """
    Collect /var/log/syslog.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        Hash+metadata record, or None if the file is unavailable.
    """
    logger.info("Starting syslog collection for case: %s", case_id)
    return _copy_log(SYSLOG_PATH, "syslog", case_id, investigator)


def collect_authlog(case_id: str, investigator: str) -> dict | None:
    """
    Collect /var/log/auth.log.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        Hash+metadata record, or None if the file is unavailable.
    """
    logger.info("Starting auth.log collection for case: %s", case_id)
    return _copy_log(AUTHLOG_PATH, "auth_log", case_id, investigator)


def collect_journalctl(case_id: str, investigator: str) -> dict | None:
    """Collect logs from systemd journal (used on Kali/modern Linux where syslog is not present)."""
    import subprocess
    os.makedirs(RAW_LOGS_DIR, exist_ok=True)
    dest_name = f"journalctl_{_timestamp_label()}.txt"
    dest_path = os.path.join(RAW_LOGS_DIR, dest_name)

    try:
        # Run journalctl and pipe output to file
        with open(dest_path, "w") as f:
            subprocess.run(["journalctl", "--no-pager"], stdout=f, stderr=subprocess.DEVNULL, check=True)
        
        logger.info("Collected journalctl logs → %s", dest_path)
        hash_record = hash_artifact(dest_path)
        
        artifact = Artifact(
            case_id       = case_id,
            artifact_name = dest_name,
            artifact_type = "journal_log",
            file_path     = dest_path,
            sha256_hash   = hash_record["sha256"],
            notes         = "Collected via journalctl (systemd)"
        )
        artifact_id = insert_artifact(artifact)
        insert_custody_entry(CustodyEntry(
            case_id=case_id, artifact_id=artifact_id,
            action="collected", performed_by=investigator,
            notes="journalctl export"
        ))
        return {**hash_record, "artifact_id": artifact_id, "artifact_type": "journal_log"}
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("Could not collect journalctl logs.")
        return None

def collect_all_logs(case_id: str, investigator: str) -> list[dict]:
    """
    Collect all supported Linux log files in one call.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        List of hash+metadata records for each successfully collected file.
    """
    logger.info("=== Log Collection Started | Case: %s ===", case_id)
    results = []

    has_syslog = False
    for fn in [collect_syslog, collect_authlog]:
        record = fn(case_id, investigator)
        if record:
            results.append(record)
            has_syslog = True

    # If neither syslog nor auth.log exist (e.g., Kali), try journalctl
    if not has_syslog:
        logger.info("Standard logs missing, attempting journalctl export...")
        record = collect_journalctl(case_id, investigator)
        if record:
            results.append(record)

    logger.info("=== Log Collection Complete: %d file(s) collected ===", len(results))
    return results


if __name__ == "__main__":
    # Quick standalone test — requires DB to be initialised first
    from database.db_setup import init_db
    init_db()
    records = collect_all_logs("CASE-TEST-001", "Hamna Ejaz")
    for r in records:
        print(f"  [{r['artifact_type']}] {r['filename']} sha256={r['sha256'][:20]}...")
