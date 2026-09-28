"""
CyberForensX — Bash History Collector
Module: acquisition/bash_history_collector.py

Collects .bash_history from the current user (and optionally all users
on the system) and stores copies in storage/raw/disk/.

Each file is hashed immediately after copying and recorded in the
database with a chain-of-custody entry.
"""

import os
import shutil
import logging
import glob
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import BASH_HIST_PATH, RAW_DISK_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _collect_history_file(source_path: str, case_id: str,
                          investigator: str, username: str = "unknown") -> dict | None:
    """
    Copy a .bash_history file to storage/raw/disk/, hash it, and record it.

    Args:
        source_path:  Absolute path to the .bash_history file.
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.
        username:     System username the history belongs to.

    Returns:
        Hash record dict if successful, None if file is missing.
    """
    if not os.path.isfile(source_path):
        logger.warning("Bash history not found for user '%s': %s", username, source_path)
        return None

    os.makedirs(RAW_DISK_DIR, exist_ok=True)

    dest_name = f"bash_history_{username}_{_timestamp_label()}"
    dest_path = os.path.join(RAW_DISK_DIR, dest_name)

    # shutil.copy2 preserves mtime/atime — important for forensic timestamps
    shutil.copy2(source_path, dest_path)
    logger.info("Collected bash history [user=%s]: %s → %s",
                username, source_path, dest_path)

    # Hash immediately — establishes integrity before any parsing
    hash_record = hash_artifact(dest_path)

    artifact = Artifact(
        case_id       = case_id,
        artifact_name = dest_name,
        artifact_type = "bash_history",
        file_path     = dest_path,
        sha256_hash   = hash_record["sha256"],
        notes         = f"Bash history for user: {username}, source: {source_path}"
    )
    artifact_id = insert_artifact(artifact)

    entry = CustodyEntry(
        case_id      = case_id,
        artifact_id  = artifact_id,
        action       = "collected",
        performed_by = investigator,
        notes        = f"Bash history copied from {source_path}"
    )
    insert_custody_entry(entry)

    return {**hash_record, "artifact_id": artifact_id,
            "artifact_type": "bash_history", "username": username}


def collect_current_user_history(case_id: str, investigator: str) -> dict | None:
    """
    Collect .bash_history for the currently logged-in user.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        Hash record dict or None.
    """
    username = os.environ.get("USER", os.environ.get("LOGNAME", "current_user"))
    logger.info("Collecting bash history for current user: %s", username)
    return _collect_history_file(BASH_HIST_PATH, case_id, investigator, username)


def collect_all_users_history(case_id: str, investigator: str) -> list[dict]:
    """
    Collect .bash_history from all user home directories on the system.

    Scans /home/* and /root/ for .bash_history files.
    Requires appropriate read permissions (run as root/sudo for full coverage).

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        List of hash+metadata records for each collected file.
    """
    logger.info("=== All-User Bash History Collection | Case: %s ===", case_id)
    results = []

    # Look in /home/<user>/.bash_history and /root/.bash_history
    search_patterns = ["/home/*/.bash_history", "/root/.bash_history"]
    found_paths = []
    for pattern in search_patterns:
        found_paths.extend(glob.glob(pattern))

    if not found_paths:
        logger.warning("No bash_history files found — check permissions.")
        return results

    for path in found_paths:
        # Derive username from path
        parts = path.split(os.sep)
        if "home" in parts:
            username = parts[parts.index("home") + 1]
        else:
            username = "root"

        record = _collect_history_file(path, case_id, investigator, username)
        if record:
            results.append(record)

    logger.info("=== Bash History Collection Complete: %d file(s) ===", len(results))
    return results


def parse_bash_history(file_path: str) -> list[dict]:
    """
    Parse a collected bash_history file into a list of structured command entries.

    Each line in bash_history is treated as a single command. If the history
    file contains extended HISTTIMEFORMAT timestamps (lines starting with #),
    those are parsed and associated with the following command.

    Args:
        file_path: Absolute path to the collected bash_history copy.

    Returns:
        List of dicts with keys: line_number, timestamp (if available), command.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"History file not found: {file_path}")

    entries = []
    pending_timestamp = None
    line_number = 0

    with open(file_path, "r", errors="replace") as f:
        for line in f:
            line_number += 1
            line = line.rstrip("\n")

            if line.startswith("#") and len(line) > 1 and line[1:].isdigit():
                # HISTTIMEFORMAT extended timestamp line — convert epoch to ISO
                try:
                    epoch = int(line[1:])
                    pending_timestamp = datetime.fromtimestamp(
                        epoch, tz=timezone.utc).isoformat()
                except ValueError:
                    pending_timestamp = None
                continue

            if line:
                entries.append({
                    "line_number": line_number,
                    "timestamp"  : pending_timestamp,     # None if not in extended format
                    "command"    : line.strip()
                })
                pending_timestamp = None   # reset after associating with command

    logger.info("Parsed %d command entries from %s", len(entries), file_path)
    return entries


if __name__ == "__main__":
    from database.db_setup import init_db
    init_db()
    records = collect_current_user_history("CASE-TEST-001", "Hamna Ejaz")
    if records:
        print(f"Collected: {records[0]['filename']} sha256={records[0]['sha256'][:20]}...")
        parsed = parse_bash_history(records[0]["file_path"])
        print(f"Commands found: {len(parsed)}")
        for cmd in parsed[:5]:
            print(f"  [{cmd['line_number']}] {cmd['command']}")
