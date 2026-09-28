"""
CyberForensX — Disk Artifact Collector
Module: acquisition/disk_collector.py

Iteration 1: Collects non-volatile disk artifacts:
  - Bash history (delegates to bash_history_collector)
  - System configuration files (/etc/passwd, /etc/shadow, /etc/hosts, /etc/hostname)
  - EXT4 inode metadata (via `stat` + `debugfs`) — stub for Iteration 2

Each file is hashed immediately after copy and recorded in the database.
"""

import os
import shutil
import logging
import subprocess
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_DISK_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# System config files to collect
CONFIG_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/fstab",
    "/etc/crontab",
]


def _timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _copy_file(source_path: str, artifact_type: str,
               case_id: str, investigator: str) -> dict | None:
    """Copy a file to storage/raw/disk/, hash it, and register it in the DB."""
    if not os.path.isfile(source_path):
        logger.warning("Disk artifact not found, skipping: %s", source_path)
        return None

    os.makedirs(RAW_DISK_DIR, exist_ok=True)
    basename  = os.path.basename(source_path).replace("/", "_")
    dest_name = f"{basename}_{_timestamp_label()}"
    dest_path = os.path.join(RAW_DISK_DIR, dest_name)

    try:
        shutil.copy2(source_path, dest_path)
    except PermissionError:
        logger.error("Permission denied to read %s. Run as root/sudo to collect this.", source_path)
        return None
    logger.info("Collected: %s → %s", source_path, dest_path)

    hash_record = hash_artifact(dest_path)

    artifact = Artifact(
        case_id       = case_id,
        artifact_name = dest_name,
        artifact_type = artifact_type,
        file_path     = dest_path,
        sha256_hash   = hash_record["sha256"],
        notes         = f"Copied from {source_path}"
    )
    artifact_id = insert_artifact(artifact)

    entry = CustodyEntry(
        case_id      = case_id,
        artifact_id  = artifact_id,
        action       = "collected",
        performed_by = investigator,
        notes        = f"Disk artifact from {source_path}"
    )
    insert_custody_entry(entry)

    return {**hash_record, "artifact_id": artifact_id, "artifact_type": artifact_type}


def collect_config_files(case_id: str, investigator: str) -> list[dict]:
    """
    Collect system configuration files listed in CONFIG_FILES.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        List of hash+metadata records for collected files.
    """
    logger.info("=== System Config Collection | Case: %s ===", case_id)
    results = []
    for path in CONFIG_FILES:
        record = _copy_file(path, "config_file", case_id, investigator)
        if record:
            results.append(record)
    logger.info("Config collection complete: %d file(s)", len(results))
    return results


def collect_ext4_metadata(device: str, case_id: str,
                          investigator: str) -> dict | None:
    """
    Collect EXT4 inode metadata from a block device using debugfs.

    NOTE: Requires root/sudo. Full EXT4 inode analysis is targeted for
    Iteration 2. This implementation captures the raw stat output.

    Args:
        device:       Block device path e.g. /dev/sda1
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        Record dict with the metadata output file path, or None on failure.
    """
    os.makedirs(RAW_DISK_DIR, exist_ok=True)
    output_file = os.path.join(RAW_DISK_DIR, f"ext4_metadata_{_timestamp_label()}.txt")

    try:
        result = subprocess.run(
            ["debugfs", "-R", "stats", device],
            capture_output=True, text=True, timeout=60
        )
        with open(output_file, "w") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        hash_record = hash_artifact(output_file)

        artifact = Artifact(
            case_id       = case_id,
            artifact_name = os.path.basename(output_file),
            artifact_type = "ext4_metadata",
            file_path     = output_file,
            sha256_hash   = hash_record["sha256"],
            notes         = f"EXT4 metadata from device {device}"
        )
        artifact_id = insert_artifact(artifact)
        insert_custody_entry(CustodyEntry(
            case_id=case_id, artifact_id=artifact_id,
            action="collected", performed_by=investigator,
            notes=f"debugfs stats on {device}"
        ))
        logger.info("EXT4 metadata collected from %s", device)
        return {**hash_record, "artifact_id": artifact_id, "artifact_type": "ext4_metadata"}

    except FileNotFoundError:
        logger.warning("debugfs not available on this system — skipping EXT4 metadata.")
        return None
    except subprocess.TimeoutExpired:
        logger.error("debugfs timed out for device: %s", device)
        return None


def collect_all_disk_artifacts(case_id: str, investigator: str,
                                device: str = None) -> list[dict]:
    """
    Run all disk artifact collectors for Iteration 1.

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.
        device:       Optional block device for EXT4 metadata (e.g. /dev/sda1).

    Returns:
        Combined list of all collected artifact records.
    """
    results = collect_config_files(case_id, investigator)
    if device:
        meta = collect_ext4_metadata(device, case_id, investigator)
        if meta:
            results.append(meta)
    return results
