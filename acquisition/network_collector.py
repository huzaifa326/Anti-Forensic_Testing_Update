"""
CyberForensX — Network Connection Collector
Module: acquisition/network_collector.py

Iteration 1 Stub: Captures active network connections using `ss`.
Full implementation (parsing + JSON storage) is in Iteration 2.

Collected data is stored in storage/raw/network/ and hashed immediately.
"""

import os
import subprocess
import json
import logging
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_NETWORK_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def capture_network_connections(case_id: str, investigator: str) -> dict | None:
    """
    Capture active network connections using `ss -tunap`.

    Saves raw text output to storage/raw/network/ and hashes immediately.
    Full JSON parsing of the output is handled in the analysis pipeline (Iteration 2).

    Args:
        case_id:      Active forensic case identifier.
        investigator: Name of the investigator.

    Returns:
        Hash+metadata record dict, or None on failure.
    """
    os.makedirs(RAW_NETWORK_DIR, exist_ok=True)
    output_file = os.path.join(RAW_NETWORK_DIR, f"netstat_{_timestamp_label()}.txt")

    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True, text=True, timeout=30
        )
        with open(output_file, "w") as f:
            f.write(f"# Captured at: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        hash_record = hash_artifact(output_file)

        artifact = Artifact(
            case_id       = case_id,
            artifact_name = os.path.basename(output_file),
            artifact_type = "network",
            file_path     = output_file,
            sha256_hash   = hash_record["sha256"],
            notes         = "Active network connections via ss -tunap"
        )
        artifact_id = insert_artifact(artifact)
        insert_custody_entry(CustodyEntry(
            case_id=case_id, artifact_id=artifact_id,
            action="collected", performed_by=investigator,
            notes="Network connections captured via ss"
        ))
        logger.info("Network connections captured: %s", output_file)
        return {**hash_record, "artifact_id": artifact_id, "artifact_type": "network"}

    except FileNotFoundError:
        logger.warning("`ss` command not found — trying `netstat` fallback.")
        return _fallback_netstat(output_file, case_id, investigator)
    except subprocess.TimeoutExpired:
        logger.error("Network capture timed out.")
        return None


def _fallback_netstat(output_file: str, case_id: str, investigator: str) -> dict | None:
    """Fallback to netstat if ss is not available."""
    try:
        result = subprocess.run(
            ["netstat", "-tunap"],
            capture_output=True, text=True, timeout=30
        )
        with open(output_file, "w") as f:
            f.write(f"# Captured at: {datetime.now(timezone.utc).isoformat()} (via netstat)\n")
            f.write(result.stdout)

        hash_record = hash_artifact(output_file)
        artifact = Artifact(
            case_id       = case_id,
            artifact_name = os.path.basename(output_file),
            artifact_type = "network",
            file_path     = output_file,
            sha256_hash   = hash_record["sha256"],
            notes         = "Active connections via netstat -tunap (fallback)"
        )
        artifact_id = insert_artifact(artifact)
        insert_custody_entry(CustodyEntry(
            case_id=case_id, artifact_id=artifact_id,
            action="collected", performed_by=investigator,
            notes="Fallback: netstat used"
        ))
        return {**hash_record, "artifact_id": artifact_id, "artifact_type": "network"}
    except Exception as e:
        logger.error("Network capture failed: %s", e)
        return None
