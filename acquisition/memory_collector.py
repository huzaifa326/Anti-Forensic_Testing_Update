"""
CyberForensX — Memory Collector (LiME)
Module: acquisition/memory_collector.py

Iteration 1 Stub:  Sets up the memory collection interface.
Full LiME integration is targeted for Iteration 3.

LiME (Linux Memory Extractor) requires:
  - A kernel module compiled for the EXACT kernel version of the target machine.
  - Root/sudo privileges to load the kernel module.

Pre-requisite (compile LiME):
    git clone https://github.com/504ensicsLabs/LiME
    cd LiME/src && make
    # This produces lime-<kernel_version>.ko
"""

import os
import subprocess
import logging
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_MEMORY_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def capture_ram(lime_module_path: str, case_id: str,
                investigator: str) -> dict | None:
    """
    Capture a full RAM dump using LiME (Linux Memory Extractor).

    The LiME kernel module must be pre-compiled for the target kernel.
    Run `uname -r` to check kernel version, then compile LiME accordingly.

    Args:
        lime_module_path: Absolute path to the compiled lime-<version>.ko file.
        case_id:          Active forensic case identifier.
        investigator:     Name of the investigator.

    Returns:
        Hash+metadata record dict, or None on failure.
    """
    if not os.path.isfile(lime_module_path):
        logger.error("LiME module not found: %s\n"
                     "Compile LiME for kernel version: %s",
                     lime_module_path,
                     subprocess.getoutput("uname -r"))
        return None

    os.makedirs(RAW_MEMORY_DIR, exist_ok=True)
    output_file = os.path.join(RAW_MEMORY_DIR, f"ram_dump_{_timestamp_label()}.lime")

    logger.info("Starting RAM capture → %s", output_file)
    logger.warning("This operation requires root/sudo privileges.")

    try:
        subprocess.run(
            ["insmod", lime_module_path,
             f"path={output_file}", "format=lime"],
            check=True, timeout=300
        )
        # Remove the module after capture
        subprocess.run(["rmmod", "lime"], check=False)
        logger.info("RAM dump complete: %s", output_file)

    except subprocess.CalledProcessError as e:
        logger.error("LiME insmod failed: %s", e)
        return None
    except subprocess.TimeoutExpired:
        logger.error("RAM capture timed out (>5 min).")
        return None

    if not os.path.isfile(output_file):
        logger.error("RAM dump file was not created — check LiME output.")
        return None

    hash_record = hash_artifact(output_file)

    artifact = Artifact(
        case_id       = case_id,
        artifact_name = os.path.basename(output_file),
        artifact_type = "memory_dump",
        file_path     = output_file,
        sha256_hash   = hash_record["sha256"],
        notes         = f"LiME RAM dump using module: {lime_module_path}"
    )
    artifact_id = insert_artifact(artifact)
    insert_custody_entry(CustodyEntry(
        case_id=case_id, artifact_id=artifact_id,
        action="collected", performed_by=investigator,
        notes="Full RAM dump via LiME"
    ))

    return {**hash_record, "artifact_id": artifact_id, "artifact_type": "memory_dump"}


def check_lime_available(lime_module_path: str) -> bool:
    """
    Check whether the LiME module is available and the kernel version matches.

    Args:
        lime_module_path: Path to the .ko file.

    Returns:
        True if the module file exists, False otherwise.
    """
    kernel = subprocess.getoutput("uname -r")
    exists = os.path.isfile(lime_module_path)
    if exists:
        logger.info("LiME module found: %s (kernel: %s)", lime_module_path, kernel)
    else:
        logger.warning("LiME module NOT found at: %s (kernel: %s)", lime_module_path, kernel)
        logger.info("Compile LiME: cd LiME/src && make — produces lime-%s.ko", kernel)
    return exists
