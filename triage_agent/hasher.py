"""
CyberForensX — Artifact Hashing Utility
Module: integrity/hashing.py

Computes SHA-256 (and optionally MD5) hashes for collected artifacts.
Called immediately after acquisition to ensure the chain-of-custody is
established before any analysis modifies the data.
"""

import hashlib
import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute the SHA-256 hash of a file.

    Reads in chunks to handle large files (e.g., RAM dumps) without
    loading the entire file into memory.

    Args:
        file_path:  Absolute path to the file.
        chunk_size: Read buffer size in bytes (default 64 KB).

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Artifact not found for hashing: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    logger.info("SHA-256 [%s]: %s", os.path.basename(file_path), digest)
    return digest


def compute_md5(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute the MD5 hash of a file.

    MD5 is provided for legacy compatibility with some forensic tools,
    but SHA-256 is the primary integrity mechanism in CyberForensX.

    Args:
        file_path:  Absolute path to the file.
        chunk_size: Read buffer size in bytes.

    Returns:
        Lowercase hexadecimal MD5 digest string.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Artifact not found for hashing: {file_path}")

    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_artifact(file_path: str) -> dict:
    """
    Compute both SHA-256 and MD5 hashes for an artifact and return
    a structured evidence record.

    Args:
        file_path: Absolute path to the artifact file.

    Returns:
        dict with keys: file_path, filename, sha256, md5, size_bytes, hashed_at
    """
    sha256 = compute_sha256(file_path)
    md5    = compute_md5(file_path)
    size   = os.path.getsize(file_path)

    record = {
        "file_path"  : file_path,
        "filename"   : os.path.basename(file_path),
        "sha256"     : sha256,
        "md5"        : md5,
        "size_bytes" : size,
        "hashed_at"  : datetime.now(timezone.utc).isoformat(),
    }
    return record


def save_hash_manifest(artifacts: list[dict], output_path: str, case_id: str = None, title: str = None, investigator: str = None) -> None:
    """
    Save a JSON manifest of artifact hashes to disk.

    This manifest can be presented as forensic evidence that files were
    not modified after collection.

    Args:
        artifacts:    List of hash records (from hash_artifact()).
        output_path:  Where to write the JSON manifest file.
        case_id:      Optional case ID string associated with collection.
        title:        Optional case title string.
        investigator: Optional investigator name string.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": artifacts
    }
    if case_id:
        payload["case_id"] = case_id
    if title:
        payload["title"] = title
    if investigator:
        payload["investigator"] = investigator

    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    logger.info("Hash manifest saved: %s", output_path)



def verify_artifact(file_path: str, expected_sha256: str) -> bool:
    """
    Verify an artifact's integrity by recomputing its hash and comparing
    it against the expected value stored at collection time.

    Args:
        file_path:       Absolute path to the artifact.
        expected_sha256: Hash recorded at the time of collection.

    Returns:
        True if the hash matches (artifact is intact), False otherwise.
    """
    current = compute_sha256(file_path)
    match = (current == expected_sha256.lower())
    if match:
        logger.info("Integrity OK: %s", os.path.basename(file_path))
    else:
        logger.warning(
            "INTEGRITY MISMATCH: %s — expected %s, got %s",
            os.path.basename(file_path), expected_sha256, current
        )
    return match
