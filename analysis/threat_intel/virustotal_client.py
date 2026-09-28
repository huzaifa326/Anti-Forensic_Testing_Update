"""
CyberForensX — VirusTotal Client
Module: analysis/threat_intel/virustotal_client.py

Queries VirusTotal API v3 to check file hashes against known malware databases.
Used as part of the Iteration 2 threat intelligence integration.

Configuration:
  Set VT_API_KEY environment variable or configure in config/settings.py

API Reference:
  https://developers.virustotal.com/reference/file-info
"""

import hashlib
import os
import json
import logging
from datetime import datetime, timezone

import requests

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.settings import VIRUSTOTAL_API_KEY, PROCESSED_DIR

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


# ─────────────────────────────────────────────────────────────────────────────
# Hash Computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_file_sha256(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file.

    Args:
        file_path: Absolute path to the file.

    Returns:
        Lowercase hex SHA-256 digest.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# VirusTotal Lookup
# ─────────────────────────────────────────────────────────────────────────────

def check_hash(file_hash: str, api_key: str = None) -> dict:
    """
    Query VirusTotal for a file hash.

    Args:
        file_hash: SHA-256 (or MD5/SHA-1) hash string.
        api_key:   VirusTotal API key. Falls back to config if not provided.

    Returns:
        Dict with keys:
          - hash: the queried hash
          - found: bool
          - positives: number of AV engines flagging as malicious
          - total: total AV engines
          - scan_date: last analysis date
          - threat_label: consensus threat label (if any)
          - permalink: URL to VT report
          - status: 'success' | 'not_found' | 'error'
          - error: error message (if status == 'error')
    """
    key = api_key or VIRUSTOTAL_API_KEY
    if not key:
        logger.warning("VirusTotal API key not configured. Set VT_API_KEY env var.")
        return {
            "hash": file_hash,
            "found": False,
            "status": "error",
            "error": "API key not configured. Set VT_API_KEY environment variable.",
        }

    url = f"{VT_API_BASE}/files/{file_hash}"
    headers = {"x-apikey": key}

    try:
        resp = requests.get(url, headers=headers, timeout=30)

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())

            return {
                "hash": file_hash,
                "found": True,
                "positives": positives,
                "total": total,
                "scan_date": attrs.get("last_analysis_date", ""),
                "threat_label": attrs.get("popular_threat_classification", {})
                                     .get("suggested_threat_label", ""),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                "status": "success",
            }
        elif resp.status_code == 404:
            return {
                "hash": file_hash,
                "found": False,
                "status": "not_found",
                "error": "Hash not found in VirusTotal database.",
            }
        elif resp.status_code == 401:
            return {
                "hash": file_hash,
                "found": False,
                "status": "error",
                "error": "Invalid VirusTotal API key.",
            }
        elif resp.status_code == 429:
            return {
                "hash": file_hash,
                "found": False,
                "status": "error",
                "error": "VirusTotal rate limit exceeded. Try again later.",
            }
        else:
            return {
                "hash": file_hash,
                "found": False,
                "status": "error",
                "error": f"VirusTotal API returned HTTP {resp.status_code}.",
            }

    except requests.RequestException as e:
        logger.error("VirusTotal API request failed: %s", e)
        return {
            "hash": file_hash,
            "found": False,
            "status": "error",
            "error": f"Network error: {str(e)}",
        }


def check_file(file_path: str, api_key: str = None) -> dict:
    """
    Compute the SHA-256 of a file and check it against VirusTotal.

    Args:
        file_path: Absolute path to the file to check.
        api_key:   VirusTotal API key (optional, uses config default).

    Returns:
        VirusTotal result dict (same as check_hash) with added 'file_path' key.
    """
    try:
        sha256 = compute_file_sha256(file_path)
    except PermissionError:
        logger.warning("Permission denied reading %s — skipping VT check.", file_path)
        return {
            "hash": "",
            "file_path": file_path,
            "filename": os.path.basename(file_path),
            "found": False,
            "status": "error",
            "error": f"Permission denied: {file_path}",
        }
    logger.info("Checking VirusTotal for %s (SHA-256: %s...)", 
                os.path.basename(file_path), sha256[:16])
    result = check_hash(sha256, api_key)
    result["file_path"] = file_path
    result["filename"] = os.path.basename(file_path)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Batch scan collected artifacts
# ─────────────────────────────────────────────────────────────────────────────

def scan_artifacts(artifact_paths: list[str], api_key: str = None) -> list[dict]:
    """
    Scan a list of artifact files against VirusTotal.

    Args:
        artifact_paths: List of file paths to scan.
        api_key:        VirusTotal API key (optional).

    Returns:
        List of result dicts for each file.
    """
    results = []
    for path in artifact_paths:
        if not os.path.isfile(path):
            logger.warning("Skipping missing file: %s", path)
            continue
        result = check_file(path, api_key)
        results.append(result)
        logger.info(
            "VT result for %s: %s",
            os.path.basename(path),
            result.get("status", "unknown"),
        )
    return results


def save_threat_intel_results(results: list[dict], output_path: str = None) -> str:
    """
    Save threat intelligence results to JSON.

    Args:
        results:     List of VT result dicts.
        output_path: Destination path. Defaults to storage/processed/threat_intel_matches.json

    Returns:
        The output path written to.
    """
    if output_path is None:
        output_path = os.path.join(PROCESSED_DIR, "threat_intel_matches.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "virustotal",
            "total_checked": len(results),
            "total_flagged": sum(1 for r in results if r.get("positives", 0) > 0),
            "results": results,
        }, f, indent=2)

    logger.info("Threat intel results saved to: %s", output_path)
    return output_path
