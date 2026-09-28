"""
CyberForensX — Feature Engineering / Unification Pipeline
Module: analysis/pipeline/feature_engineer.py

Maps heterogeneous parsed log formats (Syslog, Auth.log) into a common
feature set for downstream ML processing and timeline construction.

Common Feature Set:
  - timestamp    : ISO-8601 UTC
  - user_id      : Username associated with event
  - command_type : Type of command or action
  - origin_ip    : Source IP (primarily from auth events)
  - event_type   : Classification (system | auth | bash | network)
  - source       : Original log source identifier
  - raw_message  : Original log message for reference
"""

import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Unification — map disparate formats to common feature set
# ─────────────────────────────────────────────────────────────────────────────

def _unify_syslog_entry(entry: dict) -> dict:
    """Map a parsed syslog record to the common feature set."""
    return {
        "timestamp": entry.get("timestamp", ""),
        "user_id": "system",
        "command_type": entry.get("process", "unknown"),
        "origin_ip": "",
        "event_type": "system",
        "source": "syslog",
        "hostname": entry.get("hostname", ""),
        "raw_message": entry.get("message", ""),
    }


def _unify_authlog_entry(entry: dict) -> dict:
    """Map a parsed auth.log record to the common feature set."""
    return {
        "timestamp": entry.get("timestamp", ""),
        "user_id": entry.get("user", "unknown"),
        "command_type": entry.get("event_type", "auth"),
        "origin_ip": entry.get("ip", ""),
        "event_type": "auth",
        "source": "auth_log",
        "hostname": entry.get("hostname", ""),
        "raw_message": entry.get("message", ""),
    }


def _unify_bash_entry(entry: dict) -> dict:
    """Map a parsed bash history record to the common feature set."""
    return {
        "timestamp": entry.get("timestamp", ""),
        "user_id": entry.get("user", "unknown"),
        "command_type": "bash",
        "origin_ip": "",
        "event_type": "bash",
        "source": "bash_history",
        "hostname": "",
        "raw_message": entry.get("command", ""),
    }


def _unify_network_entry(entry: dict) -> dict:
    """Map a parsed network connection record to the common feature set."""
    return {
        "timestamp": entry.get("timestamp", ""),
        "user_id": entry.get("user", "system"),
        "command_type": "network",
        "origin_ip": entry.get("local_addr", ""),
        "event_type": "network",
        "source": "network",
        "hostname": "",
        "raw_message": entry.get("raw", str(entry)),
    }


def _unify_browser_entry(entry: dict) -> dict:
    """Map a parsed browser history record to the common feature set."""
    return {
        "timestamp": entry.get("timestamp", ""),
        "user_id": entry.get("username", "unknown"),
        "command_type": "browser_visit",
        "origin_ip": "",
        "event_type": "browser",
        "source": entry.get("source", "browser"),
        "hostname": "",
        "raw_message": f"Visited: {entry.get('url', '')} - Title: {entry.get('title', '')}",
    }


def _unify_ext4_entry(entry: dict) -> dict:
    """Map a parsed EXT4 metadata record to the common feature set."""
    return {
        "timestamp": "",  # Device wide metadata doesn't always have a strict unified timestamp of event
        "user_id": "system",
        "command_type": "filesystem_stat",
        "origin_ip": "",
        "event_type": "disk_metadata",
        "source": entry.get("source", "ext4"),
        "hostname": entry.get("last_mounted", ""),
        "raw_message": f"Volume: {entry.get('volume_name', '')} UUID: {entry.get('uuid', '')}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main Unification Function
# ─────────────────────────────────────────────────────────────────────────────

def unify_logs(
    syslog_entries: list[dict] = None,
    authlog_entries: list[dict] = None,
    bash_entries: list[dict] = None,
    network_entries: list[dict] = None,
    browser_entries: list[dict] = None,
    ext4_entries: list[dict] = None,
) -> list[dict]:
    """
    Unify parsed log entries from multiple sources into a common feature set.

    This is the critical bridge between the Acquisition and Analysis modules.
    It maps disparate log formats into a common JSON feature vector so
    downstream ML models and timeline builders can process them uniformly.

    Args:
        syslog_entries:  Parsed syslog records (from log_parser.parse_syslog)
        authlog_entries: Parsed auth.log records (from log_parser.parse_authlog)
        bash_entries:    Parsed bash history records
        network_entries: Parsed network connection records
        browser_entries: Parsed browser history records
        ext4_entries:    Parsed EXT4 metadata records

    Returns:
        List of unified feature dicts, sorted by timestamp.
    """
    unified = []

    if syslog_entries:
        for entry in syslog_entries:
            unified.append(_unify_syslog_entry(entry))

    if authlog_entries:
        for entry in authlog_entries:
            unified.append(_unify_authlog_entry(entry))

    if bash_entries:
        for entry in bash_entries:
            unified.append(_unify_bash_entry(entry))

    if network_entries:
        for entry in network_entries:
            unified.append(_unify_network_entry(entry))

    if browser_entries:
        for entry in browser_entries:
            unified.append(_unify_browser_entry(entry))

    if ext4_entries:
        for entry in ext4_entries:
            unified.append(_unify_ext4_entry(entry))

    # Sort by timestamp
    unified.sort(key=lambda e: e.get("timestamp", ""))

    logger.info(
        "Unification complete: %d total records "
        "(syslog=%d, auth=%d, bash=%d, network=%d, browser=%d, ext4=%d)",
        len(unified),
        len(syslog_entries or []),
        len(authlog_entries or []),
        len(bash_entries or []),
        len(network_entries or []),
        len(browser_entries or []),
        len(ext4_entries or []),
    )
    return unified


# ─────────────────────────────────────────────────────────────────────────────
# Save unified output
# ─────────────────────────────────────────────────────────────────────────────

def save_unified_logs(unified: list[dict], output_path: str) -> str:
    """
    Save the unified feature set to a JSON file.

    Args:
        unified:     List of unified feature dicts.
        output_path: Destination file path.

    Returns:
        The output_path written to.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Compute summary stats
    source_counts = {}
    for record in unified:
        src = record.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    with open(output_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(unified),
            "source_counts": source_counts,
            "records": unified,
        }, f, indent=2)

    logger.info("Unified logs saved to: %s (%d records)", output_path, len(unified))
    return output_path
