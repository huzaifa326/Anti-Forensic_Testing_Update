"""
CyberForensX — Timeline Builder
Module: integrity/timeline_builder.py

Merges forensic events from multiple sources (syslog, auth.log, bash history,
network captures, file system metadata) into a single unified timeline.

All timestamps are normalized to ISO-8601 UTC and events are sorted
chronologically. Output is saved to storage/processed/unified_timeline.json.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import PROCESSED_DIR

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp Normalization
# ─────────────────────────────────────────────────────────────────────────────

def normalize_timestamp(ts: str) -> str:
    """
    Normalize a timestamp string to ISO-8601 UTC format.

    Handles common formats:
      - ISO-8601 with timezone  (2026-04-07T14:23:01+00:00)
      - ISO-8601 without tz     (2026-04-07T14:23:01)  — assumed UTC
      - Syslog-style            (Apr  7 14:23:01)      — current year, UTC

    Args:
        ts: Timestamp string in any supported format.

    Returns:
        ISO-8601 UTC string, or original string if parsing fails.
    """
    if not ts:
        return ""

    # Already ISO-8601 with timezone
    try:
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass

    # Syslog format: "Apr  7 14:23:01"
    try:
        year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass

    # Unix timestamp (numeric string)
    try:
        epoch = float(ts)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass

    logger.debug("Could not normalize timestamp: %s", ts)
    return ts


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Building
# ─────────────────────────────────────────────────────────────────────────────

def build_timeline(*sources: list[dict]) -> list[dict]:
    """
    Merge events from multiple sources into a single sorted timeline.

    Each event dict should have at minimum a 'timestamp' key.
    Additional keys are preserved as-is.

    Args:
        *sources: Variable number of event lists to merge.

    Returns:
        Single list of events sorted chronologically by normalized timestamp.
    """
    all_events = []

    for source in sources:
        if not source:
            continue
        for event in source:
            # Normalize the timestamp
            normalized = dict(event)
            normalized["timestamp"] = normalize_timestamp(
                event.get("timestamp", "")
            )
            all_events.append(normalized)

    # Sort by normalized timestamp
    all_events.sort(key=lambda e: e.get("timestamp", ""))

    logger.info("Timeline built: %d events merged from %d source(s)",
                len(all_events), len(sources))
    return all_events


def build_timeline_from_processed(processed_dir: str = None) -> list[dict]:
    """
    Build a timeline by loading already-processed JSON files from the
    processed storage directory.

    Looks for:
      - normalized_logs.json (from feature_engineer)
      - Any other JSON files with event records

    Args:
        processed_dir: Path to processed output directory.

    Returns:
        Sorted timeline event list.
    """
    if processed_dir is None:
        processed_dir = PROCESSED_DIR

    sources = []

    # Load unified/normalized logs if available
    normalized_path = os.path.join(processed_dir, "normalized_logs.json")
    if os.path.isfile(normalized_path):
        try:
            with open(normalized_path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                records = data.get("records", [])
            elif isinstance(data, list):
                records = data
            else:
                records = []
            sources.append(records)
            logger.info("Loaded %d records from normalized_logs.json", len(records))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to load normalized_logs.json: %s", e)

    # Load threat intel matches if available
    threat_intel_path = os.path.join(processed_dir, "threat_intel_matches.json")
    if os.path.isfile(threat_intel_path):
        try:
            with open(threat_intel_path, "r") as f:
                data = json.load(f)
            results = data.get("results", [])
            # Convert VT results to timeline events
            for r in results:
                if r.get("found"):
                    sources.append([{
                        "timestamp": data.get("generated_at", ""),
                        "event_type": "threat_intel",
                        "source": "virustotal",
                        "raw_message": f"VT match: {r.get('filename', r.get('hash', ''))} "
                                       f"({r.get('positives', 0)}/{r.get('total', 0)} detections)",
                    }])
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to load threat_intel_matches.json: %s", e)

    return build_timeline(*sources)


# ─────────────────────────────────────────────────────────────────────────────
# Save Timeline
# ─────────────────────────────────────────────────────────────────────────────

def save_timeline(events: list[dict], output_path: str = None) -> str:
    """
    Save the unified timeline to a JSON file.

    Args:
        events:      Sorted list of timeline event dicts.
        output_path: Destination path. Defaults to
                     storage/processed/unified_timeline.json

    Returns:
        Path written to.
    """
    if output_path is None:
        output_path = os.path.join(PROCESSED_DIR, "unified_timeline.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Compute source distribution and activity trend
    source_counts = {}
    activity_trend = {}  # hourly buckets: "YYYY-MM-DD HH:00"

    source_key_map = {
        # System
        "syslog": "syslog",
        "system": "syslog",
        # Auth
        "auth_log": "auth_log",
        "authlog": "auth_log",
        "auth": "auth_log",
        # Bash
        "bash_history": "bash_history",
        "bash": "bash_history",
        # Network
        "network": "network",
        # Threat Intel
        "threat_intel": "threat_intel",
        "virustotal": "threat_intel",
        "yara": "threat_intel",
    }

    for event in events:
        # Source distribution
        raw_src = str(event.get("source") or "").lower()
        etype = str(event.get("event_type") or "").lower()
        
        # Try mapping source, then event_type, then fallback to raw values
        src = source_key_map.get(raw_src) or source_key_map.get(etype) or raw_src or etype or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1
        
        # Update the event itself so the frontend table displays standardized names
        event["source"] = src
        if etype in source_key_map:
            event["event_type"] = source_key_map[etype]

        # Activity trend (hourly)
        ts = event.get("timestamp", "")
        if ts and len(ts) >= 13:
            hour_bucket = f"{ts[:13]}:00"
            activity_trend[hour_bucket] = activity_trend.get(hour_bucket, 0) + 1

    # Time range
    timestamps = [str(e.get("timestamp", "")) for e in events if e.get("timestamp")]
    first_ts = timestamps[0] if timestamps else ""
    last_ts = timestamps[-1] if timestamps else ""

    with open(output_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "time_range": {"first": first_ts, "last": last_ts},
            "source_distribution": source_counts,
            "activity_trend": dict(sorted(activity_trend.items())),
            "events": events,
        }, f, indent=2)

    logger.info(
        "Unified timeline saved: %s (%d events, %s → %s)",
        output_path, len(events), first_ts[:19], last_ts[:19],
    )
    return output_path
