"""
CyberForensX — Log Parser
Module: analysis/pipeline/log_parser.py

Parses raw Linux log files (Syslog, Auth.log) into structured JSON records.
This is the first stage of the Iteration 2 analysis pipeline.

Supported formats:
  - Syslog:   "Mon DD HH:MM:SS hostname process[pid]: message"
  - Auth.log: "Mon DD HH:MM:SS hostname process[pid]: message" (same format,
              but content is authentication-specific)
"""

import re
import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for standard Linux log formats
# ─────────────────────────────────────────────────────────────────────────────

# Standard syslog line: "Apr  7 14:23:01 myhost sshd[1234]: Accepted password..."
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.+)$"
)

# Auth.log specifics — extract user and IP from common auth messages
_AUTH_USER_RE = re.compile(r"(?:for|user)\s+(\S+)", re.IGNORECASE)
_AUTH_IP_RE = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})")
_AUTH_EVENT_RE = re.compile(
    r"(Accepted|Failed|Invalid|session opened|session closed|"
    r"authentication failure|sudo|su\b|new user|password changed)",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp Handling
# ─────────────────────────────────────────────────────────────────────────────

def _parse_syslog_timestamp(ts_str: str, reference_year: int = None) -> str:
    """
    Convert a syslog timestamp (e.g. 'Apr  7 14:23:01') to ISO-8601.

    Syslog timestamps lack a year, so we use the reference_year argument
    (defaults to current year).

    Returns:
        ISO-8601 string like '2026-04-07T14:23:01+00:00'
    """
    if reference_year is None:
        reference_year = datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{reference_year} {ts_str}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return ts_str  # return raw string if parsing fails


# ─────────────────────────────────────────────────────────────────────────────
# Syslog Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_syslog(file_path: str, reference_year: int = None) -> list[dict]:
    """
    Parse a Syslog file into structured records.

    Args:
        file_path:      Absolute path to the syslog file.
        reference_year: Year to use for timestamps (default: current year).

    Returns:
        List of dicts with keys:
          timestamp, hostname, process, pid, message, source
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Syslog file not found: {file_path}")

    records = []
    with open(file_path, "r", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            match = _SYSLOG_RE.match(line)
            if match:
                records.append({
                    "timestamp": _parse_syslog_timestamp(
                        match.group("timestamp"), reference_year
                    ),
                    "hostname": match.group("hostname"),
                    "process": match.group("process"),
                    "pid": match.group("pid") or "",
                    "message": match.group("message"),
                    "source": "syslog",
                    "line_number": line_num,
                })
            else:
                # Log malformed lines but don't crash
                logger.debug("Unparseable syslog line %d: %s", line_num, line[:120])

    logger.info("Parsed %d records from syslog: %s", len(records), file_path)
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Auth.log Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_authlog(file_path: str, reference_year: int = None) -> list[dict]:
    """
    Parse an Auth.log file into structured records with extracted user/IP.

    Args:
        file_path:      Absolute path to the auth.log file.
        reference_year: Year to use for timestamps (default: current year).

    Returns:
        List of dicts with keys:
          timestamp, hostname, process, pid, message, user, ip,
          event_type, source
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Auth.log file not found: {file_path}")

    records = []
    with open(file_path, "r", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            match = _SYSLOG_RE.match(line)
            if not match:
                logger.debug("Unparseable auth.log line %d: %s", line_num, line[:120])
                continue

            message = match.group("message")

            # Extract user from auth messages
            user_match = _AUTH_USER_RE.search(message)
            user = user_match.group(1) if user_match else "unknown"

            # Extract IP address
            ip_match = _AUTH_IP_RE.search(message)
            ip = ip_match.group(1) if ip_match else ""

            # Classify event type
            event_match = _AUTH_EVENT_RE.search(message)
            event_type = event_match.group(1).lower() if event_match else "other"

            records.append({
                "timestamp": _parse_syslog_timestamp(
                    match.group("timestamp"), reference_year
                ),
                "hostname": match.group("hostname"),
                "process": match.group("process"),
                "pid": match.group("pid") or "",
                "message": message,
                "user": user,
                "ip": ip,
                "event_type": event_type,
                "source": "auth_log",
                "line_number": line_num,
            })

    logger.info("Parsed %d records from auth.log: %s", len(records), file_path)
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Convenience — parse all logs in a directory
# ─────────────────────────────────────────────────────────────────────────────

def parse_all_logs(log_dir: str, reference_year: int = None) -> dict:
    """
    Scan a directory for syslog and auth.log files and parse them all.

    Identifies files by name pattern:
      - Files containing 'syslog' or 'journalctl' → syslog parser
      - Files containing 'auth' → auth.log parser

    Args:
        log_dir:        Path to the directory containing log files.
        reference_year: Year for timestamp parsing.

    Returns:
        Dict with keys 'syslog' and 'authlog', each a list of parsed records.
    """
    result = {"syslog": [], "authlog": []}

    if not os.path.isdir(log_dir):
        logger.warning("Log directory not found: %s", log_dir)
        return result

    for filename in sorted(os.listdir(log_dir)):
        file_path = os.path.join(log_dir, filename)
        if not os.path.isfile(file_path):
            continue

        lower = filename.lower()
        try:
            if "auth" in lower:
                records = parse_authlog(file_path, reference_year)
                result["authlog"].extend(records)
            elif "syslog" in lower or "journalctl" in lower:
                records = parse_syslog(file_path, reference_year)
                result["syslog"].extend(records)
        except Exception as e:
            logger.error("Failed to parse %s: %s", file_path, e)

    logger.info(
        "Total parsed: %d syslog records, %d auth.log records",
        len(result["syslog"]), len(result["authlog"])
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Save parsed output
# ─────────────────────────────────────────────────────────────────────────────

def save_parsed_logs(parsed: dict, output_path: str) -> str:
    """
    Save parsed log records to a JSON file.

    Args:
        parsed:      Dict with 'syslog' and 'authlog' lists.
        output_path: Destination file path.

    Returns:
        The output_path written to.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "syslog_count": len(parsed.get("syslog", [])),
            "authlog_count": len(parsed.get("authlog", [])),
            "syslog": parsed.get("syslog", []),
            "authlog": parsed.get("authlog", []),
        }, f, indent=2)
    logger.info("Parsed logs saved to: %s", output_path)
    return output_path
