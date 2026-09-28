"""
CyberForensX — Database ORM Models
Module: database/models.py

Tables:
  - cases        : Forensic investigation cases
  - artifacts    : Collected evidence files with their hashes
  - alerts       : ML anomaly and threat intel alerts
  - custody_log  : Chain-of-custody audit trail entries
  - case_activity_log : Tracks case lifecycle events (opened, closed, deleted)
"""

import sqlite3
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# SQL Definitions — one per entity
# ─────────────────────────────────────────────────────────────────────────────

CREATE_CASES_TABLE = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT    NOT NULL UNIQUE,       -- human-readable case identifier, e.g. CASE-2026-001
    title       TEXT    NOT NULL,
    investigator TEXT   NOT NULL,
    created_at  TEXT    NOT NULL,              -- ISO-8601 timestamp
    status      TEXT    DEFAULT 'open',        -- open | closed | pending_review
    notes       TEXT
);
"""

CREATE_ARTIFACTS_TABLE = """
CREATE TABLE IF NOT EXISTS artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT    NOT NULL,
    artifact_name   TEXT    NOT NULL,          -- filename e.g. syslog_20260306.log
    artifact_type   TEXT    NOT NULL,          -- syslog | auth_log | bash_history | memory_dump | disk_image | network
    file_path       TEXT    NOT NULL,          -- absolute path in storage/raw/
    sha256_hash     TEXT    NOT NULL,          -- SHA-256 hash computed at collection time
    collected_at    TEXT    NOT NULL,          -- ISO-8601 timestamp
    blockchain_tx   TEXT,                      -- Hyperledger Fabric transaction ID (set in Iteration 3)
    notes           TEXT
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT    NOT NULL,
    artifact_id     INTEGER,
    alert_type      TEXT    NOT NULL,          -- ml_anomaly | timestomping | dotfile | rootkit | luks | threat_intel
    severity        TEXT    DEFAULT 'medium',  -- low | medium | high | critical
    description     TEXT    NOT NULL,
    detected_at     TEXT    NOT NULL,          -- ISO-8601 timestamp
    mitre_technique TEXT,                      -- MITRE ATT&CK technique ID e.g. T1070.006
    resolved        INTEGER DEFAULT 0          -- 0=open, 1=resolved (SQLite boolean)
);
"""

CREATE_CUSTODY_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS custody_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT    NOT NULL,
    artifact_id     INTEGER NOT NULL,
    action          TEXT    NOT NULL,          -- collected | hashed | analyzed | reported | verified
    performed_by    TEXT    NOT NULL,          -- investigator name
    performed_at    TEXT    NOT NULL,          -- ISO-8601 timestamp
    notes           TEXT
);
"""

CREATE_CASE_ACTIVITY_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS case_activity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT    NOT NULL,          -- human-readable case identifier
    action          TEXT    NOT NULL,          -- opened | closed | deleted
    performed_by    TEXT    NOT NULL,          -- investigator / user who performed action
    performed_at    TEXT    NOT NULL,          -- ISO-8601 timestamp
    notes           TEXT
);
"""

ALL_TABLES = [
    CREATE_CASES_TABLE,
    CREATE_ARTIFACTS_TABLE,
    CREATE_ALERTS_TABLE,
    CREATE_CUSTODY_LOG_TABLE,
    CREATE_CASE_ACTIVITY_LOG_TABLE,
    # Users table for simple authentication (login/signup)
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        two_factor_code TEXT,
        two_factor_expiry TEXT,
        created_at TEXT NOT NULL
    );
    """,
]


# ─────────────────────────────────────────────────────────────────────────────
# Helper dataclasses (lightweight, no external dependency)
# ─────────────────────────────────────────────────────────────────────────────

class Case:
    """Represents a forensic investigation case."""
    def __init__(self, case_id: str, title: str, investigator: str,
                 status: str = "open", notes: str = ""):
        self.case_id      = case_id
        self.title        = title
        self.investigator = investigator
        self.created_at   = datetime.now(timezone.utc).isoformat()
        self.status       = status
        self.notes        = notes

    def to_tuple(self):
        return (self.case_id, self.title, self.investigator,
                self.created_at, self.status, self.notes)


class Artifact:
    """Represents a collected evidence artifact."""
    def __init__(self, case_id: str, artifact_name: str, artifact_type: str,
                 file_path: str, sha256_hash: str, notes: str = ""):
        self.case_id       = case_id
        self.artifact_name = artifact_name
        self.artifact_type = artifact_type
        self.file_path     = file_path
        self.sha256_hash   = sha256_hash
        self.collected_at  = datetime.now(timezone.utc).isoformat()
        self.blockchain_tx = None
        self.notes         = notes

    def to_tuple(self):
        return (self.case_id, self.artifact_name, self.artifact_type,
                self.file_path, self.sha256_hash, self.collected_at,
                self.blockchain_tx, self.notes)


class Alert:
    """Represents a forensic alert (ML anomaly, threat intel match, etc.)."""
    def __init__(self, case_id: str, alert_type: str, description: str,
                 artifact_id: int = None, severity: str = "medium",
                 mitre_technique: str = None):
        self.case_id         = case_id
        self.artifact_id     = artifact_id
        self.alert_type      = alert_type
        self.severity        = severity
        self.description     = description
        self.detected_at     = datetime.now(timezone.utc).isoformat()
        self.mitre_technique = mitre_technique
        self.resolved        = 0

    def to_tuple(self):
        return (self.case_id, self.artifact_id, self.alert_type,
                self.severity, self.description, self.detected_at,
                self.mitre_technique, self.resolved)


class CustodyEntry:
    """A chain-of-custody log entry."""
    def __init__(self, case_id: str, artifact_id: int, action: str,
                 performed_by: str, notes: str = ""):
        self.case_id      = case_id
        self.artifact_id  = artifact_id
        self.action       = action
        self.performed_by = performed_by
        self.performed_at = datetime.now(timezone.utc).isoformat()
        self.notes        = notes

    def to_tuple(self):
        return (self.case_id, self.artifact_id, self.action,
                self.performed_by, self.performed_at, self.notes)


class CaseActivityEntry:
    """A case lifecycle activity log entry (opened, closed, deleted)."""
    def __init__(self, case_id: str, action: str, performed_by: str, notes: str = ""):
        self.case_id      = case_id
        self.action       = action
        self.performed_by = performed_by
        self.performed_at = datetime.now(timezone.utc).isoformat()
        self.notes        = notes

    def to_tuple(self):
        return (self.case_id, self.action, self.performed_by,
                self.performed_at, self.notes)


class User:
    """Represents an application user for the dashboard."""
    def __init__(self, username: str, email: str, password_hash: str, display_name: str = "",
                 two_factor_code: str = None, two_factor_expiry: str = None):
        from datetime import datetime, timezone
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.display_name = display_name
        self.two_factor_code = two_factor_code
        self.two_factor_expiry = two_factor_expiry
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_tuple(self):
        return (self.username, self.email, self.password_hash, self.display_name,
                self.two_factor_code, self.two_factor_expiry, self.created_at)
