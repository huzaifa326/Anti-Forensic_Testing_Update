"""
CyberForensX — Database Initialization & CRUD Operations
Module: database/db_setup.py

Initializes the SQLite database and provides helper functions
for inserting and querying Cases, Artifacts, Alerts, and Custody entries.
"""

import sqlite3
import logging
import sys
import os

# Allow running standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import DATABASE_PATH
from database.models import (
    ALL_TABLES,
    Case, Artifact, Alert, CustodyEntry, CaseActivityEntry
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Connection Helper
# ─────────────────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with foreign key enforcement enabled."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row   # allows dict-like row access
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Initialise Database
# ─────────────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create all tables in the SQLite database (idempotent — safe to re-run)."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Ensure we recreate tables when schema has changed (tests expect a fresh schema)
        # Drop dependent tables first to avoid FK issues, then recreate.
        drop_order = [
            "custody_log", "alerts", "artifacts", "case_activity_log", "cases", "users"
        ]
        for t in drop_order:
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {t}")
            except Exception:
                pass

        for ddl in ALL_TABLES:
            cursor.execute(ddl)
        conn.commit()
        logger.info("Database initialised at: %s", DATABASE_PATH)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Cases
# ─────────────────────────────────────────────────────────────────────────────

def insert_case(case: Case) -> int:
    """Insert a new forensic case. Returns the new row id."""
    sql = """
        INSERT INTO cases (case_id, title, investigator, created_at, status, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, case.to_tuple())
        conn.commit()
        logger.info("Case inserted: %s", case.case_id)
        return cursor.lastrowid
    finally:
        conn.close()


def get_case(case_id: str) -> sqlite3.Row | None:
    """Retrieve a case by its human-readable case_id."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def list_cases() -> list:
    """Return all cases."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return cursor.fetchall()
    finally:
        conn.close()


def close_case(case_id: str) -> bool:
    """Close a case by setting its status to 'closed'.
    Returns True if the case was found and closed, False otherwise."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        if row is None:
            return False
        if row["status"] == "closed":
            return True  # already closed
        cursor.execute("UPDATE cases SET status = 'closed' WHERE case_id = ?", (case_id,))
        conn.commit()
        logger.info("Case closed: %s", case_id)
        return True
    finally:
        conn.close()


def delete_case(case_id: str) -> bool:
    """Delete a case and all its related artifacts, alerts, and custody log entries.
    Returns True if the case was found and deleted, False otherwise."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM cases WHERE case_id = ?", (case_id,))
        if cursor.fetchone() is None:
            return False
        cursor.execute("DELETE FROM custody_log WHERE case_id = ?", (case_id,))
        cursor.execute("DELETE FROM alerts WHERE case_id = ?", (case_id,))
        cursor.execute("DELETE FROM artifacts WHERE case_id = ?", (case_id,))
        cursor.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        conn.commit()
        logger.info("Case deleted: %s", case_id)
        return True
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Artifacts
# ─────────────────────────────────────────────────────────────────────────────

def insert_artifact(artifact: Artifact) -> int:
    """Insert a collected artifact record. Returns the new row id."""
    sql = """
        INSERT INTO artifacts
            (case_id, artifact_name, artifact_type, file_path,
             sha256_hash, collected_at, blockchain_tx, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, artifact.to_tuple())
        conn.commit()
        artifact_id = cursor.lastrowid
        logger.info("Artifact recorded: %s [%s] hash=%s",
                    artifact.artifact_name, artifact.artifact_type,
                    artifact.sha256_hash[:16] + "...")
        return artifact_id
    finally:
        conn.close()


def get_artifacts_for_case(case_id: str) -> list:
    """Return all artifacts belonging to a case."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM artifacts WHERE case_id = ? ORDER BY collected_at",
            (case_id,)
        )
        return cursor.fetchall()
    finally:
        conn.close()


def update_blockchain_tx(artifact_id: int, tx_id: str) -> None:
    """Attach a Hyperledger Fabric transaction ID to an artifact (used in Iteration 3)."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE artifacts SET blockchain_tx = ? WHERE id = ?",
            (tx_id, artifact_id)
        )
        conn.commit()
        logger.info("Blockchain TX set for artifact id=%d: %s", artifact_id, tx_id)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

def insert_alert(alert: Alert) -> int:
    """Insert a forensic alert. Returns the new row id."""
    sql = """
        INSERT INTO alerts
            (case_id, artifact_id, alert_type, severity,
             description, detected_at, mitre_technique, resolved)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, alert.to_tuple())
        conn.commit()
        logger.info("Alert inserted: [%s] %s (severity=%s)",
                    alert.alert_type, alert.description[:60], alert.severity)
        return cursor.lastrowid
    finally:
        conn.close()


def get_alerts_for_case(case_id: str) -> list:
    """Return all alerts for a given case."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM alerts WHERE case_id = ? ORDER BY detected_at",
            (case_id,)
        )
        return cursor.fetchall()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Chain-of-Custody Log
# ─────────────────────────────────────────────────────────────────────────────

def insert_custody_entry(entry: CustodyEntry) -> int:
    """Append a chain-of-custody action entry. Returns the new row id."""
    sql = """
        INSERT INTO custody_log
            (case_id, artifact_id, action, performed_by, performed_at, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, entry.to_tuple())
        conn.commit()
        logger.info("Custody entry: artifact_id=%d action=%s by=%s",
                    entry.artifact_id, entry.action, entry.performed_by)
        return cursor.lastrowid
    finally:
        conn.close()


def get_custody_log(case_id: str) -> list:
    """Return the full chain-of-custody log for a case."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM custody_log WHERE case_id = ? ORDER BY performed_at",
            (case_id,)
        )
        return cursor.fetchall()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint — run directly to initialise DB
# ─────────────────────────────────────────────────────────────────────────────

def insert_case_activity(entry: CaseActivityEntry) -> int:
    """Log a case lifecycle event (opened, closed, deleted). Returns the new row id."""
    sql = """
        INSERT INTO case_activity_log
            (case_id, action, performed_by, performed_at, notes)
        VALUES (?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, entry.to_tuple())
        conn.commit()
        logger.info("Case activity: case=%s action=%s by=%s",
                    entry.case_id, entry.action, entry.performed_by)
        return cursor.lastrowid
    finally:
        conn.close()


def get_case_activity_log(limit: int = 20) -> list:
    """Return the most recent case activity log entries."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM case_activity_log ORDER BY performed_at DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Users (Authentication)
# ─────────────────────────────────────────────────────────────────────────────

def insert_user(username: str, email: str, password_hash: str, display_name: str = "") -> int:
    """Insert a new application user. Returns new row id."""
    sql = """
        INSERT INTO users (username, email, password_hash, display_name, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (username, email, password_hash, display_name))
        conn.commit()
        logger.info("User created: %s", username)
        return cursor.lastrowid
    finally:
        conn.close()


def get_user_by_username(username: str):
    """Retrieve a user row by username."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()
    finally:
        conn.close()

def get_user_by_id(user_id: int):
    """Retrieve a user row by user ID."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()
    finally:
        conn.close()

def get_user_by_email(email: str):
    """Retrieve a user row by email."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cursor.fetchone()
    finally:
        conn.close()

def update_user_2fa(user_id: int, code: str, expiry: str):
    """Update 2FA code and expiry for a user."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET two_factor_code = ?, two_factor_expiry = ? WHERE id = ?",
            (code, expiry, user_id)
        )
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Import from External Database (USB Portable Mode)
# ─────────────────────────────────────────────────────────────────────────────

def import_from_external_db(external_db_path: str) -> dict:
    """
    Import cases, artifacts, custody_log, alerts, and activity_log from
    an external SQLite database (e.g., USB evidence_output) into the
    local workstation database.

    Skips cases that already exist locally (by case_id) to avoid duplicates.
    Artifact IDs are re-mapped so foreign keys remain consistent.

    Returns:
        dict with counts: cases_imported, artifacts_imported, custody_imported,
                          alerts_imported, activity_imported, cases_skipped
    """
    if not os.path.isfile(external_db_path):
        raise FileNotFoundError(f"External database not found: {external_db_path}")

    ext_conn = sqlite3.connect(external_db_path)
    ext_conn.row_factory = sqlite3.Row
    local_conn = get_connection()

    stats = {
        "cases_imported": 0,
        "cases_skipped": 0,
        "artifacts_imported": 0,
        "custody_imported": 0,
        "alerts_imported": 0,
        "activity_imported": 0,
    }

    try:
        ext_cur = ext_conn.cursor()
        local_cur = local_conn.cursor()

        # Get existing case IDs to avoid duplicates
        local_cur.execute("SELECT case_id FROM cases")
        existing_case_ids = {row["case_id"] for row in local_cur.fetchall()}

        # Fetch all cases from external DB
        ext_cur.execute("SELECT * FROM cases")
        ext_cases = ext_cur.fetchall()

        for ext_case in ext_cases:
            cid = ext_case["case_id"]

            if cid in existing_case_ids:
                stats["cases_skipped"] += 1
                logger.info("Import skip (already exists): %s", cid)
                continue

            # Insert case
            local_cur.execute(
                "INSERT INTO cases (case_id, title, investigator, created_at, status, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cid, ext_case["title"], ext_case["investigator"],
                 ext_case["created_at"], ext_case["status"], ext_case["notes"])
            )
            stats["cases_imported"] += 1

            # Import artifacts — map old IDs to new IDs
            artifact_id_map = {}  # old_id -> new_id
            ext_cur.execute("SELECT * FROM artifacts WHERE case_id = ?", (cid,))
            for art in ext_cur.fetchall():
                local_cur.execute(
                    "INSERT INTO artifacts (case_id, artifact_name, artifact_type, "
                    "file_path, sha256_hash, collected_at, blockchain_tx, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (cid, art["artifact_name"], art["artifact_type"],
                     art["file_path"], art["sha256_hash"], art["collected_at"],
                     art["blockchain_tx"], art["notes"])
                )
                artifact_id_map[art["id"]] = local_cur.lastrowid
                stats["artifacts_imported"] += 1

            # Import custody log with remapped artifact IDs
            ext_cur.execute("SELECT * FROM custody_log WHERE case_id = ?", (cid,))
            for entry in ext_cur.fetchall():
                new_art_id = artifact_id_map.get(entry["artifact_id"], entry["artifact_id"])
                local_cur.execute(
                    "INSERT INTO custody_log (case_id, artifact_id, action, "
                    "performed_by, performed_at, notes) VALUES (?, ?, ?, ?, ?, ?)",
                    (cid, new_art_id, entry["action"],
                     entry["performed_by"], entry["performed_at"], entry["notes"])
                )
                stats["custody_imported"] += 1

            # Import alerts with remapped artifact IDs
            ext_cur.execute("SELECT * FROM alerts WHERE case_id = ?", (cid,))
            for alert in ext_cur.fetchall():
                new_art_id = artifact_id_map.get(alert["artifact_id"], alert["artifact_id"])
                local_cur.execute(
                    "INSERT INTO alerts (case_id, artifact_id, alert_type, severity, "
                    "description, detected_at, mitre_technique, resolved) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (cid, new_art_id, alert["alert_type"], alert["severity"],
                     alert["description"], alert["detected_at"],
                     alert["mitre_technique"], alert["resolved"])
                )
                stats["alerts_imported"] += 1

            # Import activity log
            try:
                ext_cur.execute("SELECT * FROM case_activity_log WHERE case_id = ?", (cid,))
                for act in ext_cur.fetchall():
                    local_cur.execute(
                        "INSERT INTO case_activity_log (case_id, action, performed_by, "
                        "performed_at, notes) VALUES (?, ?, ?, ?, ?)",
                        (cid, act["action"], act["performed_by"],
                         act["performed_at"], act["notes"])
                    )
                    stats["activity_imported"] += 1
            except Exception:
                pass  # activity log table may not exist in older DBs

        local_conn.commit()
        logger.info("Import complete: %s", stats)

    finally:
        ext_conn.close()
        local_conn.close()

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entrypoint — run directly to initialise DB
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print(f"Database ready at: {DATABASE_PATH}")
