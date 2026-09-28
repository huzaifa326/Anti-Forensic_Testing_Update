"""
CyberForensX — Browser History Collector
Module: acquisition/browser_history_collector.py

Collects browser history SQLite databases for Chrome and Firefox.
"""

import os
import shutil
import logging
import glob
from datetime import datetime, timezone
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_DISK_DIR
from integrity.hashing import hash_artifact
from database.db_setup import insert_artifact, insert_custody_entry
from database.models import Artifact, CustodyEntry

logger = logging.getLogger(__name__)

def _timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def _collect_sqlite_db(source_path: str, case_id: str, investigator: str, browser_name: str, username: str) -> dict | None:
    if not os.path.isfile(source_path):
        return None

    os.makedirs(RAW_DISK_DIR, exist_ok=True)
    dest_name = f"browser_history_{browser_name}_{username}_{_timestamp_label()}.sqlite"
    dest_path = os.path.join(RAW_DISK_DIR, dest_name)

    try:
        shutil.copy2(source_path, dest_path)
    except Exception as e:
        logger.error("Failed to copy %s: %s", source_path, e)
        return None

    hash_record = hash_artifact(dest_path)

    artifact = Artifact(
        case_id       = case_id,
        artifact_name = dest_name,
        artifact_type = f"{browser_name}_history",
        file_path     = dest_path,
        sha256_hash   = hash_record["sha256"],
        notes         = f"Browser history for {username}, browser: {browser_name}"
    )
    artifact_id = insert_artifact(artifact)

    entry = CustodyEntry(
        case_id      = case_id,
        artifact_id  = artifact_id,
        action       = "collected",
        performed_by = investigator,
        notes        = f"Browser history copied from {source_path}"
    )
    insert_custody_entry(entry)

    return {**hash_record, "artifact_id": artifact_id, "artifact_type": f"{browser_name}_history", "username": username}

def collect_browser_history(case_id: str, investigator: str) -> list[dict]:
    results = []
    # Currently just looking at the users in /home, can be extended to root.
    user_dirs = glob.glob("/home/*")
    
    for udir in user_dirs:
        username = os.path.basename(udir)
        
        # Chrome
        chrome_path = os.path.join(udir, ".config/google-chrome/Default/History")
        if os.path.isfile(chrome_path):
            res = _collect_sqlite_db(chrome_path, case_id, investigator, "chrome", username)
            if res: results.append(res)
            
        # Firefox (look for any profile)
        ff_profiles = glob.glob(os.path.join(udir, ".mozilla/firefox/*.default*/places.sqlite"))
        for ff_path in ff_profiles:
            res = _collect_sqlite_db(ff_path, case_id, investigator, "firefox", username)
            if res: results.append(res)

    return results
