"""
CyberForensX — Browser History Parser
Module: analysis/pipeline/browser_parser.py

Parses collected Firefox and Chrome SQLite databases.
"""

import sqlite3
import os
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

def parse_chrome_history(file_path: str, username: str) -> list[dict]:
    records = []
    if not os.path.isfile(file_path):
        return records
        
    try:
        # Chrome history is a SQLite DB
        conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        query = "SELECT urls.url, urls.title, visits.visit_time FROM urls JOIN visits ON urls.id = visits.url"
        cursor.execute(query)
        
        for row in cursor.fetchall():
            url, title, visit_time = row
            # WebKit timestamp is microseconds since Jan 1, 1601
            epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
            try:
                dt = epoch_start + timedelta(microseconds=visit_time)
                iso_time = dt.isoformat()
            except Exception:
                iso_time = ""
                
            records.append({
                "source": "chrome_history",
                "username": username,
                "url": url,
                "title": title,
                "timestamp": iso_time
            })
            
        conn.close()
    except Exception as e:
        logger.error(f"Chrome parser error for {file_path}: {e}")
        
    return records

def parse_firefox_history(file_path: str, username: str) -> list[dict]:
    records = []
    if not os.path.isfile(file_path):
        return records
        
    try:
        # Firefox places is a SQLite DB
        conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        query = "SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id"
        cursor.execute(query)
        
        for row in cursor.fetchall():
            url, title, visit_date = row
            # PRTime is microseconds since Jan 1, 1970
            try:
                dt = datetime.fromtimestamp(visit_date / 1000000.0, tz=timezone.utc)
                iso_time = dt.isoformat()
            except Exception:
                iso_time = ""
                
            records.append({
                "source": "firefox_history",
                "username": username,
                "url": url,
                "title": title,
                "timestamp": iso_time
            })
            
        conn.close()
    except Exception as e:
        logger.error(f"Firefox parser error for {file_path}: {e}")
        
    return records

def parse_all_browsers(raw_disk_dir: str) -> list[dict]:
    all_records = []
    if not os.path.exists(raw_disk_dir):
        return all_records
        
    for filename in os.listdir(raw_disk_dir):
        if not filename.startswith("browser_history_"):
            continue
            
        file_path = os.path.join(raw_disk_dir, filename)
        parts = filename.split("_")
        
        # Expected format: browser_history_browsername_username_timestamp.sqlite
        if len(parts) >= 5:
            browser = parts[2]
            username = parts[3]
            
            if browser == "chrome":
                all_records.extend(parse_chrome_history(file_path, username))
            elif browser == "firefox":
                all_records.extend(parse_firefox_history(file_path, username))
                
    return all_records
