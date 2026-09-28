import pytest
import os
import sys
import json
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.anti_forensics.detector import detect_anti_forensics
from database.db_setup import init_db, insert_case
from database.models import Case

def test_anti_forensics_timestomp(tmp_path, monkeypatch):
    init_db()
    uid = "CASE-" + uuid.uuid4().hex
    insert_case(Case(uid, "Test", "Test"))
    
    # Mock logs for timestomp
    logs = [
        {"event_type": "command", "command": "ls -la", "source": "bash_history"},
        {"event_type": "command", "command": "touch -t 202010101010 my_file", "source": "bash_history"},
    ]
    
    log_file = tmp_path / "normalized_logs.json"
    with open(log_file, "w") as f:
        json.dump(logs, f)
        
    # Mock RAW_DISK_DIR empty for this test
    monkeypatch.setattr('analysis.anti_forensics.detector.RAW_DISK_DIR', str(tmp_path))
    monkeypatch.setattr('analysis.anti_forensics.detector.full_rootkit_scan', lambda: [])
        
    alerts = detect_anti_forensics(uid, str(log_file))
    
    assert len(alerts) == 1
    assert alerts[0].alert_type == "timestomping"

def test_anti_forensics_rootkit_dotfile(tmp_path, monkeypatch):
    init_db()
    uid = "CASE-" + uuid.uuid4().hex
    insert_case(Case(uid, "Test", "Test"))
    
    # Create empty log file
    log_file = tmp_path / "normalized_logs.json"
    with open(log_file, "w") as f:
        json.dump([], f)
        
    # Create suspicious disk files
    disk_dir = tmp_path / "raw_disk"
    disk_dir.mkdir()
    (disk_dir / ".hidden_malware").write_text("evil")
    (disk_dir / "chkrootkit_output.txt").write_text("found something")
    
    monkeypatch.setattr('analysis.anti_forensics.detector.RAW_DISK_DIR', str(disk_dir))
    monkeypatch.setattr('analysis.anti_forensics.detector.full_rootkit_scan', lambda: [])
    
    alerts = detect_anti_forensics(uid, str(log_file))
    
    # Should catch .hidden_malware and chkrootkit
    assert len(alerts) == 2
    types = [a.alert_type for a in alerts]
    assert "dotfile" in types
    assert "rootkit" in types
