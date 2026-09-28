import pytest
import os
import json
import uuid
from analysis.ml.anomaly_detector import detect_anomalies
from database.db_setup import init_db, insert_case
from database.models import Case

def test_ml_anomaly_detector(tmp_path):
    init_db()
    uid = "CASE-" + uuid.uuid4().hex
    insert_case(Case(uid, "ML Test", "Test"))
    
    # Create mock normalized logs
    logs = [
        {"event_type": "authlog", "command": "ssh", "user_id": "root", "ip_addr": "192.168.1.100"},
        {"event_type": "authlog", "command": "ssh", "user_id": "root", "ip_addr": "192.168.1.100"},
        {"event_type": "authlog", "command": "ssh", "user_id": "root", "ip_addr": "192.168.1.100"},
        {"event_type": "authlog", "command": "ssh", "user_id": "root", "ip_addr": "192.168.1.100"},
        {"event_type": "authlog", "command": "ssh", "user_id": "root", "ip_addr": "192.168.1.100"},
        {"event_type": "command", "command": "sudo rm -rf /", "user_id": "unknown_hacker", "ip_addr": "10.0.0.99"}, # Anomaly
    ]
    
    log_file = tmp_path / "normalized_logs.json"
    with open(log_file, "w") as f:
        json.dump(logs, f)
        
    alerts = detect_anomalies(uid, str(log_file))
    
    # We should have at least one anomaly because of the outlier
    assert len(alerts) >= 1
    
    found_hacker = any("unknown_hacker" in a.description for a in alerts)
    assert found_hacker
