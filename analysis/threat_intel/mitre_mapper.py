"""
CyberForensX — MITRE ATT&CK Mapper
Module: analysis/threat_intel/mitre_mapper.py

Maps forensic events and anomalies to the MITRE ATT&CK framework.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Basic mapping of event types/patterns to MITRE techniques
MITRE_MAPPING = {
    "auth": {
        "failed_login": {"id": "T1110", "name": "Brute Force"},
        "sudo_usage": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        "ssh_login": {"id": "T1021.004", "name": "Remote Services: SSH"},
    },
    "bash": {
        "shred": {"id": "T1070.004", "name": "Indicator Removal on Host: File Deletion"},
        "curl": {"id": "T1105", "name": "Ingress Tool Transfer"},
        "wget": {"id": "T1105", "name": "Ingress Tool Transfer"},
        "nc": {"id": "T1043", "name": "Commonly Used Port"},
        "crontab": {"id": "T1053.003", "name": "Scheduled Task/Job: Cron"},
    },
    "network": {
        "outbound_connection": {"id": "T1043", "name": "Commonly Used Port"},
        "listening_port": {"id": "T1043", "name": "Commonly Used Port"},
    },
    "threat_intel": {
        "malware_match": {"id": "T1588.001", "name": "Obtain Capabilities: Malware"},
        "ioc_match": {"id": "T1071", "name": "Application Layer Protocol"},
    }
}

def map_event_to_mitre(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an event with MITRE ATT&CK mapping if applicable.
    """
    event_type = event.get("event_type", "unknown")
    raw_message = str(event.get("raw_message", "") or "").lower()
    
    mapping = {}
    
    # Logic for Bash commands
    if event_type == "bash":
        for cmd, info in MITRE_MAPPING["bash"].items():
            if cmd in raw_message:
                mapping = info
                break
                
    # Logic for Auth events
    elif event_type == "auth":
        if "failed" in raw_message:
            mapping = MITRE_MAPPING["auth"]["failed_login"]
        elif "sudo" in raw_message:
            mapping = MITRE_MAPPING["auth"]["sudo_usage"]
        elif "ssh" in raw_message:
            mapping = MITRE_MAPPING["auth"]["ssh_login"]
            
    # Logic for Network events
    elif event_type == "network":
        mapping = MITRE_MAPPING["network"]["outbound_connection"]
        
    # Logic for Threat Intel matches
    elif event_type == "threat_intel":
        mapping = MITRE_MAPPING["threat_intel"]["malware_match"]

    if mapping:
        event["mitre_id"] = mapping["id"]
        event["mitre_name"] = mapping["name"]
        
    return event

def enrich_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich a full list of timeline events with MITRE data."""
    for event in events:
        map_event_to_mitre(event)
    return events
