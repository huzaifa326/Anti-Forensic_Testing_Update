"""
CyberForensX — Multi-Device Correlator
Module: integrity/multi_device_correlator.py

Links and correlates events across multiple forensic sources (USB, Disk, Network).
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def correlate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Apply correlation logic to a list of timeline events.
    
    Example Correlations:
    1. USB Plug-in -> File movement/modification
    2. Network Connection -> Remote auth login
    """
    # Sort events by timestamp just in case
    events.sort(key=lambda x: x.get("timestamp", ""))
    
    for i, event in enumerate(events):
        correlations = []
        
        # Scenario 1: Identify USB-related events in logs
        msg = str(event.get("raw_message", "")).lower()
        if "usb" in msg and "device" in msg:
            event["is_correlation_root"] = True
            event["correlation_type"] = "USB_DEVICE_ACTIVITY"
            
            # Look for subsequent file changes within a 5-minute window
            root_ts_str = event.get("timestamp", "")
            if root_ts_str:
                try:
                    # Basic timestamp parsing (ISO-8601)
                    root_ts = datetime.fromisoformat(root_ts_str.split("+")[0])
                    for j in range(i + 1, min(i + 50, len(events))): # Look ahead 50 events
                        other = events[j]
                        other_ts_str = other.get("timestamp", "")
                        if not other_ts_str: continue
                        
                        other_ts = datetime.fromisoformat(other_ts_str.split("+")[0])
                        if other_ts - root_ts > timedelta(minutes=5):
                            break # Outside window
                            
                        # If it's a file change or bash command, link it
                        if other.get("event_type") in ["bash", "disk"]:
                            other["correlated_to"] = root_ts_str
                            other["correlation_reason"] = f"Activity near USB event @ {root_ts_str}"
                            correlations.append(other_ts_str)
                except (ValueError, IndexError):
                    pass
        
        # Scenario 2: Link network IPs to other activities
        origin_ip = event.get("origin_ip")
        if origin_ip and origin_ip != "—":
            for j in range(len(events)):
                if i == j: continue
                other = events[j]
                if other.get("origin_ip") == origin_ip:
                    # These share the same IP - potentially same threat actor
                    event["linked_by_ip"] = origin_ip
                    
        if correlations:
            event["correlated_events"] = correlations

    return events

def run_correlation_pipeline(timeline_path: str):
    """
    Load a timeline from disk, run correlation, and save back (placeholder).
    """
    # This would involve loading the JSON, applying correlation, and updating the file.
    # For now, it's called internally by the dashboard or main pipeline.
    logger.info("Multi-device correlation pipeline started.")
    pass
