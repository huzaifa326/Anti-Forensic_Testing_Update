"""
CyberForensX — ML Anomaly Detection
Module: analysis/ml/anomaly_detector.py

Uses Isolation Forest to detect anomalies in unified log data (syslog, authlog, bash history).
"""

import json
import logging
import os
import sys
from datetime import datetime

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# Fix path for standalone execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.settings import PROCESSED_DIR
from database.db_setup import insert_alert
from database.models import Alert

logger = logging.getLogger(__name__)

def detect_anomalies(case_id: str, logs_path: str = None) -> list:
    """
    Read the normalized logs, extract features, build an IsolationForest model,
    and detect anomalies. Generates Alerts for any detected anomalies.
    """
    if logs_path is None:
        logs_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")

    if not os.path.isfile(logs_path):
        logger.warning(f"No normalized logs found at {logs_path}. Run --analyze first.")
        return []

    try:
        with open(logs_path, 'r') as f:
            data = json.load(f)
            logs = data.get('records', data) if isinstance(data, dict) else data
    except Exception as e:
        logger.error(f"Failed to load logs for ML analysis: {e}")
        return []

    if not logs:
        logger.info("No log events to analyze.")
        return []

    # Features to consider: event_type, command, user, ip
    df = pd.DataFrame(logs)
    
    # We need certain columns to exist, fill defaults if missing
    for col in ['event_type', 'command', 'user_id', 'ip_addr']:
        if col not in df.columns:
            df[col] = "unknown"
            
    # Fill NAs
    df.fillna("unknown", inplace=True)

    # Encode categorical features
    le = LabelEncoder()
    df['event_type_encoded'] = le.fit_transform(df['event_type'].astype(str))
    df['command_encoded'] = le.fit_transform(df['command'].astype(str))
    df['user_encoded'] = le.fit_transform(df['user_id'].astype(str))
    df['ip_encoded'] = le.fit_transform(df['ip_addr'].astype(str))

    features = ['event_type_encoded', 'command_encoded', 'user_encoded', 'ip_encoded']
    X = df[features]

    # For datasets with very few samples, adjust contamination or n_estimators
    contamination = 0.05 if len(X) > 20 else 0.1
    
    # Train Isolation Forest
    # Using a fixed random state for reproducibility in this context
    clf = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
    
    try:
        df['anomaly'] = clf.fit_predict(X)
    except Exception as e:
        logger.error(f"Error fitting IsolationForest: {e}")
        return []

    # Filter to anomalies (-1 means outlier)
    anomalies = df[df['anomaly'] == -1]
    
    raised_alerts = []
    
    for idx, row in anomalies.iterrows():
        description = (f"ML Anomaly Detected: Unusual user behaviour. "
                       f"Type: {row['event_type']}, User: {row['user_id']}, "
                       f"Command: {row.get('command', 'N/A')}, IP: {row.get('ip_addr', 'N/A')}")
        
        # Determine severity based loosely on event type
        severity = "medium"
        if "sudo" in str(row.get('command', '')).lower() or row.get('event_type') == "authlog":
            severity = "high"

        alert = Alert(
            case_id=case_id,
            alert_type="ml_anomaly",
            description=description,
            severity=severity,
            mitre_technique="T1098" # Account Manipulation - placeholder
        )
        
        insert_alert(alert)
        raised_alerts.append(alert)
        logger.info(f"Anomaly detected and recorded for case {case_id}: {description[:50]}...")

    logger.info(f"ML Anomaly Detection complete. {len(raised_alerts)} anomalies found out of {len(logs)} records.")
    return raised_alerts
