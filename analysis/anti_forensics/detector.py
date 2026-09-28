"""
CyberForensX — Anti-Forensics Detection
Module: analysis/anti_forensics/detector.py

Detects potential anti-forensics activity like timestomping, rootkits, hidden files,
and LUKS-encrypted containers with a more controlled and deduplicated workflow.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

# Fix path for standalone execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.settings import PROCESSED_DIR, RAW_DISK_DIR
from database.db_setup import insert_alert, get_artifacts_for_case
from database.models import Alert
from analysis.anti_forensics.luks_extractor import scan_for_luks
from analysis.anti_forensics.rootkit_detector import full_rootkit_scan

logger = logging.getLogger(__name__)


def _add_alert(case_id: str, alert_type: str, description: str, severity: str, mitre_technique: str, seen: set, alerts: list) -> None:
    key = (case_id, alert_type, description)
    if key in seen:
        return
    seen.add(key)
    alert = Alert(
        case_id=case_id,
        alert_type=alert_type,
        description=description,
        severity=severity,
        mitre_technique=mitre_technique,
    )
    insert_alert(alert)
    alerts.append(alert)
    logger.warning(f"Anti-Forensics Alert (Case {case_id}): {description}")


def detect_anti_forensics(case_id: str, logs_path: str = None) -> list:
    """
    Run anti-forensics heuristics against normalized logs and collected disk evidence.
    Generates alerts for anomalous findings like timestomping, dotfiles, rootkit artifacts,
    and LUKS-encrypted volumes.
    """
    if logs_path is None:
        logs_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")

    raised_alerts = []
    seen = set()

    # 1. Detect timestomping in bash history / command entries
    if os.path.isfile(logs_path):
        try:
            with open(logs_path, 'r') as f:
                data = json.load(f)
                logs = data.get('records', data) if isinstance(data, dict) else data

            for log in logs:
                if log.get('source') == 'bash_history' or log.get('event_type') == 'command':
                    cmd = str(log.get('command', '')).lower()
                    indicators = [
                        'touch -t',
                        'touch -m',
                        'touch -d',
                        'touch -c',
                        'setfattr',
                        'osutime',
                    ]
                    if any(token in cmd for token in indicators):
                        _add_alert(
                            case_id,
                            "timestomping",
                            f"Potential timestomping detected via bash history: {log.get('command', '')}",
                            "high",
                            "T1070.006",
                            seen,
                            raised_alerts,
                        )
        except Exception as e:
            logger.error(f"Failed to check logs for timestomping: {e}")
    else:
        logger.warning(f"No normalized logs found at {logs_path}. Skipping bash history checks.")

    # 2. Inspect collected artifacts for suspicious hidden files / rootkit tools
    artifacts = get_artifacts_for_case(case_id)
    try:
        for art in artifacts:
            filename = art["artifact_name"] if isinstance(art, dict) else str(art)
            file_path = art["file_path"] if isinstance(art, dict) else None
            if not file_path or not os.path.isfile(file_path):
                continue

            low_name = filename.lower()
            if filename.startswith('.') and 'bash' not in low_name and 'zsh' not in low_name:
                _add_alert(
                    case_id,
                    "dotfile",
                    f"Suspicious hidden file collected: {filename}",
                    "medium",
                    "T1564.001",
                    seen,
                    raised_alerts,
                )

            if any(token in low_name for token in ['unhide', 'chkrootkit', 'rkhunter', 'rootkit', 'backdoor', 'knark']):
                _add_alert(
                    case_id,
                    "rootkit",
                    f"Possible rootkit or anti-forensics tool artifact found: {filename}",
                    "high",
                    "T1014",
                    seen,
                    raised_alerts,
                )

            # Timestomp detection by comparing file mtime vs collected_at from DB
            try:
                collected_at = art.get("collected_at")
                if collected_at:
                    # collected_at may already be an ISO string; parse conservatively
                    try:
                        collected_dt = datetime.fromisoformat(str(collected_at))
                    except Exception:
                        # fallback to naive parsing
                        collected_dt = datetime.fromtimestamp(float(collected_at))

                    mtime = datetime.fromtimestamp(os.path.getmtime(file_path), timezone.utc)
                    # If file mtime differs from collected_at by >5 minutes, raise an alert
                    if abs((mtime - collected_dt).total_seconds()) > 300:
                        _add_alert(
                            case_id,
                            "timestomp_file",
                            f"File timestamp anomaly for {filename}: file mtime={mtime.isoformat()} vs collected_at={collected_dt.isoformat()}",
                            "high",
                            "T1070.006",
                            seen,
                            raised_alerts,
                        )
            except Exception:
                # ignore timestamp parse errors but continue other checks
                pass
    except Exception as e:
        logger.error(f"Failed to inspect artifacts for anti-forensics: {e}")

    # 2b. Direct disk scan fallback for live evidence not yet inserted in DB.
    if os.path.isdir(RAW_DISK_DIR):
        for entry in os.listdir(RAW_DISK_DIR):
            full_path = os.path.join(RAW_DISK_DIR, entry)
            if not os.path.isfile(full_path):
                continue

            low_name = entry.lower()
            if entry.startswith('.') and 'bash' not in low_name and 'zsh' not in low_name:
                _add_alert(
                    case_id,
                    "dotfile",
                    f"Suspicious hidden file found in disk evidence: {entry}",
                    "medium",
                    "T1564.001",
                    seen,
                    raised_alerts,
                )

            if any(token in low_name for token in ['unhide', 'chkrootkit', 'rkhunter', 'rootkit', 'backdoor', 'knark']):
                _add_alert(
                    case_id,
                    "rootkit",
                    f"Possible rootkit or anti-forensics tool artifact found on disk: {entry}",
                    "high",
                    "T1014",
                    seen,
                    raised_alerts,
                )

    # 3. Detect LUKS-encrypted volumes in raw disk paths
    if os.path.isdir(RAW_DISK_DIR):
        disk_files = [os.path.join(RAW_DISK_DIR, f) for f in os.listdir(RAW_DISK_DIR)]
        luks_volumes = scan_for_luks(disk_files)

        for vol in luks_volumes:
            desc = f"Encrypted LUKS volume found: {os.path.basename(vol['device'])} (UUID: {vol.get('uuid', 'unknown')})"
            _add_alert(
                case_id,
                "luks_volume",
                desc,
                "high",
                "T1480",
                seen,
                raised_alerts,
            )

            if logs_path and os.path.isfile(logs_path):
                try:
                    with open(logs_path, 'r') as f:
                        data = json.load(f)
                    logs_list = data.get('records', data) if isinstance(data, dict) else data

                    logs_list.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "luks_volume",
                        "source": "anti_forensics",
                        "device": vol.get('device', 'unknown'),
                        "uuid": vol.get('uuid', 'unknown'),
                        "cipher": vol.get('cipher', 'unknown'),
                        "cipher_mode": vol.get('cipher_mode', 'unknown'),
                        "hash": vol.get('hash', 'unknown'),
                        "message": desc,
                    })

                    with open(logs_path, 'w') as f:
                        if isinstance(data, dict):
                            data['records'] = logs_list
                            json.dump(data, f, indent=2)
                        else:
                            json.dump(logs_list, f, indent=2)
                except Exception as e:
                    logger.error(f"Failed to append LUKS logs to normalized_logs.json: {e}")

    # 4. Advanced rootkit heuristics (live system based)
    rootkit_findings = full_rootkit_scan()
    for finding in rootkit_findings:
        desc = finding.get("desc", "Potential rootkit behavior detected")
        _add_alert(
            case_id,
            "advanced_rootkit",
            desc,
            "high",
            "T1014",
            seen,
            raised_alerts,
        )

    logger.info(f"Anti-Forensics Detection complete. {len(raised_alerts)} unique alerts raised.")
    return raised_alerts
