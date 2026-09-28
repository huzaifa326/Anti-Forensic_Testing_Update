"""
CyberForensX — Main CLI Entry Point
Module: main.py

Orchestrates the CyberForensX pipeline from the command line.
Iteration 1: Initialise DB + run all evidence acquisition collectors.
Iteration 2: Artifact parsing, threat intel integration, timeline building.

Usage:
    sudo python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --collect
    sudo python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --collect --device /dev/sda1
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --analyze
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --timeline
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --threat-intel
"""

import argparse
import logging
import sys
import os

# Ensure project root is on PYTHONPATH when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import DATABASE_PATH, PORTABLE_MODE, RAW_LOGS_DIR, PROCESSED_DIR, RAW_DISK_DIR

# In portable mode, write log to the evidence_output dir on USB
if PORTABLE_MODE:
    _evidence_dir = os.environ.get("CYBERFORENSX_EVIDENCE_DIR",
                                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_output"))
    _log_path = os.path.join(_evidence_dir, "cyberforensX.log")
    os.makedirs(_evidence_dir, exist_ok=True)
else:
    _log_path = "cyberforensX.log"

from database.db_setup import init_db, insert_case, get_case
from database.models import Case
from acquisition.log_collector import collect_all_logs
from acquisition.bash_history_collector import collect_all_users_history, parse_bash_history
from acquisition.disk_collector import collect_all_disk_artifacts
from acquisition.network_collector import capture_network_connections

# Iteration 2 imports
from analysis.pipeline.log_parser import parse_all_logs, save_parsed_logs
from analysis.pipeline.feature_engineer import unify_logs, save_unified_logs
from analysis.threat_intel.virustotal_client import check_file, save_threat_intel_results
from analysis.threat_intel.misp_client import search_ioc, save_misp_results
from analysis.threat_intel.yara_scanner import scan_artifact
from analysis.threat_intel.mitre_mapper import enrich_timeline
from integrity.timeline_builder import build_timeline_from_processed, save_timeline
from integrity.multi_device_correlator import correlate_events

# Iteration 3 imports
from analysis.ml.anomaly_detector import detect_anomalies
from analysis.anti_forensics.detector import detect_anti_forensics
from integrity.blockchain.fabric_client import log_evidence_to_blockchain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_log_path, mode="a"),
    ]
)
logger = logging.getLogger("CyberForensX")


# ─────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CyberForensX",
        description="AI-Assisted Automated Digital Forensics & Incident Reconstruction Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Initialise database only:
    python main.py --init-db

  Run full Iteration 1 evidence collection:
    sudo python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --collect

  Collection with EXT4 metadata from a block device:
    sudo python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --collect --device /dev/sda1

  Parse logs & build unified features (Iteration 2):
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --analyze

  Build unified timeline (Iteration 2):
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --timeline

  Run threat intel scan (Iteration 2):
    python main.py --case CASE-2026-001 --investigator "Hamna Ejaz" --threat-intel
        """
    )
    parser.add_argument("--init-db", action="store_true",
                        help="Initialise the SQLite database and exit.")
    parser.add_argument("--case", type=str, metavar="CASE_ID",
                        help="Forensic case identifier (e.g. CASE-2026-001)")
    parser.add_argument("--investigator", type=str, metavar="NAME",
                        help="Name of the investigator running this collection")
    parser.add_argument("--title", type=str, default="CyberForensX Investigation",
                        metavar="TITLE", help="Case title (used when creating a new case)")
    parser.add_argument("--collect", action="store_true",
                        help="Run all Iteration 1 evidence collectors")
    parser.add_argument("--device", type=str, default=None, metavar="DEVICE",
                        help="Block device for EXT4 metadata, e.g. /dev/sda1")
    # Iteration 2 flags
    parser.add_argument("--analyze", action="store_true",
                        help="Parse collected logs into JSON and build unified features (Iteration 2)")
    parser.add_argument("--timeline", action="store_true",
                        help="Build a unified sorted timeline from processed artifacts (Iteration 2)")
    parser.add_argument("--threat-intel", action="store_true",
                        help="Scan collected artifacts against VirusTotal (Iteration 2)")
    # Iteration 3 flags
    parser.add_argument("--ml-anomaly", action="store_true",
                        help="Run ML isolation forest to detect anomalous activity (Iteration 3)")
    parser.add_argument("--anti-forensics", action="store_true",
                        help="Check for anti-forensics techniques like timestomping and rootkits (Iteration 3)")
    parser.add_argument("--blockchain", action="store_true",
                        help="Log collected evidence hashes to simulated blockchain ledger (Iteration 3)")
    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Acquisition Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def run_acquisition(case_id: str, investigator: str, device: str = None) -> None:
    """
    Run all Iteration 1 evidence collectors in sequence.

    Order:
      1. Network connections (volatile — captured first)
      2. System logs (Syslog, Auth.log)
      3. Bash history (all users)
      4. Disk artifacts (config files, EXT4 metadata)

    Each artifact is hashed and recorded in the DB immediately after collection.
    """
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Evidence Acquisition         ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("║      Investigator: %-30s║", investigator)
    logger.info("╚══════════════════════════════════════════════════╝")

    collected_total = 0

    # 1. Network connections (most volatile — captured first)
    logger.info("─── [1/4] Network Connection Capture ───")
    net = capture_network_connections(case_id, investigator)
    if net:
        collected_total += 1

    # 2. System logs
    logger.info("─── [2/4] System Log Collection ───")
    logs = collect_all_logs(case_id, investigator)
    collected_total += len(logs)

    # 3. Bash history
    logger.info("─── [3/4] Bash History Collection ───")
    history = collect_all_users_history(case_id, investigator)
    collected_total += len(history)

    # 4. Disk artifacts (config files + optional EXT4 metadata)
    logger.info("─── [4/4] Disk Artifact Collection ───")
    disk = collect_all_disk_artifacts(case_id, investigator, device=device)
    collected_total += len(disk)

    logger.info("══════════════════════════════════════════════════")
    logger.info("Evidence Collection Complete: %d artifact(s) recorded", collected_total)
    logger.info("Database: %s", DATABASE_PATH)
    logger.info("══════════════════════════════════════════════════")


# ─────────────────────────────────────────────────────────────────────────────
# Iteration 2: Analysis Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(case_id: str) -> None:
    """
    Run Iteration 2 log parsing and feature engineering.
    Parses raw syslog/auth.log files from storage/raw/logs/ into structured
    JSON and unifies them into a common feature set.
    """
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Artifact Parsing (Iter 2)    ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")

    # Step 1: Parse raw logs
    logger.info("─── [1/2] Parsing Raw Logs ───")
    parsed = parse_all_logs(RAW_LOGS_DIR)
    parsed_path = os.path.join(PROCESSED_DIR, "parsed_logs.json")
    save_parsed_logs(parsed, parsed_path)
    logger.info("Parsed %d syslog + %d auth.log records",
                len(parsed["syslog"]), len(parsed["authlog"]))

    # Step 1.5: Parse bash history (stored in RAW_DISK_DIR)
    bash_entries = []
    if os.path.exists(RAW_DISK_DIR):
        for filename in os.listdir(RAW_DISK_DIR):
            if "bash_history" in filename:
                try:
                    file_path = os.path.join(RAW_DISK_DIR, filename)
                    # Filename format: bash_history_username_timestamp
                    parts = filename.split("_")
                    username = parts[2] if len(parts) > 2 else "unknown"
                    entries = parse_bash_history(file_path)
                    for e in entries:
                        e["user"] = username
                    bash_entries.extend(entries)
                except Exception as e:
                    logger.error("Failed to parse bash history %s: %s", filename, e)
    
    if bash_entries:
        logger.info("Parsed %d bash history command(s)", len(bash_entries))

    # Step 2: Unify into common feature set
    logger.info("─── [2/2] Feature Engineering (Unification) ───")
    unified = unify_logs(
        syslog_entries=parsed["syslog"],
        authlog_entries=parsed["authlog"],
        bash_entries=bash_entries
    )
    output_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
    save_unified_logs(unified, output_path)

    logger.info("══════════════════════════════════════════════════")
    logger.info("Analysis Complete: %d unified records saved to %s",
                len(unified), output_path)
    logger.info("══════════════════════════════════════════════════")


def run_timeline(case_id: str) -> None:
    """
    Build a unified timeline from all processed artifacts.
    Also applies multi-device correlation and MITRE mapping.
    """
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Timeline Builder (Iter 2)    ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")

    events = build_timeline_from_processed(PROCESSED_DIR)
    
    # Apply Correlation (Iter 2)
    logger.info("─── Running Multi-Device Correlation ───")
    events = correlate_events(events)
    
    # Apply MITRE Mapping (Iter 2)
    logger.info("─── Mapping Events to MITRE ATT&CK ───")
    events = enrich_timeline(events)
    
    output_path = save_timeline(events)

    logger.info("══════════════════════════════════════════════════")
    logger.info("Timeline Complete: %d events saved to %s",
                len(events), output_path)
    logger.info("══════════════════════════════════════════════════")


def run_threat_intel(case_id: str) -> None:
    """
    Scan collected artifacts against VirusTotal and YARA.
    """
    from database.db_setup import get_artifacts_for_case

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Threat Intel Scan (Iter 2)   ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")

    artifacts = get_artifacts_for_case(case_id)
    if not artifacts:
        logger.warning("No artifacts found for case %s. Run --collect first.", case_id)
        return

    paths = [a["file_path"] for a in artifacts if os.path.isfile(a["file_path"])]
    
    # VirusTotal Scan
    logger.info("─── [1/2] VirusTotal Hash Lookup ───")
    vt_results = []
    for path in paths:
        result = check_file(path)
        vt_results.append(result)
        logger.info("  VT: %s → %s", os.path.basename(path), result.get("status", "unknown"))
    save_threat_intel_results(vt_results)

    # YARA Scan (Iter 2)
    logger.info("─── [2/2] YARA Pattern Scan ───")
    matched_files = 0
    for path in paths:
        result = scan_artifact(path)
        if result["status"] == "matches_found":
            matched_files += 1
            logger.warning("  YARA: %s → MATCHED %d rule(s)!", 
                           os.path.basename(path), result["matches_count"])
        else:
            logger.info("  YARA: %s → Clean", os.path.basename(path))

    logger.info("══════════════════════════════════════════════════")
    logger.info("Threat Intel Complete: %d file(s) scanned.", len(paths))
    logger.info("══════════════════════════════════════════════════")


# ─────────────────────────────────────────────────────────────────────────────
# Iteration 3 Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def run_ml_anomaly(case_id: str) -> None:
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — ML Anomaly Detection (Iter 3)║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")
    detect_anomalies(case_id)

def run_anti_forensics(case_id: str) -> None:
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Anti-Forensics Scan (Iter 3) ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")
    detect_anti_forensics(case_id)

def run_blockchain(case_id: str) -> None:
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║      CyberForensX — Blockchain Logging (Iter 3)  ║")
    logger.info("║      Case: %-38s║", case_id)
    logger.info("╚══════════════════════════════════════════════════╝")
    log_evidence_to_blockchain(case_id)


# ─────────────────────────────────────────────────────────────────────────────
# Case Management
# ─────────────────────────────────────────────────────────────────────────────

def ensure_case_exists(case_id: str, title: str, investigator: str) -> None:
    """Create the case in the DB if it does not already exist."""
    existing = get_case(case_id)
    if not existing:
        case = Case(case_id=case_id, title=title, investigator=investigator)
        insert_case(case)
        logger.info("New case created: %s — %s", case_id, title)
    else:
        logger.info("Resuming existing case: %s", case_id)


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Always initialise the database first (idempotent)
    init_db()

    if args.init_db:
        logger.info("Database initialised at: %s", DATABASE_PATH)
        sys.exit(0)

    if not args.case or not args.investigator:
        parser.print_help()
        logger.error("--case and --investigator are required for collection.")
        sys.exit(1)

    ensure_case_exists(args.case, args.title, args.investigator)

    if args.collect:
        run_acquisition(args.case, args.investigator, device=args.device)

    if args.analyze:
        run_analysis(args.case)

    if args.timeline:
        run_timeline(args.case)

    if getattr(args, 'threat_intel', False):
        run_threat_intel(args.case)

    if getattr(args, 'ml_anomaly', False):
        run_ml_anomaly(args.case)

    if getattr(args, 'anti_forensics', False):
        run_anti_forensics(args.case)

    if getattr(args, 'blockchain', False):
        run_blockchain(args.case)

    # Check if any action was specified
    actions = [args.collect, args.analyze, args.timeline, getattr(args, 'threat_intel', False),
               getattr(args, 'ml_anomaly', False), getattr(args, 'anti_forensics', False),
               getattr(args, 'blockchain', False)]
    if not any(actions):
        logger.info("No action specified. Use --collect, --analyze, --timeline, --threat-intel, --ml-anomaly, --anti-forensics, or --blockchain.")
        parser.print_help()


if __name__ == "__main__":
    main()
