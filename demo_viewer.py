"""
CyberForensX — Live Demo Viewer
Run this after `python main.py --collect` to display all collected evidence.

Usage:
    python demo_viewer.py
    python demo_viewer.py --case CASE-2026-001
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_setup import (
    get_connection, list_cases,
    get_artifacts_for_case, get_alerts_for_case, get_custody_log
)

# ── ANSI colors (readable in most terminals) ─────────────────────────────────
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

LINE   = "─" * 70


def banner():
    print(f"""
{BOLD}{CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ███████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝███████╗ ╚███╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗╚════██║ ██╔██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║  ██║███████║██╔╝ ██╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{RESET}
{BOLD}   AI-Assisted Automated Digital Forensics & Incident Reconstruction Platform{RESET}
{DIM}   FAST-NUCES Islamabad | Team: Hamna Ejaz, Huzaifa Afzal, Muhammad Huzaifa{RESET}
{DIM}   Iteration 1 — Evidence Acquisition Demo{RESET}
""")


def section(title: str):
    print(f"\n{BOLD}{YELLOW}{'═' * 70}{RESET}")
    print(f"{BOLD}{YELLOW}  {title}{RESET}")
    print(f"{BOLD}{YELLOW}{'═' * 70}{RESET}")


def subsection(title: str):
    print(f"\n{CYAN}{LINE}{RESET}")
    print(f"{CYAN}  {title}{RESET}")
    print(f"{CYAN}{LINE}{RESET}")


def show_cases():
    section("📁  FORENSIC CASES IN DATABASE")
    cases = list_cases()
    if not cases:
        print(f"  {RED}No cases found. Run: sudo python main.py --case <ID> --investigator <NAME> --collect{RESET}")
        return []

    for c in cases:
        print(f"\n  {GREEN}{BOLD}Case ID      :{RESET} {c['case_id']}")
        print(f"  {GREEN}{BOLD}Title        :{RESET} {c['title']}")
        print(f"  {GREEN}{BOLD}Investigator :{RESET} {c['investigator']}")
        print(f"  {GREEN}{BOLD}Status       :{RESET} {c['status'].upper()}")
        print(f"  {GREEN}{BOLD}Created At   :{RESET} {c['created_at']}")
        if c['notes']:
            print(f"  {GREEN}{BOLD}Notes        :{RESET} {c['notes']}")

    return [dict(c) for c in cases]


def show_artifacts(case_id: str):
    subsection(f"🗄️  COLLECTED ARTIFACTS  |  Case: {case_id}")
    artifacts = get_artifacts_for_case(case_id)

    if not artifacts:
        print(f"  {RED}No artifacts found for this case.{RESET}")
        return

    type_icons = {
        "syslog"       : "📋",
        "auth_log"     : "🔐",
        "bash_history" : "⌨️ ",
        "network"      : "🌐",
        "config_file"  : "⚙️ ",
        "ext4_metadata": "💽",
        "memory_dump"  : "🧠",
    }

    for i, a in enumerate(artifacts, 1):
        icon = type_icons.get(a["artifact_type"], "📄")
        print(f"\n  {BOLD}[{i}] {icon}  {a['artifact_name']}{RESET}")
        print(f"       Type        : {CYAN}{a['artifact_type']}{RESET}")
        print(f"       SHA-256     : {GREEN}{a['sha256_hash']}{RESET}")
        print(f"       File Size   : {_human_size(a['file_path'])}")
        print(f"       Path        : {DIM}{a['file_path']}{RESET}")
        print(f"       Collected   : {a['collected_at']}")
        tx = a['blockchain_tx']
        if tx:
            print(f"       Blockchain  : {GREEN}✓ {tx}{RESET}")
        else:
            print(f"       Blockchain  : {DIM}⏳ Pending (Iteration 3){RESET}")

    print(f"\n  {GREEN}{BOLD}Total artifacts collected: {len(artifacts)}{RESET}")


def show_custody_log(case_id: str):
    subsection(f"⛓️   CHAIN OF CUSTODY LOG  |  Case: {case_id}")
    log = get_custody_log(case_id)

    if not log:
        print(f"  {RED}No custody entries found.{RESET}")
        return

    for entry in log:
        action_color = GREEN if entry["action"] == "collected" else CYAN
        print(f"  [{entry['performed_at']}]  "
              f"{action_color}{entry['action'].upper():12}{RESET}  "
              f"artifact_id={entry['artifact_id']}  "
              f"by={BOLD}{entry['performed_by']}{RESET}")
        if entry["notes"]:
            print(f"    {DIM}↳ {entry['notes']}{RESET}")

    print(f"\n  {GREEN}{BOLD}Total custody entries: {len(log)}{RESET}")


def show_storage_summary():
    subsection("💾  STORAGE DIRECTORY SUMMARY")

    from config.settings import RAW_LOGS_DIR, RAW_DISK_DIR, RAW_NETWORK_DIR, RAW_MEMORY_DIR
    dirs = {
        "Logs    (syslog/auth.log)": RAW_LOGS_DIR,
        "Disk    (config/ext4)    ": RAW_DISK_DIR,
        "Network (ss/netstat)     ": RAW_NETWORK_DIR,
        "Memory  (RAM dumps)      ": RAW_MEMORY_DIR,
    }
    for label, path in dirs.items():
        if os.path.isdir(path):
            files = os.listdir(path)
            total_size = sum(
                os.path.getsize(os.path.join(path, f))
                for f in files if os.path.isfile(os.path.join(path, f))
            )
            print(f"  {GREEN}✓{RESET}  {label}  {BOLD}{len(files)} file(s){RESET}  "
                  f"[{_bytes_to_human(total_size)}]")
            for f in files:
                print(f"       {DIM}└─ {f}{RESET}")
        else:
            print(f"  {DIM}○  {label}  (empty){RESET}")


def show_integrity_check(case_id: str):
    subsection(f"🔒  INTEGRITY VERIFICATION  |  Case: {case_id}")

    from integrity.hashing import verify_artifact
    artifacts = get_artifacts_for_case(case_id)

    if not artifacts:
        print(f"  {RED}No artifacts to verify.{RESET}")
        return

    all_ok = True
    for a in artifacts:
        path = a["file_path"]
        expected = a["sha256_hash"]
        if not os.path.isfile(path):
            print(f"  {RED}✗  FILE MISSING: {a['artifact_name']}{RESET}")
            all_ok = False
            continue
            
        try:
            ok = verify_artifact(path, expected)
            if ok:
                print(f"  {GREEN}✓  INTACT{RESET}  {a['artifact_name']}")
            else:
                print(f"  {RED}✗  TAMPERED{RESET} {a['artifact_name']}")
                all_ok = False
        except PermissionError:
            print(f"  {YELLOW}⚠  PERMISSION DENIED (Run with sudo to verify){RESET} {a['artifact_name']}")
            all_ok = False

    print()
    if all_ok:
        print(f"  {GREEN}{BOLD}✅  All artifacts are INTACT — chain of custody is valid.{RESET}")
    else:
        print(f"  {RED}{BOLD}❌  INTEGRITY VIOLATION DETECTED.{RESET}")


def _human_size(file_path: str) -> str:
    try:
        return _bytes_to_human(os.path.getsize(file_path))
    except Exception:
        return "N/A"


def _bytes_to_human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberForensX — Live Demo Viewer")
    parser.add_argument("--case", type=str, default=None,
                        help="Case ID to inspect (default: first case in DB)")
    args = parser.parse_args()

    banner()

    cases = show_cases()
    if not cases:
        return

    # Pick case to inspect
    case_id = args.case or cases[0]["case_id"]
    print(f"\n{BOLD}  Inspecting case: {CYAN}{case_id}{RESET}")

    show_storage_summary()
    show_artifacts(case_id)
    show_custody_log(case_id)
    show_integrity_check(case_id)

    print(f"\n{BOLD}{GREEN}{'═' * 70}{RESET}")
    print(f"{BOLD}{GREEN}  ✅  CyberForensX Iteration 1 Demo Complete{RESET}")
    print(f"{BOLD}{GREEN}{'═' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
