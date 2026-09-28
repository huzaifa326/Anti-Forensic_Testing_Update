from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup
import sys
import os
import re
import json
import math

# Add parent directory to path so we can import from other modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.db_setup import list_cases, get_case, get_artifacts_for_case, get_custody_log, get_alerts_for_case, insert_case, close_case, delete_case, insert_case_activity, get_case_activity_log, import_from_external_db, insert_user, get_user_by_username, get_user_by_email, get_user_by_id, update_user_2fa
from database.models import Case, CaseActivityEntry
from integrity.hashing import verify_artifact
from importer.usb_importer import ingest_usb_case
from acquisition.log_collector import collect_all_logs
from acquisition.bash_history_collector import collect_all_users_history, parse_bash_history
from acquisition.disk_collector import collect_all_disk_artifacts
from acquisition.network_collector import capture_network_connections
# Iteration 2 imports
from analysis.pipeline.log_parser import parse_all_logs, save_parsed_logs
from analysis.pipeline.feature_engineer import unify_logs, save_unified_logs
from analysis.pipeline.browser_parser import parse_all_browsers
from analysis.pipeline.ext4_parser import parse_all_ext4
from acquisition.browser_history_collector import collect_browser_history
from analysis.threat_intel.virustotal_client import check_file, save_threat_intel_results
from analysis.threat_intel.misp_client import search_ioc, save_misp_results
from integrity.timeline_builder import build_timeline_from_processed, save_timeline
# Iteration 3 imports
from analysis.ml.anomaly_detector import detect_anomalies
from analysis.anti_forensics.detector import detect_anti_forensics
from integrity.blockchain.fabric_client import log_evidence_to_blockchain, tamper_ledger, get_ledger_summary
from reporting.exporters.pdf_report import generate_case_pdf
from analysis.validation.validator import validate_case_against_dataset
from config.settings import RAW_LOGS_DIR, PROCESSED_DIR, RAW_DISK_DIR
import logging

try:
    import ijson
except ImportError:  # pragma: no cover - optional fallback
    ijson = None

collect_logger = logging.getLogger("CyberForensX.dashboard")

TIMELINE_PAGE_SIZE = 100

app = Flask(__name__)
app.secret_key = "cyberforensx_super_secret_dev_key"

import smtplib
from email.mime.text import MIMEText
import random
from datetime import datetime, timedelta

from config.settings import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD

def send_2fa_email(to_email, code):
    # In a production app, the SMTP config would be in config or env variables.
    # We will attempt to use a local or standard SMTP. For demonstration:
    try:
        msg = MIMEText(f"Your CyberForensX 2FA Code is: {code}\n\nPlease enter this on the dashboard to log in.")
        msg['Subject'] = 'CyberForensX Login 2FA Code'
        msg['From'] = SMTP_USERNAME or 'noreply@cyberforensx.local'
        msg['To'] = to_email
        
        # If SMTP credentials evaluate to True, send the real email over TLS
        if SMTP_USERNAME and SMTP_PASSWORD:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
            collect_logger.info(f"2FA email sent successfully to {to_email}")
        else:
            # Fallback to local terminal print
            collect_logger.warning(f"DEMO 2FA CODE FOR {to_email}: {code}")
        
    except Exception as e:
        collect_logger.error(f"Failed to send 2FA email: {str(e)}")

@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'verify_2fa', 'static']
    if request.endpoint not in allowed_routes:
        if 'user_id' not in session:
            flash("Please log in to access the dashboard.", "error")
            return redirect(url_for('login'))
        
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            g.user = dict(user)
        else:
            session.pop('user_id', None)


def _ensure_timeline_cache() -> str:
    """Return the cached timeline path, generating it once if missing or stale."""
    timeline_path = os.path.join(PROCESSED_DIR, "unified_timeline.json")
    normalized_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
    
    stale = False
    if os.path.isfile(timeline_path) and os.path.isfile(normalized_path):
        if os.path.getmtime(normalized_path) > os.path.getmtime(timeline_path):
            stale = True
            collect_logger.info("Timeline cache is stale (normalized_logs.json is newer).")

    if not os.path.isfile(timeline_path) or stale:
        collect_logger.info("Regenerating unified timeline...")
        events = build_timeline_from_processed(PROCESSED_DIR)
        save_timeline(events)
    return timeline_path


def _load_timeline_metadata(timeline_path: str) -> dict:
    """Load timeline metadata without materializing the full events list."""
    meta = {
        "generated_at": "",
        "total_events": 0,
        "time_range": {"first": "", "last": ""},
        "source_distribution": {},
        "activity_trend": {},
    }

    if ijson is None:
        with open(timeline_path, "r") as f:
            data = json.load(f)
        meta["generated_at"] = data.get("generated_at", "")
        meta["total_events"] = int(data.get("total_events", 0) or 0)
        meta["time_range"] = data.get("time_range", meta["time_range"]) or meta["time_range"]
        meta["source_distribution"] = data.get("source_distribution", {}) or {}
        meta["activity_trend"] = data.get("activity_trend", {}) or {}
        return meta

    with open(timeline_path, "rb") as f:
        for prefix, event, value in ijson.parse(f):
            if prefix == "generated_at" and event == "string":
                meta["generated_at"] = value
            elif prefix == "total_events" and event in {"number", "integer"}:
                meta["total_events"] = int(value)
            elif prefix == "time_range.first" and event == "string":
                meta["time_range"]["first"] = value
            elif prefix == "time_range.last" and event == "string":
                meta["time_range"]["last"] = value
            elif prefix.startswith("source_distribution.") and event in {"number", "integer"}:
                key = prefix.split(".", 1)[1]
                meta["source_distribution"][key] = int(value)
            elif prefix.startswith("activity_trend.") and event in {"number", "integer"}:
                key = prefix.split(".", 1)[1]
                meta["activity_trend"][key] = int(value)
            elif prefix == "events" and event == "start_array":
                break

    return meta


def _load_timeline_page(timeline_path: str, page: int, per_page: int, order: str = "desc") -> list[dict]:
    """Stream a single page of timeline events from the cached JSON file."""
    page = max(page, 1)
    per_page = max(per_page, 1)

    if ijson is None:
        with open(timeline_path, "r") as f:
            data = json.load(f)
        events = data.get("events", [])
        if order == "asc":
            events = list(reversed(events))
        start = (page - 1) * per_page
        return events[start:start + per_page]

    # Collect all events then reverse if needed (ijson streams forward only)
    all_events = []
    with open(timeline_path, "rb") as f:
        for event in ijson.items(f, "events.item"):
            all_events.append(event)

    if order == "asc":
        all_events = list(reversed(all_events))

    start = (page - 1) * per_page
    return all_events[start:start + per_page]

@app.route("/")
def index():
    # Fetch all cases to display on the dashboard
    cases = list_cases()
    activity_log = get_case_activity_log(limit=20)
    return render_template("index.html", cases=cases, activity_log=activity_log)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        display = request.form.get("display_name", "").strip()
        
        if not username or not email or not password:
            flash("Username, email and password are required.", "error")
            return redirect(url_for('signup'))
            
        existing = get_user_by_username(username)
        if existing:
            flash("Username already taken.", "error")
            return redirect(url_for('signup'))
            
        existing_email = get_user_by_email(email)
        if existing_email:
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))
            
        pw_hash = generate_password_hash(password)
        insert_user(username, email, pw_hash, display)
        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))
        
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            code = str(random.randint(100000, 999999))
            expiry = (datetime.now() + timedelta(minutes=10)).isoformat()
            
            update_user_2fa(user["id"], code, expiry)
            send_2fa_email(user["email"], code)
            
            session["pre_2fa_user_id"] = user["id"]
            return redirect(url_for('verify_2fa'))
        else:
            flash("Invalid username or password.", "error")
            
    return render_template("login.html")

@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if "pre_2fa_user_id" not in session:
        return redirect(url_for('login'))
        
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user_id = session["pre_2fa_user_id"]
        
        user = get_user_by_id(user_id)
        if user and user["two_factor_code"] == code:
            # Check expiry (simple string comparison works for isoformat but datetime obj is safer, let's just do datetime)
            user_expiry_dt = datetime.fromisoformat(user["two_factor_expiry"])
            # Remove any timezone info if present to compare with naive datetime.now(), or assume UTC
            # We generated using datetime.now(), so naive comparison is safe.
            if user_expiry_dt > datetime.now():
                session["user_id"] = user["id"]
                session.pop("pre_2fa_user_id", None)
                update_user_2fa(user["id"], None, None)
                flash(f"Welcome back, {user['display_name'] or user['username']}!", "success")
                return redirect(url_for('index'))
            else:
                flash("2FA code expired. Please log in again.", "error")
                session.pop("pre_2fa_user_id", None)
                return redirect(url_for('login'))
        else:
            flash("Invalid 2FA code.", "error")
            
    return render_template("verify_2fa.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route("/case/new", methods=["POST"])
def new_case():
    case_id = request.form.get("case_id", "").strip()
    title = request.form.get("title", "").strip()
    investigator = request.form.get("investigator", "").strip()

    # --- Server-side validation ---
    errors = []
    if not case_id:
        errors.append("Case ID is required.")
    elif len(case_id) < 6 or len(case_id) > 50:
        errors.append("Case ID must be 6–50 characters.")
    elif not re.match(r'^CASE-[A-Za-z0-9\-_]+$', case_id):
        errors.append("Case ID must start with CASE- followed by letters, numbers, hyphens, or underscores (e.g. CASE-2026-002).")

    if not title:
        errors.append("Title is required.")
    elif len(title) < 3 or len(title) > 100:
        errors.append("Title must be 3–100 characters.")
    elif not re.match(r"^[A-Za-z0-9 \-_.,&'()]+$", title):
        errors.append("Title contains invalid characters.")

    if not investigator:
        errors.append("Investigator name is required.")
    elif len(investigator) < 2 or len(investigator) > 60:
        errors.append("Investigator name must be 2–60 characters.")
    elif not re.match(r"^[A-Za-z .'\-]+$", investigator):
        errors.append("Investigator name may only contain letters, spaces, dots, apostrophes, and hyphens.")

    if errors:
        for err in errors:
            flash(err, "error")
        return redirect(url_for("index"))

    case = Case(case_id, title, investigator)
    try:
        insert_case(case)
        insert_case_activity(CaseActivityEntry(case_id, "opened", investigator))
        flash(f"Case {case_id} created successfully.", "success")
    except Exception as e:
        flash(f"Error creating case: {str(e)}", "error")
        
    return redirect(url_for("index"))

@app.route("/case/<case_id>")
def view_case(case_id):
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))
        
    artifacts = get_artifacts_for_case(case_id)
    custody_log = get_custody_log(case_id)
    # ML/Threat Intel alerts (empty right now, but ready for Iteration 3)
    alerts = get_alerts_for_case(case_id)
    
    # Iteration 2: Check for parsed data
    parsing_done = False
    parsed_stats = {}
    normalized_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
    if os.path.isfile(normalized_path):
        parsing_done = True
        try:
            with open(normalized_path, "r") as f:
                if isinstance(data, dict):
                    parsed_stats = {
                        "total_records": data.get("total_records", len(data.get("records", []))),
                        "source_counts": data.get("source_counts", {}),
                        "generated_at": data.get("generated_at", "")
                    }
                elif isinstance(data, list):
                    parsed_stats = {
                        "total_records": len(data),
                        "source_counts": {"manual": len(data)},
                        "generated_at": ""
                    }
                else:
                    parsed_stats = {"total_records": 0, "source_counts": {}, "generated_at": ""}
        except Exception as e:
            collect_logger.error(f"Failed to read parsed stats: {e}")
            parsing_done = False
    
    return render_template("case.html", 
                           case=case, 
                           artifacts=artifacts, 
                           custody_log=custody_log, 
                           alerts=alerts,
                           parsing_done=parsing_done,
                           parsed_stats=parsed_stats)

@app.route("/api/parsed/<case_id>")
def api_parsed_data(case_id):
    """Return paginated parsed log data for the frontend table."""
    import html, urllib.parse
    case_id = html.unescape(urllib.parse.unquote(case_id))
    case = get_case(case_id)
        
    normalized_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
    if not os.path.isfile(normalized_path):
        return jsonify({"status": "error", "message": "Parsed data not found"}), 404
        
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        source_filter = request.args.get('source', '')
        cmd_filter = request.args.get('command_type', '')
        search_query = request.args.get('search', '').lower()
        
        with open(normalized_path, "r") as f:
            data = json.load(f)
            
        records = data.get("records", [])
        
        # Apply filters
        if source_filter:
            records = [r for r in records if r.get("source") == source_filter]
        if cmd_filter:
            records = [r for r in records if r.get("command_type") == cmd_filter]
        if search_query:
            records = [r for r in records if search_query in r.get("raw_message", "").lower()]
            
        total_filtered = len(records)
        
        # Paginate
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_records = records[start_idx:end_idx]
        
        return jsonify({
            "status": "success",
            "total_records": data.get("total_records", 0),
            "total_filtered": total_filtered,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_filtered + per_page - 1) // per_page,
            "records": paginated_records
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/verify/<artifact_id>")
def verify_hash(artifact_id):
    # This is a functional Iteration 1 feature
    # Find the artifact path
    # SQLite doesn't have a direct get_artifact_by_id in our db_setup, so we will scan all artifacts
    # To keep it simple, we expect case_id in query params to narrow it down
    case_id = request.args.get("case_id")
    if not case_id:
        return jsonify({"status": "error", "message": "case_id required"})
        
    artifacts = get_artifacts_for_case(case_id)
    target = next((a for a in artifacts if str(a['id']) == artifact_id), None)
    
    if not target:
        return jsonify({"status": "error", "message": "Artifact not found"})
        
    path = target["file_path"]
    expected = target["sha256_hash"]
    
    if not os.path.isfile(path):
        return jsonify({"status": "error", "message": "File is missing from disk!"})
        
    try:
        ok = verify_artifact(path, expected)
        if ok:
            return jsonify({"status": "success", "message": "Integrity verified. Hash matches."})
        else:
            return jsonify({"status": "tampered", "message": "INTEGRITY VIOLATION DETECTED. Hash mismatch."})
    except PermissionError:
        return jsonify({"status": "warning", "message": "Permission denied. Flask must run as root to read this file."})
        
@app.route("/case/<case_id>/close", methods=["POST"])
def close_case_route(case_id):
    """Close a case by changing its status to closed."""
    try:
        closed = close_case(case_id)
        if closed:
            case = get_case(case_id)
            performer = case["investigator"] if case else "Unknown"
            insert_case_activity(CaseActivityEntry(case_id, "closed", performer))
            flash(f"Case {case_id} has been closed.", "success")
        else:
            flash(f"Case {case_id} not found.", "error")
    except Exception as e:
        flash(f"Error closing case: {str(e)}", "error")
    return redirect(url_for("index"))

@app.route("/case/<case_id>/delete", methods=["POST"])
def delete_case_route(case_id):
    """Permanently delete a case and all associated data."""
    try:
        case = get_case(case_id)
        performer = case["investigator"] if case else "Unknown"
        deleted = delete_case(case_id)
        if deleted:
            insert_case_activity(CaseActivityEntry(case_id, "deleted", performer))
            flash(f"Case {case_id} has been permanently deleted.", "success")
        else:
            flash(f"Case {case_id} not found.", "error")
    except Exception as e:
        flash(f"Error deleting case: {str(e)}", "error")
    return redirect(url_for("index"))

@app.route("/case/<case_id>/collect", methods=["POST"])
def collect_evidence_route(case_id):
    """Run selected evidence collectors for a case from the dashboard."""
    case = get_case(case_id)
    if not case:
        flash(f"Case {case_id} not found.", "error")
        return redirect(url_for("index"))

    if case["status"] == "closed":
        flash("Cannot collect evidence for a closed case.", "error")
        return redirect(url_for("view_case", case_id=case_id))

    # Determine which collectors to run
    collect_all = request.form.get("collect_all")
    selected = request.form.getlist("collectors")

    if collect_all:
        selected = ["network", "logs", "bash", "disk", "browser"]

    if not selected:
        flash("Please select at least one evidence type to collect.", "error")
        return redirect(url_for("view_case", case_id=case_id))

    investigator = case["investigator"]
    collected_total = 0
    errors_list = []

    # 1. Network connections (most volatile — captured first)
    if "network" in selected:
        try:
            net = capture_network_connections(case_id, investigator)
            if net:
                collected_total += 1
        except Exception as e:
            errors_list.append(f"Network: {str(e)}")

    # 2. System logs
    if "logs" in selected:
        try:
            logs = collect_all_logs(case_id, investigator)
            collected_total += len(logs)
        except Exception as e:
            errors_list.append(f"Logs: {str(e)}")

    # 3. Bash history
    if "bash" in selected:
        try:
            history = collect_all_users_history(case_id, investigator)
            collected_total += len(history)
        except Exception as e:
            errors_list.append(f"Bash History: {str(e)}")

    # 4. Disk artifacts (config files)
    if "disk" in selected:
        try:
            disk = collect_all_disk_artifacts(case_id, investigator)
            collected_total += len(disk)
        except Exception as e:
            errors_list.append(f"Disk: {str(e)}")
            
    # 5. Browser history
    if "browser" in selected:
        try:
            browsers = collect_browser_history(case_id, investigator)
            collected_total += len(browsers)
        except Exception as e:
            errors_list.append(f"Browser History: {str(e)}")

    if collected_total > 0:
        flash(f"Evidence collection complete: {collected_total} artifact(s) collected and hashed.", "success")
    else:
        flash("No artifacts were collected. Some files may require root/sudo access.", "error")

    if errors_list:
        for err in errors_list:
            flash(f"Collection warning — {err}", "error")

    return redirect(url_for("view_case", case_id=case_id))

@app.route("/artifact/<int:artifact_id>/download")
def download_artifact(artifact_id):
    """Serve an artifact file for viewing / downloading."""
    case_id = request.args.get("case_id")
    if not case_id:
        flash("Missing case_id parameter.", "error")
        return redirect(url_for("index"))

    artifacts = get_artifacts_for_case(case_id)
    target = next((a for a in artifacts if a["id"] == artifact_id), None)

    if not target:
        flash("Artifact not found.", "error")
        return redirect(url_for("view_case", case_id=case_id))

    path = target["file_path"]
    if not os.path.isfile(path):
        flash(f"File not found on disk: {path}", "error")
        return redirect(url_for("view_case", case_id=case_id))

    try:
        return send_file(path, as_attachment=False)
    except PermissionError:
        flash("Permission denied. Flask must run as root to read this file.", "error")
        return redirect(url_for("view_case", case_id=case_id))

def _find_usb_database():
    """Scan common USB mount points for the CyberForensX database file."""
    import glob
    search_patterns = [
        # Fixed mount points (common if manual mount to /mnt/usb)
        "/mnt/usb/CyberForens*/evidence_output/database/cyberforensX.db",
        "/mnt/usb/CyberForens*/database/cyberforensX.db",
        
        # Standard Media mounts (e.g. /media/user/label) — check 1 and 2 levels deep
        "/media/*/CyberForens*/evidence_output/database/cyberforensX.db",
        "/media/*/CyberForens*/database/cyberforensX.db",
        "/media/*/*/CyberForens*/evidence_output/database/cyberforensX.db",
        "/media/*/*/CyberForens*/database/cyberforensX.db",
        
        # Run Media mounts (Kali/Debian default: /run/media/user/label)
        "/run/media/*/*/CyberForens*/evidence_output/database/cyberforensX.db",
        "/run/media/*/*/CyberForens*/database/cyberforensX.db",
        
        # Generic mnt mounts
        "/mnt/*/CyberForens*/evidence_output/database/cyberforensX.db",
        "/mnt/*/CyberForens*/database/cyberforensX.db",
    ]
    
    search_paths = []
    for pattern in search_patterns:
        # Use glob to expand asterisks (matches both 'CyberForensX' and 'CyberForensx')
        search_paths.extend(glob.glob(pattern))
        
    for path in search_paths:
        if os.path.isfile(path):
            return path
    return None

@app.route("/import", methods=["POST"])
def import_from_usb():
    """Import cases & evidence from attached USB drive with optional Case ID override."""
    name_option = request.form.get("name_option", "original").strip()
    custom_case_id = request.form.get("custom_case_id", "").strip() if name_option == "custom" else None
    usb_custom_path = request.form.get("usb_path", "").strip()

    imported = 0
    skipped = 0
    artifacts = 0

    # 1. Attempt legacy DB import
    db_path = _find_usb_database()
    if db_path:
        try:
            stats = import_from_external_db(db_path)
            imported += stats["cases_imported"]
            skipped += stats["cases_skipped"]
            artifacts += stats["artifacts_imported"]
        except Exception as e:
            flash(f"Legacy Import error: {str(e)}", "error")

    # 2. Attempt offline manifest ingestion
    import glob
    manifests = []
    if usb_custom_path and os.path.exists(usb_custom_path):
        if os.path.isfile(os.path.join(usb_custom_path, "manifest.json")):
            manifests.append(os.path.join(usb_custom_path, "manifest.json"))
        else:
            manifests.extend(glob.glob(os.path.join(usb_custom_path, "**", "manifest.json"), recursive=True))

    if not manifests:
        search_patterns = [
            "/mnt/usb/CASE_*/manifest.json",
            "/media/*/CASE_*/manifest.json",
            "/media/*/*/CASE_*/manifest.json",
            "/run/media/*/*/CASE_*/manifest.json",
            "evidence_output/manifest.json",
            "CASE_*/manifest.json"
        ]
        for pattern in search_patterns:
            manifests.extend(glob.glob(pattern))

    # Remove duplicate manifest paths
    manifests = list(set(manifests))

    for manifest_path in manifests:
        case_dir = os.path.dirname(manifest_path)
        try:
            from importer.usb_importer import ingest_usb_case
            result = ingest_usb_case(case_dir, custom_case_id=custom_case_id)
            if result.get("success"):
                valid_count = sum(1 for a in result["artifacts"] if "OK" in a["status"])
                imported += 1
                artifacts += valid_count
                final_cid = result.get("case_id", "imported case")
                flash(f"Successfully imported USB Case as '{final_cid}' ({valid_count} verified artifacts).", "success")
        except Exception as e:
            collect_logger.error(f"Failed to ingest offline case from {case_dir}: {e}")
            flash(f"Failed to ingest case from {case_dir}: {str(e)}", "error")

    if imported == 0 and skipped == 0 and not manifests:
        flash("No valid USB case manifests found at the specified location.", "info")

    return redirect(url_for("index"))



@app.route("/analyze/file", methods=["POST"])
def analyze_file():
    """Run VirusTotal hash lookup on a specified artifact."""
    case_id = request.form.get("case_id", "").strip()
    artifact_id = request.form.get("artifact_id", "").strip()

    if not case_id or not artifact_id:
        flash("Case ID and Artifact ID are required for file analysis.", "error")
        return redirect(request.referrer or url_for('index'))

    artifacts = get_artifacts_for_case(case_id)
    target = next((a for a in artifacts if str(a['id']) == artifact_id), None)

    if not target:
        flash("Artifact not found.", "error")
        return redirect(request.referrer or url_for('index'))

    file_path = target["file_path"]
    if not os.path.isfile(file_path):
        flash(f"Artifact file missing from disk: {file_path}", "error")
        return redirect(url_for('view_case', case_id=case_id))

    try:
        result = check_file(file_path)
        if result.get("status") == "success":
            if result.get("positives", 0) > 0:
                flash(Markup(
                    f"⚠ VirusTotal MATCH: {result['filename']} — "
                    f"{result['positives']}/{result['total']} detections. "
                    f"Threat: {result.get('threat_label', 'Unknown')}. "
                    f"<a href='{result.get('permalink', '#')}' target='_blank'>View Report</a>"
                ), "error")
            else:
                flash(
                    f"✓ VirusTotal CLEAN: {result['filename']} — "
                    f"0/{result['total']} detections.",
                    "success"
                )
        elif result.get("status") == "not_found":
            flash(f"VirusTotal: Hash not found in database for {target['artifact_name']}.", "info")
        else:
            flash(f"VirusTotal error: {result.get('error', 'Unknown error')}", "error")
    except Exception as e:
        flash(f"VirusTotal scan failed: {str(e)}", "error")

    return redirect(url_for('view_case', case_id=case_id))

@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    """Search MISP for an IOC (hash, IP, or domain)."""
    ioc_value = request.form.get("ioc_value", "").strip()
    case_id = request.form.get("case_id", "").strip()

    if not ioc_value:
        flash("Please enter an IOC value (hash, IP, or domain) to search.", "error")
        return redirect(request.referrer or url_for('index'))

    try:
        results = search_ioc(ioc_value)
        if results:
            save_misp_results(results, ioc_value)
            flash(
                f"MISP found {len(results)} matching event(s) for '{ioc_value}'. "
                f"Results saved to processed/misp_results.json.",
                "success"
            )
        else:
            flash(f"MISP: No matching events found for '{ioc_value}'. (MISP may not be configured.)", "info")
    except Exception as e:
        flash(f"MISP search failed: {str(e)}", "error")

    if case_id:
        return redirect(url_for('view_case', case_id=case_id))
    return redirect(request.referrer or url_for('index'))

@app.route("/case/<case_id>/parse", methods=["POST"])
def parse_artifacts_route(case_id):
    """Parse collected log artifacts into structured JSON and build unified features."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))

    try:
        # Parse raw logs
        parsed = parse_all_logs(RAW_LOGS_DIR)
        parsed_path = os.path.join(PROCESSED_DIR, "parsed_logs.json")
        save_parsed_logs(parsed, parsed_path)

        # Parse bash history separately (from all collected artifacts)
        bash_entries = []
        artifacts = get_artifacts_for_case(case_id)
        for art in artifacts:
            filename = art["artifact_name"]
            if "bash_history" in filename or "zsh_history" in filename:
                try:
                    file_path = art["file_path"]
                    if not os.path.isfile(file_path):
                        continue
                    username = filename.split("_")[0] if "_" in filename else "unknown"
                    entries = parse_bash_history(file_path)
                    for e in entries:
                        e["user"] = username
                    bash_entries.extend(entries)
                except Exception as e:
                    collect_logger.error(f"Failed to parse bash history {filename}: {e}")

        # Parse browser history and Ext4 properly from RAW_DISK_DIR since they reside there too
        browser_entries = parse_all_browsers(RAW_DISK_DIR)
        ext4_entries = parse_all_ext4(RAW_DISK_DIR)

        # Unify into common feature set
        unified = unify_logs(
            syslog_entries=parsed["syslog"],
            authlog_entries=parsed["authlog"],
            bash_entries=bash_entries,
            browser_entries=browser_entries,
            ext4_entries=ext4_entries
        )
        output_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
        save_unified_logs(unified, output_path)

        # Invalidate timeline cache to force rebuild with new data
        timeline_cache = os.path.join(PROCESSED_DIR, "unified_timeline.json")
        if os.path.exists(timeline_cache):
            os.remove(timeline_cache)
            collect_logger.info("Invalidated unified_timeline.json cache.")

        total = len(parsed["syslog"]) + len(parsed["authlog"]) + len(bash_entries)
        flash(
            f"Artifact parsing complete: {total} log entries parsed, "
            f"{len(unified)} unified records saved.",
            "success"
        )
    except Exception as e:
        flash(f"Artifact parsing failed: {str(e)}", "error")

    return redirect(url_for('view_case', case_id=case_id))

@app.route("/case/<case_id>/timeline")
def view_timeline(case_id):
    """Display the unified forensic timeline for a case."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    try:
        per_page = min(max(int(request.args.get("per_page", TIMELINE_PAGE_SIZE)), 1), 500)
    except ValueError:
        per_page = TIMELINE_PAGE_SIZE

    order = request.args.get("order", "desc")
    if order not in ("asc", "desc"):
        order = "desc"

    timeline_path = _ensure_timeline_cache()
    timeline_meta = _load_timeline_metadata(timeline_path)
    total_events = int(timeline_meta.get("total_events", 0) or 0)
    total_pages = max(1, math.ceil(total_events / per_page)) if total_events else 1
    page = min(page, total_pages)
    events = _load_timeline_page(timeline_path, page, per_page, order=order)

    return render_template(
        "timeline.html",
        case=case,
        events=events,
        total_events=total_events,
        total_pages=total_pages,
        page=page,
        per_page=per_page,
        order=order,
        timeline_meta=timeline_meta,
    )

@app.route("/api/timeline/<case_id>")
def api_timeline(case_id):
    """Return timeline data as JSON for AJAX/frontend consumption."""
    timeline_path = _ensure_timeline_cache()

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    try:
        per_page = min(max(int(request.args.get("per_page", TIMELINE_PAGE_SIZE)), 1), 500)
    except ValueError:
        per_page = TIMELINE_PAGE_SIZE

    order = request.args.get("order", "desc")
    if order not in ("asc", "desc"):
        order = "desc"

    timeline_meta = _load_timeline_metadata(timeline_path)
    total_events = int(timeline_meta.get("total_events", 0) or 0)
    total_pages = max(1, math.ceil(total_events / per_page)) if total_events else 1
    page = min(page, total_pages)
    events = _load_timeline_page(timeline_path, page, per_page, order=order)

    return jsonify({
        "status": "success",
        "generated_at": timeline_meta.get("generated_at", ""),
        "total_events": total_events,
        "total_pages": total_pages,
        "page": page,
        "per_page": per_page,
        "order": order,
        "time_range": timeline_meta.get("time_range", {}),
        "source_distribution": timeline_meta.get("source_distribution", {}),
        "events": events,
    })

@app.route("/case/<case_id>/scan-vt", methods=["POST"])
def scan_all_vt(case_id):
    """Scan all artifacts for a case against VirusTotal."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))

    artifacts = get_artifacts_for_case(case_id)
    if not artifacts:
        flash("No artifacts to scan. Run evidence collection first.", "error")
        return redirect(url_for('view_case', case_id=case_id))

    results = []
    for art in artifacts:
        path = art["file_path"]
        if not os.path.isfile(path):
            continue
        result = check_file(path)
        results.append(result)

    if results:
        save_threat_intel_results(results)

    flagged = sum(1 for r in results if r.get("positives", 0) > 0)
    errors = sum(1 for r in results if r.get("status") == "error")
    clean = len(results) - flagged - errors

    summary = f"VirusTotal scan complete: {len(results)} artifact(s) scanned — "
    summary += f"{clean} clean, {flagged} flagged, {errors} skipped/error."
    flash(summary, "success" if flagged == 0 else "error")

    return redirect(url_for('view_case', case_id=case_id))

@app.route("/case/<case_id>/scan/ml-anomaly", methods=["POST"])
def run_ml_anomaly_scan(case_id):
    """Run ML Anomaly Detection on normalized logs."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))
    
    normalized_path = os.path.join(PROCESSED_DIR, "normalized_logs.json")
    if not os.path.isfile(normalized_path):
        flash("No parsed logs found. Run 'Parse Artifacts' first.", "error")
        return redirect(url_for('view_case', case_id=case_id))
    
    try:
        alerts = detect_anomalies(case_id, normalized_path)
        insert_case_activity(CaseActivityEntry(case_id, f"ran_ml_scan_{len(alerts)}_anomalies_detected", case["investigator"]))
        flash(f"ML Anomaly Scan complete. {len(alerts)} anomaly/anomalies detected and logged.", "success" if len(alerts) == 0 else "warning")
    except Exception as e:
        collect_logger.error(f"ML Anomaly scan failed: {e}")
        flash(f"ML Anomaly Scan failed: {str(e)}", "error")
    
    return redirect(url_for('view_case', case_id=case_id))

@app.route("/case/<case_id>/scan/anti-forensics", methods=["POST"])
def run_anti_forensics_scan(case_id):
    """Run Anti-Forensics Detection on collected artifacts."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))
    
    try:
        alerts = detect_anti_forensics(case_id)
        insert_case_activity(CaseActivityEntry(case_id, f"ran_anti_forensics_scan_{len(alerts)}_alerts", case["investigator"]))
        flash(f"Anti-Forensics Scan complete. {len(alerts)} suspicious indicator(s) detected.", "success" if len(alerts) == 0 else "warning")
    except Exception as e:
        collect_logger.error(f"Anti-Forensics scan failed: {e}")
        flash(f"Anti-Forensics Scan failed: {str(e)}", "error")
    
    return redirect(url_for('view_case', case_id=case_id))

@app.route("/case/<case_id>/scan/blockchain", methods=["POST"])
def run_blockchain_logging(case_id):
    """Log all artifacts to the simulated blockchain ledger."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("index"))
    
    artifacts = get_artifacts_for_case(case_id)
    if not artifacts:
        flash("No artifacts to log. Run evidence collection first.", "error")
        return redirect(url_for('view_case', case_id=case_id))
    
    try:
        log_evidence_to_blockchain(case_id)
        insert_case_activity(CaseActivityEntry(case_id, "logged_artifacts_to_blockchain", case["investigator"]))
        flash(f"Blockchain Logging complete. {len(artifacts)} artifact(s) logged to immutable ledger.", "success")
    except Exception as e:
        collect_logger.error(f"Blockchain logging failed: {e}")
        flash(f"Blockchain Logging failed: {str(e)}", "error")
    
    return redirect(url_for('view_case', case_id=case_id))


@app.route("/case/<case_id>/report/pdf", methods=["POST"])
def generate_pdf_report(case_id):
    """Generate and return a PDF report for the case."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for('index'))

    try:
        report_type = request.form.get("type", "technical")
        outpath = generate_case_pdf(case_id, report_type=report_type)
        insert_case_activity(CaseActivityEntry(case_id, f"generated_{report_type}_pdf_report", case["investigator"]))
        return send_file(outpath, as_attachment=True)
    except Exception as e:
        collect_logger.error(f"PDF report generation failed: {e}")
        flash(f"PDF Report failed: {str(e)}", "error")
        return redirect(url_for('view_case', case_id=case_id))


@app.route("/case/<case_id>/validate", methods=["POST"])
def run_validation(case_id):
    """Validate case processed logs against a provided dataset file name (in processed/datasets)."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for('index'))

    dataset = request.form.get('dataset_file', '').strip()
    if not dataset:
        flash("Please provide a dataset file name to validate against.", "error")
        return redirect(url_for('view_case', case_id=case_id))

    try:
        report = validate_case_against_dataset(case_id, dataset)
        insert_case_activity(CaseActivityEntry(case_id, "ran_validation", case["investigator"]))
        flash(f"Validation complete: {report['matches']}/{report['expected_count']} matched. Observed {report['observed_count']}.", "success")
    except Exception as e:
        collect_logger.error(f"Validation failed: {e}")
        flash(f"Validation failed: {str(e)}", "error")

    return redirect(url_for('view_case', case_id=case_id))

@app.route("/api/blockchain/<case_id>")
def api_blockchain_ledger(case_id):
    """Fetch blockchain ledger entries for a case."""
    import html, urllib.parse
    case_id = html.unescape(urllib.parse.unquote(case_id))
    
    # Find the ledger file
    ledger_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "integrity", "blockchain", "simulated_ledger.json"
    )
    
    if not os.path.isfile(ledger_path):
        return jsonify({"status": "success", "ledger": [], "total_entries": 0, "total_artifacts": 0})
    
    try:
        with open(ledger_path, 'r') as f:
            ledger = json.load(f)
        
        # Filter to case-specific entries (exact match or case_id substring match)
        case_entries = []
        for entry in ledger:
            entry_case_id = entry.get("payload", {}).get("case_id", "")
            if entry_case_id == case_id or case_id in entry_case_id or entry_case_id in case_id:
                case_entries.append(entry)
                
        # Deduplicate entries by artifact name (keep the most recent transaction per artifact)
        # Because the user may have imported the same case multiple times from USB
        unique_entries = {}
        for entry in case_entries:
            art_name = entry.get("payload", {}).get("artifact_name")
            if art_name:
                # Entries appended later will overwrite earlier ones in the dict, which is exactly what we want (latest TX)
                unique_entries[art_name] = entry
                
        final_entries = list(unique_entries.values())
        # Sort them by timestamp descending (newest first)
        final_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return jsonify({
            "status": "success",
            "ledger": final_entries,
            "total_entries": len(final_entries),
            "total_artifacts": len(final_entries)
        })
    except Exception as e:
        collect_logger.error(f"Failed to read blockchain ledger: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/blockchain/status/<case_id>")
def api_blockchain_status(case_id):
    """Return blockchain chain summary and integrity status for a case."""
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Case not found"}), 404

    summary = get_ledger_summary(case_id)
    artifacts = get_artifacts_for_case(case_id)
    total_artifacts = len(artifacts)
    logged_artifacts = sum(1 for art in artifacts if art.get("blockchain_tx"))

    return jsonify({
        "status": "success",
        "case_id": case_id,
        "total_artifacts": total_artifacts,
        "logged_artifacts": logged_artifacts,
        "pending_artifacts": max(total_artifacts - logged_artifacts, 0),
        "fabric_configured": summary.get("fabric_configured", False),
        "fabric_mode": summary.get("fabric_mode", "simulated"),
        "chain_valid": summary.get("chain_valid", False),
        "last_hash": summary.get("last_hash", "GENESIS"),
        "issues": summary.get("issues", []),
    })


@app.route("/api/blockchain/tamper/<case_id>", methods=["POST"])
def api_blockchain_tamper(case_id):
    """Endpoint to intentionally tamper the simulated ledger for testing tamper detection.
    Accepts optional form field `mutate` with values `record_hash` or `payload`.
    """
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Case not found"}), 404

    mutate = request.form.get("mutate", "record_hash")
    try:
        result = tamper_ledger(case_id=case_id, mutate=mutate)
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        collect_logger.error(f"Tamper operation failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/case/<case_id>/report")
def case_report(case_id):
    """Generate and return a PDF report for the case."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for('index'))

    try:
        report_type = request.args.get("type", "technical")
        pdf_path = generate_case_pdf(case_id, report_type=report_type)
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        collect_logger.error(f"PDF report generation failed: {e}")
        flash(f"Report generation failed: {str(e)}", "error")
        return redirect(url_for('view_case', case_id=case_id))


@app.route("/case/<case_id>/validate", methods=["POST"])
def case_validate(case_id):
    """Validate detected alerts for a case against a ground-truth dataset."""
    case = get_case(case_id)
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for('index'))

    # Optional dataset path can be provided via form (hidden) in future
    result = validate_case_against_dataset(case_id)
    if result.get('status') != 'success':
        flash(result.get('message', 'Validation failed'), 'error')
    else:
        score = result.get('score', 0.0)
        flash(f"Validation complete: {result.get('matched')} / {result.get('ground_truth_total')} matched — score={score:.2f}", 'success')
    return redirect(url_for('view_case', case_id=case_id))

if __name__ == "__main__":
    # Ensure database exists
    from database.db_setup import init_db
    init_db()
    print("Starting CyberForensX Dashboard...")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
