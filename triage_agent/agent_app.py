import argparse
import os
import threading
import sqlite3
import pyotp
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from collectors import collect_all
from hasher import save_hash_manifest

app = Flask(__name__)
app.secret_key = "cyberforensx_super_secret_triage"

# --- DB SETUP FOR PORTABLE AGENT ---
DB_NAME = "/dev/shm/triage_users.db"

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        conn.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password_hash TEXT,
                        totp_secret TEXT
                     )''')
        conn.commit()
        conn.close()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- FLASK LOGIN MULTIPLEXING ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username, totp_secret):
        self.id = str(id)
        self.username = username
        self.totp_secret = totp_secret

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['totp_secret'])
    return None

# --- AUTH ROUTES ---
@app.route("/signup", methods=["GET", "POST"])
def signup():
    db = get_db()
    # Security: Only allow one investigator to claim this ephemeral RAM session.
    count = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
    if count and count['count'] > 0:
        flash("Security Lock: An investigator has already claimed this session. New signups are disabled.", "error")
        return redirect(url_for('login'))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        db = get_db()
        existing = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already exists.", "error")
            return redirect(url_for('signup'))
            
        pwhash = generate_password_hash(password)
        totp_secret = pyotp.random_base32()
        
        cur = db.execute("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
                         (username, pwhash, totp_secret))
        db.commit()
        
        # Log them in temporarily for 2FA setup
        u = User(cur.lastrowid, username, totp_secret)
        login_user(u)
        session['2fa_setup_pending'] = True
        return redirect(url_for('setup_2fa'))
        
    return render_template("signup.html")

@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if not session.get('2fa_setup_pending'):
        return redirect(url_for('index'))
        
    if request.method == "POST":
        code = request.form.get("code", "")
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code):
            session.pop('2fa_setup_pending', None)
            session['2fa_authenticated'] = True
            flash("2FA successfully configured!", "info")
            return redirect(url_for('index'))
        flash("Invalid code.", "error")
        return redirect(url_for('setup_2fa'))
    
    totp = pyotp.TOTP(current_user.totp_secret)
    qr_uri = totp.provisioning_uri(name=current_user.username, issuer_name="CyberForensX-Triage")
    
    import qrcode
    import io
    import base64
    qr = qrcode.make(qr_uri)
    buf = io.BytesIO()
    qr.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    
    return render_template("setup_2fa.html", secret=current_user.totp_secret, qr_b64=qr_b64)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and session.get('2fa_authenticated'):
        return redirect(url_for('index'))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            u = User(user['id'], user['username'], user['totp_secret'])
            login_user(u)
            session['2fa_authenticated'] = False
            return redirect(url_for('verify_2fa'))
            
        flash("Invalid credentials.", "error")
    return render_template("login.html")

@app.route("/verify_2fa", methods=["GET", "POST"])
@login_required
def verify_2fa():
    if request.method == "POST":
        code = request.form.get("code", "")
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code):
            session['2fa_authenticated'] = True
            return redirect(url_for('index'))
        flash("Invalid 2FA code.", "error")
    return render_template("2fa.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))


# --- TRIAGE CORE LOGIC ---
collection_status = {"status": "idle", "logs": []}

def log_msg(msg):
    print(f"[*] {msg}")
    collection_status["logs"].append(msg)

def run_collection(case_id, modules, title=None, investigator=None):
    collection_status["status"] = "running"
    base_dir = f"CASE_{case_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(base_dir, exist_ok=True)
    log_msg(f"Target directory: {base_dir}")
    
    artifacts = collect_all(base_dir, modules, log_msg)
    manifest_path = os.path.join(base_dir, "manifest.json")
    save_hash_manifest(artifacts, manifest_path, case_id=case_id, title=title, investigator=investigator)
    
    log_msg(f"Collection complete. Manifest saved at {manifest_path}")
    collection_status["status"] = "complete"

@app.route("/")
@login_required
def index():
    if not session.get('2fa_authenticated'):
        return redirect(url_for('verify_2fa'))
    return render_template("index.html")

@app.route("/api/start", methods=["POST"])
@login_required
def start_collection():
    if not session.get('2fa_authenticated'):
        return jsonify({"error": "Unauthorized"}), 401
        
    if collection_status["status"] == "running":
        return jsonify({"error": "Already running"}), 400
    data = request.json
    case_id = data.get("case_id", "CASE-OFFLINE-001")
    title = data.get("title", "Offline Triage Import")
    investigator = data.get("investigator", "USB Agent")
    modules = data.get("modules", [])
    collection_status["logs"] = []
    threading.Thread(target=run_collection, args=(case_id, modules, title, investigator)).start()
    return jsonify({"status": "started"})

@app.route("/api/status")
@login_required
def status():
    return jsonify(collection_status)

if __name__ == "__main__":
    init_db()
    parser = argparse.ArgumentParser(description="CyberForensX Zero-Footprint Triage Agent")
    parser.add_argument("--case-id", type=str, help="Case ID for headless execution")
    parser.add_argument("--auto", action="store_true", help="Run in headless CLI mode and exit")
    args = parser.parse_args()

    if args.auto:
        if not args.case_id:
            print("[!] --case-id is required for --auto mode")
            exit(1)
        run_collection(args.case_id, ["volatile", "logs", "history", "browser", "disk"])
    else:
        print("Starting Triage Dashboard on http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=5000, debug=False)
