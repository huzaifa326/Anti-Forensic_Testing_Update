"""
CyberForensX — Global Configuration
Module: config/settings.py
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# Portable Mode Detection
# ─────────────────────────────────────────────────────────────────────────────
# When CYBERFORENSX_PORTABLE=1 is set (by run.sh on USB), all evidence
# storage and database paths point to the USB drive's evidence_output/
# directory. This ensures ZERO writes to the suspect machine's disk.
PORTABLE_MODE = os.environ.get("CYBERFORENSX_PORTABLE", "0") == "1"

# ─────────────────────────────────────────────────────────────────────────────
# Base Paths
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PORTABLE_MODE:
    # All output goes to the USB's evidence_output/ folder
    EVIDENCE_BASE = os.environ.get("CYBERFORENSX_EVIDENCE_DIR",
                                    os.path.join(BASE_DIR, "evidence_output"))
    STORAGE_DIR   = os.path.join(EVIDENCE_BASE, "raw")
    RAW_DIR       = STORAGE_DIR
    PROCESSED_DIR = os.path.join(EVIDENCE_BASE, "processed")
else:
    # Normal development mode — storage inside project
    STORAGE_DIR      = os.path.join(BASE_DIR, "storage")
    RAW_DIR          = os.path.join(STORAGE_DIR, "raw")
    PROCESSED_DIR    = os.path.join(STORAGE_DIR, "processed")

# Raw sub-directories
RAW_MEMORY_DIR   = os.path.join(RAW_DIR, "memory")
RAW_DISK_DIR     = os.path.join(RAW_DIR, "disk")
RAW_LOGS_DIR     = os.path.join(RAW_DIR, "logs")
RAW_NETWORK_DIR  = os.path.join(RAW_DIR, "network")

# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────
if PORTABLE_MODE:
    DATABASE_PATH = os.path.join(EVIDENCE_BASE, "database", "cyberforensX.db")
else:
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "cyberforensX.db")

# ─────────────────────────────────────────────────────────────────────────────
# Evidence Source Paths (Linux defaults)
# ─────────────────────────────────────────────────────────────────────────────
SYSLOG_PATH    = "/var/log/syslog"
AUTHLOG_PATH   = "/var/log/auth.log"
BASH_HIST_PATH = os.path.expanduser("~/.bash_history")

# ─────────────────────────────────────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────────────────────────────────────
HASH_ALGORITHM = "sha256"   # Used for artifact integrity verification

# ─────────────────────────────────────────────────────────────────────────────
# Email Configuration (for 2FA)
# ─────────────────────────────────────────────────────────────────────────────
SMTP_SERVER   = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "ejazhamna25@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "ggkrmnmrnmgldhvn")

# ─────────────────────────────────────────────────────────────────────────────
# Threat Intelligence API Keys (fill in before use)
# ─────────────────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")
MISP_URL           = os.environ.get("MISP_URL", "")
MISP_API_KEY       = os.environ.get("MISP_API_KEY", "")

# ─────────────────────────────────────────────────────────────────────────────
# YARA Rules
# ─────────────────────────────────────────────────────────────────────────────
YARA_RULES_DIR = os.path.join(BASE_DIR, "config", "yara_rules")

# ─────────────────────────────────────────────────────────────────────────────
# ML Configuration
# ─────────────────────────────────────────────────────────────────────────────
ML_CONTAMINATION = 0.05   # Expected anomaly fraction for Isolation Forest
ML_N_ESTIMATORS  = 100

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
