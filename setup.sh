#!/bin/bash
# CyberForensX — Environment Setup Script (Iteration 1)

echo "┌──────────────────────────────────────────┐"
echo "│ CyberForensX Environment Setup           │"
echo "└──────────────────────────────────────────┘"

echo "[*] Checking Python version..."
python3 --version || { echo "Python 3 is required but not installed."; exit 1; }

echo "[*] Installing required system dependencies..."
# We use --break-system-packages for Kali Linux as requested during development,
# but ideally a venv should be used.
pip install -r requirements.txt --break-system-packages -q

echo "[*] Ensuring all storage directories exist..."
mkdir -p storage/raw/logs
mkdir -p storage/raw/disk
mkdir -p storage/raw/network
mkdir -p storage/raw/memory
mkdir -p storage/processed

echo "[*] Initializing the database..."
python3 main.py --init-db

echo "[*] Environment setup complete!"
echo "    Run the collectors with: sudo python3 main.py --case CASE-001 --investigator <Name> --collect"
