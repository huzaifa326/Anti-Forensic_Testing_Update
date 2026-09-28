#!/bin/bash
set -e

echo "[*] Installing PyInstaller if needed..."
python3 -m pip install --upgrade pyinstaller flask --quiet

echo "[*] Packaging Triage Agent into a standalone binary..."
cd triage_agent

# Ensure we include the templates folder for Flask
python3 -m PyInstaller --onefile \
    --add-data "templates:templates" \
    --name cyberforensx-triage \
    agent_app.py

echo ""
echo "[+] Build complete!"
echo "[+] Your zero-footprint portable binary is located at:"
echo "    $(pwd)/dist/cyberforensx-triage"
echo ""
echo "You can now copy 'cyberforensx-triage' to your empty USB drive."
echo "No other files or python environments are required!"
