#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CyberForensX — Portable USB Preparation Script                        ║
# ║  Prepares a self-contained forensic toolkit on a USB drive              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   ./prepare_usb.sh /media/hamna/USB_DRIVE
#
# This script:
#   1. Copies the CyberForensX project to the USB drive
#   2. Downloads a standalone portable Python (no install needed on suspect)
#   3. Installs all pip dependencies INTO the USB (vendor folder)
#   4. Creates the run.sh launcher
#   5. Creates evidence output directories
#
# After this, the USB is 100% self-contained — plug into any Linux x86_64
# machine and run without installing anything.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "┌──────────────────────────────────────────────────┐"
echo "│  CyberForensX — USB Forensic Toolkit Preparation │"
echo "└──────────────────────────────────────────────────┘"
echo -e "${NC}"

# ── Validate USB mount point ──────────────────────────────────────────────
if [ -z "$1" ]; then
    echo -e "${RED}[ERROR]${NC} Usage: $0 /path/to/usb/mount"
    echo ""
    echo "Available mounted drives:"
    lsblk -o NAME,SIZE,MOUNTPOINT | grep -v "loop"
    echo ""
    echo "Example: $0 /media/hamna/MY_USB"
    exit 1
fi

USB_PATH="$1"

if [ ! -d "$USB_PATH" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$USB_PATH' does not exist."
    echo "Make sure the USB is mounted first."
    exit 1
fi

# Check available space (need ~500MB minimum)
AVAIL_KB=$(df "$USB_PATH" | tail -1 | awk '{print $4}')
AVAIL_MB=$((AVAIL_KB / 1024))
echo -e "${CYAN}[*]${NC} USB mount: $USB_PATH"
echo -e "${CYAN}[*]${NC} Available space: ${AVAIL_MB} MB"

if [ "$AVAIL_MB" -lt 500 ]; then
    echo -e "${RED}[ERROR]${NC} Need at least 500 MB free. Only ${AVAIL_MB} MB available."
    exit 1
fi

TOOLKIT_DIR="$USB_PATH/CyberForensX"
PYTHON_DIR="$TOOLKIT_DIR/portable_python"
VENDOR_DIR="$TOOLKIT_DIR/vendor"
EVIDENCE_DIR="$TOOLKIT_DIR/evidence_output"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}[*]${NC} Source project: $PROJECT_DIR"
echo -e "${CYAN}[*]${NC} USB toolkit:    $TOOLKIT_DIR"
echo ""

# ── Step 1: Copy project files ───────────────────────────────────────────
echo -e "${GREEN}[1/5]${NC} Copying CyberForensX project to USB..."

# Preserve evidence_output if it exists (never delete collected evidence!)
if [ -d "$TOOLKIT_DIR/evidence_output" ]; then
    echo -e "   ${YELLOW}→${NC} Preserving existing evidence_output/ directory"
    mv "$TOOLKIT_DIR/evidence_output" "/tmp/_cyberforensx_evidence_backup_$$"
fi

rm -rf "$TOOLKIT_DIR"
mkdir -p "$TOOLKIT_DIR"

# Restore evidence if it was backed up
if [ -d "/tmp/_cyberforensx_evidence_backup_$$" ]; then
    mv "/tmp/_cyberforensx_evidence_backup_$$" "$TOOLKIT_DIR/evidence_output"
    echo -e "   ${GREEN}✓${NC} Previous evidence restored"
fi

# Copy everything except DB, collected evidence, pycache, .git
rsync -a --progress \
    --exclude='*.db' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='storage/raw/logs/*.txt' \
    --exclude='storage/raw/network/*.txt' \
    --exclude='storage/raw/disk/*_*' \
    --exclude='storage/raw/memory/*' \
    --exclude='storage/processed/*' \
    --exclude='*.tar.gz' \
    --exclude='cyberforensX.log' \
    --exclude='portable_python' \
    --exclude='vendor' \
    --exclude='evidence_output' \
    "$PROJECT_DIR/" "$TOOLKIT_DIR/"

echo -e "   ${GREEN}✓${NC} Project files copied"

# ── Step 2: Download portable Python ─────────────────────────────────────
echo -e "${GREEN}[2/5]${NC} Setting up portable Python..."

PYTHON_VERSION="3.12.3"
PYTHON_URL="https://github.com/indygreg/python-build-standalone/releases/download/20240415/cpython-${PYTHON_VERSION}+20240415-x86_64-unknown-linux-gnu-install_only.tar.gz"
PYTHON_TAR="/tmp/portable_python.tar.gz"

if [ ! -d "$PYTHON_DIR/bin" ]; then
    echo "   Downloading standalone Python ${PYTHON_VERSION} (~30 MB)..."
    if command -v wget &> /dev/null; then
        wget -q --show-progress -O "$PYTHON_TAR" "$PYTHON_URL"
    elif command -v curl &> /dev/null; then
        curl -L --progress-bar -o "$PYTHON_TAR" "$PYTHON_URL"
    else
        echo -e "${RED}[ERROR]${NC} Neither wget nor curl found. Install one first."
        exit 1
    fi

    echo "   Extracting..."
    mkdir -p "$PYTHON_DIR"
    tar xzf "$PYTHON_TAR" -C "$PYTHON_DIR" --strip-components=1
    rm -f "$PYTHON_TAR"
    echo -e "   ${GREEN}✓${NC} Portable Python ${PYTHON_VERSION} installed"
else
    echo -e "   ${YELLOW}→${NC} Portable Python already exists, skipping download"
fi

# ── Step 3: Install dependencies into vendor folder ──────────────────────
echo -e "${GREEN}[3/5]${NC} Installing Python dependencies to USB..."
mkdir -p "$VENDOR_DIR"

"$PYTHON_DIR/bin/python3" -m pip install \
    --target="$VENDOR_DIR" \
    --quiet \
    --no-cache-dir \
    -r "$TOOLKIT_DIR/requirements.txt"

echo -e "   ${GREEN}✓${NC} All dependencies installed to vendor/"

# ── Step 4: Create evidence output directories ───────────────────────────
echo -e "${GREEN}[4/5]${NC} Creating evidence output directories..."
mkdir -p "$EVIDENCE_DIR/raw/logs"
mkdir -p "$EVIDENCE_DIR/raw/disk"
mkdir -p "$EVIDENCE_DIR/raw/network"
mkdir -p "$EVIDENCE_DIR/raw/memory"
mkdir -p "$EVIDENCE_DIR/processed"
mkdir -p "$EVIDENCE_DIR/database"
echo -e "   ${GREEN}✓${NC} Evidence directories created"

# ── Step 5: Create the launcher scripts ──────────────────────────────────
echo -e "${GREEN}[5/5]${NC} Creating launcher scripts..."

# Main launcher: run.sh
cat > "$TOOLKIT_DIR/run.sh" << 'LAUNCHER'
#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CyberForensX — Portable Forensic Toolkit Launcher          ║
# ║  Run this from the USB drive on the suspect machine          ║
# ║                                                              ║
# ║  Usage:                                                      ║
# ║    sudo ./run.sh                        (dashboard mode)     ║
# ║    sudo ./run.sh --cli CASE-001 "Name"  (CLI collection)    ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

# Resolve the directory this script lives in (the USB)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$SCRIPT_DIR/portable_python/bin/python3"
VENDOR="$SCRIPT_DIR/vendor"

# Check we're running as root (needed for /etc/shadow, other users' history, etc.)
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "⚠  WARNING: Not running as root."
    echo "   Some evidence (e.g., /etc/shadow, other users' bash history)"
    echo "   will NOT be accessible. Re-run with sudo for full collection."
    echo ""
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Tell CyberForensX to use portable/USB paths
export CYBERFORENSX_PORTABLE=1
export CYBERFORENSX_EVIDENCE_DIR="$SCRIPT_DIR/evidence_output"
export PYTHONPATH="$VENDOR:$SCRIPT_DIR:$PYTHONPATH"

# Ensure evidence output directories exist
mkdir -p "$SCRIPT_DIR/evidence_output/raw/logs"
mkdir -p "$SCRIPT_DIR/evidence_output/raw/disk"
mkdir -p "$SCRIPT_DIR/evidence_output/raw/network"
mkdir -p "$SCRIPT_DIR/evidence_output/raw/memory"
mkdir -p "$SCRIPT_DIR/evidence_output/processed"
mkdir -p "$SCRIPT_DIR/evidence_output/database"

echo ""
echo "┌──────────────────────────────────────────────────┐"
echo "│  CyberForensX — Portable Forensic Toolkit        │"
echo "│  All evidence will be saved to USB drive          │"
echo "│  Suspect disk will NOT be modified                │"
echo "└──────────────────────────────────────────────────┘"
echo ""
echo "  Evidence output : $SCRIPT_DIR/evidence_output/"
echo "  Database        : $SCRIPT_DIR/evidence_output/database/cyberforensX.db"
echo ""

if [ "$1" == "--cli" ]; then
    # CLI mode: ./run.sh --cli CASE-ID "Investigator Name"
    if [ -z "$2" ] || [ -z "$3" ]; then
        echo "CLI Usage: sudo ./run.sh --cli CASE-ID \"Investigator Name\""
        exit 1
    fi
    echo "  Mode            : CLI Evidence Collection"
    echo "  Case            : $2"
    echo "  Investigator    : $3"
    echo ""
    "$PYTHON" "$SCRIPT_DIR/main.py" --case "$2" --investigator "$3" --collect
else
    # Dashboard mode (default)
    echo "  Mode            : Web Dashboard"
    echo "  URL             : http://localhost:5000"
    echo ""
    echo "  Press Ctrl+C to stop the dashboard."
    echo ""
    "$PYTHON" "$SCRIPT_DIR/reporting/dashboard/app.py"
fi
LAUNCHER

chmod +x "$TOOLKIT_DIR/run.sh"
echo -e "   ${GREEN}✓${NC} run.sh created"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  USB Forensic Toolkit is ready!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  USB Location : ${CYAN}$TOOLKIT_DIR${NC}"
echo -e "  Total Size   : $(du -sh "$TOOLKIT_DIR" | cut -f1)"
echo ""
echo -e "  ${YELLOW}On the suspect machine:${NC}"
echo -e "    1. Plug in the USB drive"
echo -e "    2. Mount it:  ${CYAN}sudo mount /dev/sdX1 /mnt/usb${NC}"
echo -e "    3. Run:       ${CYAN}sudo /mnt/usb/CyberForensX/run.sh${NC}"
echo -e "    4. Collect evidence via dashboard or CLI"
echo -e "    5. Unplug USB — all evidence is on the drive"
echo ""
