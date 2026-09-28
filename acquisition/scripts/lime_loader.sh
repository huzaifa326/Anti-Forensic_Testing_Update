"""
CyberForensX — Shell script to load LiME kernel module
Module: acquisition/scripts/lime_loader.sh

Usage: sudo bash lime_loader.sh [output_path]
Requires: LiME .ko pre-compiled for target kernel (uname -r)
"""
#!/usr/bin/env bash

set -euo pipefail

KERNEL_VER=$(uname -r)
LIME_MODULE="lime-${KERNEL_VER}.ko"
OUTPUT_DIR="../../storage/raw/memory"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/ram_dump_${TIMESTAMP}.lime"

mkdir -p "${OUTPUT_DIR}"

if [ ! -f "${LIME_MODULE}" ]; then
    echo "[ERROR] LiME module not found: ${LIME_MODULE}"
    echo "        Compile LiME for kernel ${KERNEL_VER}:"
    echo "        git clone https://github.com/504ensicsLabs/LiME"
    echo "        cd LiME/src && make"
    exit 1
fi

echo "[INFO] Loading LiME module: ${LIME_MODULE}"
echo "[INFO] Output file: ${OUTPUT_FILE}"
insmod "${LIME_MODULE}" "path=${OUTPUT_FILE}" format=lime

echo "[INFO] RAM dump complete: ${OUTPUT_FILE}"
rmmod lime
echo "[INFO] LiME module unloaded."
