#!/usr/bin/env bash
# CyberForensX — Disk Image Script
# Module: acquisition/scripts/disk_image.sh
#
# Creates a forensic disk image using dd.
# Usage: sudo bash disk_image.sh /dev/sda
# Requires root/sudo and enough storage space in storage/raw/disk/

set -euo pipefail

DEVICE="${1:-}"
if [ -z "${DEVICE}" ]; then
    echo "[ERROR] Usage: sudo bash disk_image.sh /dev/<device>"
    exit 1
fi

if [ ! -b "${DEVICE}" ]; then
    echo "[ERROR] Not a block device: ${DEVICE}"
    exit 1
fi

OUTPUT_DIR="../../storage/raw/disk"
mkdir -p "${OUTPUT_DIR}"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
DEVICE_NAME=$(basename "${DEVICE}")
OUTPUT_FILE="${OUTPUT_DIR}/disk_image_${DEVICE_NAME}_${TIMESTAMP}.dd"
HASH_FILE="${OUTPUT_FILE}.sha256"

echo "[INFO] Imaging device: ${DEVICE} → ${OUTPUT_FILE}"
echo "[INFO] This may take a long time depending on disk size."

# dd: bs=4M for efficient block reads; conv=noerror,sync to handle bad sectors
dd if="${DEVICE}" of="${OUTPUT_FILE}" bs=4M conv=noerror,sync status=progress

echo "[INFO] Computing SHA-256 hash..."
sha256sum "${OUTPUT_FILE}" > "${HASH_FILE}"
cat "${HASH_FILE}"
echo "[INFO] Disk image complete. Hash file: ${HASH_FILE}"
