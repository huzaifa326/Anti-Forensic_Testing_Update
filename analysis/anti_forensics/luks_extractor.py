"""
CyberForensX — LUKS Extractor
Module: analysis/anti_forensics/luks_extractor.py

Detects and extracts metadata for LUKS encrypted volumes as part of anti-forensics detection.
"""

import os
import subprocess
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def check_luks_magic(file_path: str) -> bool:
    """Check the first few bytes for LUKS magic headers."""
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            # LUKS1 and LUKS2 start with LUKS\xba\xbe
            if header.startswith(b"LUKS\xba\xbe"):
                return True
    except Exception as e:
        logger.error(f"Error reading magic bytes from {file_path}: {e}")
    return False

def extract_luks_metadata(device_or_file: str) -> Dict[str, Any]:
    """Use cryptsetup luksDump to extract metadata."""
    metadata = {
        "device": device_or_file,
        "is_luks": False,
        "uuid": "unknown",
        "cipher": "unknown",
        "cipher_mode": "unknown",
        "hash": "unknown",
        "payload_offset": "unknown",
        "version": "unknown"
    }
    
    try:
        # cryptsetup luksDump needs root to run on block devices, but works on images if readable
        result = subprocess.run(
            ["cryptsetup", "luksDump", device_or_file],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            metadata["is_luks"] = True
            output = result.stdout
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("UUID:"):
                    metadata["uuid"] = line.split(":", 1)[1].strip()
                elif line.startswith("Cipher name:"):
                    metadata["cipher"] = line.split(":", 1)[1].strip()
                elif line.startswith("Cipher mode:"):
                    metadata["cipher_mode"] = line.split(":", 1)[1].strip()
                elif line.startswith("Hash spec:"):
                    metadata["hash"] = line.split(":", 1)[1].strip()
                elif line.startswith("Payload offset:"):
                    metadata["payload_offset"] = line.split(":", 1)[1].strip()
                elif line.startswith("Version:"):
                    metadata["version"] = line.split(":", 1)[1].strip()
        else:
            # Maybe cryptsetup failed (e.g. not installed or no permission)
            # Let's fallback to magic bytes check
            if check_luks_magic(device_or_file):
                metadata["is_luks"] = True
                metadata["version"] = "LUKS (magic matched)"
    except Exception as e:
        logger.error(f"Failed to run cryptsetup on {device_or_file}: {e}")

    return metadata

def scan_for_luks(scan_paths: List[str]) -> List[Dict[str, Any]]:
    """Scan a list of files or block devices for LUKS volumes."""
    found_volumes = []
    
    for path in scan_paths:
        if not os.path.exists(path):
            continue
            
        meta = extract_luks_metadata(path)
        if meta.get("is_luks"):
            found_volumes.append(meta)
            
    return found_volumes
