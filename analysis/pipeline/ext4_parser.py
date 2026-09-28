"""
CyberForensX — EXT4 Metadata Parser
Module: analysis/pipeline/ext4_parser.py

Parses debugfs output for EXT4 metadata into structured records.
"""

import os
import re
import logging

logger = logging.getLogger(__name__)

def parse_ext4_metadata(file_path: str) -> list[dict]:
    records = []
    if not os.path.isfile(file_path):
        return records

    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()

        # Just a basic stub parser for demonstration 
        # that extracts some filesystem info from debugfs -R stats
        # since actual debugfs stats output doesn't contain a list of inodes easily without specific queries
        
        fs_volume_match = re.search(r"Filesystem volume name:\s*(.*)", content)
        last_mounted_match = re.search(r"Last mounted on:\s*(.*)", content)
        fs_uuid_match = re.search(r"Filesystem UUID:\s*(.*)", content)
        
        # In a real situation we'd parse specific inodes, but for debugfs stats, we just create a single record for the volume.
        records.append({
            "source": "ext4_metadata",
            "volume_name": fs_volume_match.group(1).strip() if fs_volume_match else "unknown",
            "last_mounted": last_mounted_match.group(1).strip() if last_mounted_match else "unknown",
            "uuid": fs_uuid_match.group(1).strip() if fs_uuid_match else "unknown",
            "raw_output": content[:200] + "..." # Just keeping a stub snippet
        })
        
    except Exception as e:
        logger.error(f"Ext4 parser error for {file_path}: {e}")
        
    return records

def parse_all_ext4(raw_disk_dir: str) -> list[dict]:
    all_records = []
    if not os.path.exists(raw_disk_dir):
        return all_records
        
    for filename in os.listdir(raw_disk_dir):
        if not filename.startswith("ext4_metadata_") or not filename.endswith(".txt"):
            continue
            
        file_path = os.path.join(raw_disk_dir, filename)
        all_records.extend(parse_ext4_metadata(file_path))
                
    return all_records
