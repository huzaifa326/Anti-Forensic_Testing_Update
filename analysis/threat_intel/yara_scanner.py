"""
CyberForensX — YARA Scanner
Module: analysis/threat_intel/yara_scanner.py

Provides pattern-based malware detection for forensic artifacts using YARA rules.
"""

import os
import yara
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Default path for YARA rules
YARA_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config", "yara_rules"
)

class YaraScanner:
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile all .yar files in the rules directory."""
        rule_files = {}
        if not os.path.isdir(self.rules_dir):
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    rule_files[file] = os.path.join(root, file)

        if not rule_files:
            logger.info("No YARA rules found for compilation.")
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"Successfully compiled {len(rule_files)} YARA rule file(s).")
        except yara.Error as e:
            logger.error(f"YARA compilation error: {e}")

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a file and return a list of matches.
        
        Returns:
            List of dicts containing 'rule', 'tags', and 'meta'.
        """
        if not self.rules:
            return []

        if not os.path.isfile(file_path):
            logger.error(f"File not found for scanning: {file_path}")
            return []

        try:
            matches = self.rules.match(file_path)
            results = []
            for m in matches:
                matched_strings = []
                for s in m.strings[:5]:
                    # Handle both tuple and object structures for compatibility
                    if isinstance(s, tuple):
                        data = s[2]
                    else:
                        # For StringMatch objects in newer yara-python
                        data = s.instances[0].matched_data if s.instances else b""
                    matched_strings.append(data.decode(errors='replace'))

                results.append({
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": m.meta,
                    "strings": matched_strings
                })
            return results
        except yara.Error as e:
            logger.error(f"YARA scanning error for {file_path}: {e}")
            return []

    def scan_directory(self, dir_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Scan all files in a directory recursively."""
        all_results = {}
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                matches = self.scan_file(full_path)
                if matches:
                    all_results[full_path] = matches
        return all_results

def scan_artifact(file_path: str) -> Dict[str, Any]:
    """Helper function to scan a single artifact and return a summary."""
    scanner = YaraScanner()
    matches = scanner.scan_file(file_path)
    if matches:
        return {
            "status": "matches_found",
            "matches_count": len(matches),
            "matches": matches
        }
    return {"status": "clean", "matches_count": 0, "matches": []}
