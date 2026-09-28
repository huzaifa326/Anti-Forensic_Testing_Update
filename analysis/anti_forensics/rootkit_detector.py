"""
CyberForensX — Rootkit Detector
Module: analysis/anti_forensics/rootkit_detector.py

Advanced heuristics for detecting rootkits and hidden processes.
"""

import os
import subprocess
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def find_hidden_pids() -> List[Dict[str, Any]]:
    """
    Compare /proc PIDs with `ps` output to find hidden processes.
    Note: Requires to be run on a live system, or adapt to parse collected ps_output and proc_listings.
    """
    hidden_processes = []
    
    try:
        # 1. Get PIDs from /proc
        proc_pids = set()
        for d in os.listdir("/proc"):
            if d.isdigit():
                proc_pids.add(int(d))
                
        # 2. Get PIDs from ps
        result = subprocess.run(["ps", "-e", "-o", "pid="], capture_output=True, text=True, timeout=10)
        ps_pids = set()
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.strip().isdigit():
                    ps_pids.add(int(line.strip()))
                    
        # 3. Compare. If a PID is in /proc but NOT in ps, ps is likely hooked (userland rootkit)
        # If a PID is in ps but NOT in /proc... wait, that shouldn't happen unless race condition.
        # But a kernel rootkit might hide from BOTH. In that case, we can't detect it this way easily without kernel modules.
        
        # Userland rootkit hiding from PS:
        userland_hidden = proc_pids - ps_pids
        for pid in userland_hidden:
            # Double check if it still exists (race condition mitigation)
            if os.path.exists(f"/proc/{pid}"):
                try:
                    with open(f"/proc/{pid}/cmdline", "r") as f:
                        cmdline = f.read().replace('\x00', ' ')
                except Exception:
                    cmdline = "unknown"
                hidden_processes.append({
                    "type": "hidden_process",
                    "pid": pid,
                    "cmdline": cmdline.strip(),
                    "desc": "PID exists in /proc but is hidden from ps output"
                })
                
    except Exception as e:
        logger.error(f"Error during hidden PID scan: {e}")
        
    return hidden_processes

def scan_kernel_modules() -> List[Dict[str, Any]]:
    """Scan for suspicious or hidden kernel modules."""
    findings = []
    try:
        # Note: A real deep scan requires comparing sysfs (/sys/module) vs lsmod output
        sysfs_mods = set(os.listdir("/sys/module"))
        
        result = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=10)
        lsmod_mods = set()
        if result.returncode == 0:
             # Skip header
            lines = result.stdout.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if parts:
                    lsmod_mods.add(parts[0])
                    
        hidden_mods = sysfs_mods - lsmod_mods
        # Filter out common false positives (many legitimate modules like workqueue, network contain 'rk')
        # Check for explicit rootkit indicators
        suspicious_keywords = ["rootkit", "rkhunter", "chkrootkit", "backdoor", "hook", "_rk", "rk_"]
        
        for mod in hidden_mods:
            mod_lower = mod.lower()
            for kw in suspicious_keywords:
                if kw in mod_lower:
                    findings.append({
                        "type": "hidden_module",
                        "module_name": mod,
                        "desc": f"Kernel module {mod} found in sysfs but not in lsmod."
                    })
                    break
    except Exception as e:
        logger.error(f"Error scanning kernel modules: {e}")
        
    return findings

def full_rootkit_scan() -> List[Dict[str, Any]]:
    """Run all rootkit heuristics."""
    results = []
    results.extend(find_hidden_pids())
    results.extend(scan_kernel_modules())
    return results
