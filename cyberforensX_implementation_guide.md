# CyberForensX — Complete Implementation Guide

> **AI-Assisted Automated Digital Forensics & Incident Reconstruction Platform**  
> Strictly derived from the FYP1 Scope Document and Mid Report.

---

## Overview

CyberForensX is a **host-based digital forensics platform for Linux endpoints** that automates the complete digital forensics lifecycle:

1. **Evidence Acquisition** — Collect volatile & non-volatile artifacts
2. **Forensic Analysis & Intelligence** — ML anomaly detection, anti-forensics detection, threat intel
3. **Integrity & Correlation** — Blockchain chain-of-custody, timeline reconstruction, multi-device correlation
4. **Reporting & Visualization** — Interactive dashboard, automated PDF reports

**Target Environment:** Linux laptops, desktops, and PCs  
**Primary Language:** Python + Shell Scripting  
**Out of Scope:** Network forensics, Mobile forensics, Windows/macOS analysis

---

## Feature-Based Folder Structure

```
CyberForensX/
│
├── acquisition/                        # Module 1: Evidence Acquisition
│   ├── __init__.py
│   ├── memory_collector.py             # RAM dump via LiME
│   ├── network_collector.py            # Active connections via Netstat
│   ├── disk_collector.py               # Disk artifact extraction (dd, EXT4 inode metadata)
│   ├── log_collector.py                # Syslog, Auth.log collection
│   ├── bash_history_collector.py       # Bash history extraction
│   └── scripts/
│       ├── lime_loader.sh              # Shell script to load LiME kernel module
│       └── disk_image.sh               # Shell script wrapping dd for disk imaging
│
├── analysis/                           # Module 2: Forensic Analysis & Intelligence
│   ├── __init__.py
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── log_parser.py               # Raw text → structured JSON (Syslog, Auth.log)
│   │   └── feature_engineer.py         # Unification pipeline: maps logs to common feature set
│   │                                   # (Timestamp, User_ID, Command_Type, Origin_IP)
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── anomaly_detector.py         # Isolation Forest ML model
│   │   └── model_trainer.py            # Training/evaluation logic
│   ├── anti_forensics/
│   │   ├── __init__.py
│   │   ├── timestomping_detector.py    # Detect fake/manipulated file timestamps
│   │   ├── dotfile_detector.py         # Detect hidden files (dotfiles)
│   │   ├── rootkit_detector.py         # Rootkit indicators & process hiding detection
│   │   └── luks_extractor.py           # Detect encrypted LUKS partitions
│   └── threat_intel/
│       ├── __init__.py
│       ├── virustotal_client.py        # VirusTotal API — file hash lookups
│       ├── misp_client.py              # MISP threat intelligence integration
│       ├── yara_scanner.py             # YARA pattern matching on artifacts
│       └── mitre_mapper.py             # Map findings to MITRE ATT&CK techniques
│
├── integrity/                          # Module 3: Integrity & Correlation
│   ├── __init__.py
│   ├── blockchain/
│   │   ├── __init__.py
│   │   ├── fabric_client.py            # Hyperledger Fabric connection & chaincode calls
│   │   ├── evidence_logger.py          # Hash & record artifacts on blockchain
│   │   └── chain_of_custody.py         # Retrieve & verify chain-of-custody records
│   ├── hashing.py                      # SHA-256 / MD5 hash generation for artifacts
│   ├── timeline_builder.py             # Merge logs, history, file events → unified timeline
│   └── multi_device_correlator.py      # Link events across devices (e.g., USB ↔ file copies)
│
├── reporting/                          # Module 4: Reporting & Visualization
│   ├── __init__.py
│   ├── dashboard/
│   │   ├── app.py                      # Web-based interactive dashboard (Flask/FastAPI)
│   │   ├── static/
│   │   │   ├── css/
│   │   │   └── js/
│   │   └── templates/
│   │       ├── index.html              # Dashboard home
│   │       └── timeline.html           # Interactive timeline visualization
│   ├── report_generator.py             # Jinja2 + ReportLab PDF report engine
│   ├── templates/
│   │   ├── technical_report.j2         # Technical report template (investigators)
│   │   └── executive_report.j2         # Executive summary template (management)
│   └── exporters/
│       ├── __init__.py
│       └── pdf_exporter.py             # Renders Jinja2 templates → PDF via ReportLab
│
├── storage/                            # Structured evidence storage (JSON output)
│   ├── raw/                            # Raw collected artifacts
│   │   ├── memory/                     # RAM dump files (.lime)
│   │   ├── disk/                       # Disk images
│   │   ├── logs/                       # Syslog, Auth.log copies
│   │   └── network/                    # Netstat capture output
│   └── processed/                      # Parsed JSON artifacts
│       ├── normalized_logs.json
│       ├── ml_anomalies.json
│       ├── anti_forensics_findings.json
│       ├── threat_intel_matches.json
│       └── unified_timeline.json
│
├── database/                           # Backend database setup
│   ├── db_setup.py                     # Database initialization (SQLite / PostgreSQL)
│   ├── models.py                       # ORM models for cases, artifacts, alerts
│   └── migrations/                     # Schema migration files
│
├── config/
│   ├── settings.py                     # Global configuration (paths, API keys, thresholds)
│   └── yara_rules/                     # YARA rule files
│       └── malware.yar
│
├── tests/                              # Test suite
│   ├── test_acquisition.py
│   ├── test_analysis.py
│   ├── test_integrity.py
│   └── test_reporting.py
│
├── main.py                             # Entry point — CLI orchestration of all modules
├── requirements.txt
└── README.md
```

---

## Module-by-Module Implementation Guide

---

### Module 1 — Evidence Acquisition

**Goal:** Automate collection of volatile and non-volatile artifacts from the Linux target machine.

#### 1.1 Memory Acquisition (`memory_collector.py`)

- Load the **LiME** kernel module via `lime_loader.sh`
- Capture full RAM dump to `storage/raw/memory/`
- Command wrapped in Python using `subprocess`:

```python
import subprocess, datetime, os

def capture_ram(output_dir="storage/raw/memory"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/ram_dump_{ts}.lime"
    # LiME must be pre-compiled for the target kernel
    subprocess.run(
        ["insmod", "lime.ko", f"path={output_file}", "format=lime"],
        check=True
    )
    return output_file
```

#### 1.2 Network Connection Capture (`network_collector.py`)

- Use `netstat -tunap` or `ss -tunap` to capture active connections
- Parse output and store as structured JSON

```python
import subprocess, json

def capture_network(output_path="storage/raw/network/netstat.json"):
    result = subprocess.run(["ss", "-tunap"], capture_output=True, text=True)
    # Parse lines into dicts: {proto, local_addr, remote_addr, state, pid}
    # Save to JSON
    ...
```

#### 1.3 Disk Artifact Extraction (`disk_collector.py`)

- Extract **EXT4 inode metadata** using `stat` and `debugfs`
- Collect **bash history**, config files ([/etc/passwd](file:///etc/passwd), [/etc/shadow](file:///etc/shadow), [/etc/hosts](file:///etc/hosts))
- Store raw copies under `storage/raw/disk/`

#### 1.4 Log Collection (`log_collector.py`)

- Copy `/var/log/syslog` and `/var/log/auth.log` to `storage/raw/logs/`
- Preserve original timestamps for forensic integrity

---

### Module 2 — Forensic Analysis & Intelligence

**Goal:** Parse raw artifacts, detect anomalies via ML, detect anti-forensics, and integrate threat intelligence.

#### 2.1 Unification Pipeline — Feature Engineering

**Purpose:** Map heterogeneous log formats into a common feature set for ML processing.

Common features extracted from both Syslog and Auth.log:

| Feature | Source |
|---|---|
| `Timestamp` | Both |
| `User_ID` | Auth.log |
| `Command_Type` | Syslog/Bash History |
| `Origin_IP` | Auth.log (SSH logins) |
| `Event_Type` | Both |

```python
# feature_engineer.py — example
def unify_logs(syslog_entries, authlog_entries):
    unified = []
    for entry in syslog_entries:
        unified.append({
            "timestamp": entry["ts"],
            "user_id": entry.get("user", "unknown"),
            "command_type": entry.get("cmd", ""),
            "origin_ip": "",
            "event_type": "system"
        })
    for entry in authlog_entries:
        unified.append({
            "timestamp": entry["ts"],
            "user_id": entry.get("user", "unknown"),
            "command_type": "auth",
            "origin_ip": entry.get("ip", ""),
            "event_type": "auth"
        })
    return unified
```

#### 2.2 ML Anomaly Detection — Isolation Forest (`anomaly_detector.py`)

- Train **Isolation Forest** on the unified feature vectors
- Flag anomalous log entries with anomaly scores
- Save flagged entries to `storage/processed/ml_anomalies.json`

```python
from sklearn.ensemble import IsolationForest
import numpy as np

def detect_anomalies(feature_matrix):
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(feature_matrix)
    scores = model.decision_function(feature_matrix)
    predictions = model.predict(feature_matrix)  # -1 = anomaly
    return predictions, scores
```

#### 2.3 Anti-Forensics Detection

##### Timestomping Detector (`timestomping_detector.py`)
- Compare `mtime`, `atime`, `ctime` via `stat()`
- Flag files where metadata timestamps are inconsistent with inode change time

```python
import os

def detect_timestomping(filepath):
    stat = os.stat(filepath)
    # If mtime > ctime, timestamps may have been manually set backwards
    if stat.st_mtime > stat.st_ctime:
        return True, f"Suspicious: mtime ({stat.st_mtime}) > ctime ({stat.st_ctime})"
    return False, "Clean"
```

##### Hidden Dotfiles Detector (`dotfile_detector.py`)
- Recursively scan home directories for hidden files (`.` prefixed) in unexpected locations
- Cross-reference against a whitelist of known dotfiles (`.bashrc`, `.profile`, etc.)

##### Rootkit Detector (`rootkit_detector.py`)
- Compare `/proc` process list vs `ps aux` output — discrepancies indicate hidden processes
- Check for hidden kernel modules by comparing `lsmod` vs `/proc/modules`

##### LUKS Extractor (`luks_extractor.py`)
- Detect LUKS-encrypted partitions using `blkid` and `cryptsetup luksDump`
- Log detected encrypted volumes as forensic artifacts

#### 2.4 Threat Intelligence Integration

##### VirusTotal (`virustotal_client.py`)
- Compute SHA-256 hash of collected files
- Query VirusTotal API to check hashes against malware databases

```python
import hashlib, requests

VT_API_KEY = "YOUR_API_KEY"

def check_hash(filepath):
    sha256 = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY}
    )
    return resp.json()
```

##### MISP (`misp_client.py`)
- Search MISP instance for matching IOCs (hashes, IPs, domains) from collected artifacts

##### YARA Scanner (`yara_scanner.py`)
- Apply YARA rule files (`config/yara_rules/`) against raw artifacts and memory dumps

##### MITRE ATT&CK Mapper (`mitre_mapper.py`)
- Map detected behaviors (e.g., timestomping, rootkit) to MITRE ATT&CK technique IDs

---

### Module 3 — Integrity & Correlation

**Goal:** Ensure evidence is tamper-proof using blockchain and reconstruct the attack timeline.

#### 3.1 Artifact Hashing (`hashing.py`)

- For every collected artifact, generate SHA-256 hash immediately after acquisition
- Record hash + metadata (filename, timestamp, investigator) before any analysis

#### 3.2 Blockchain Logging — Hyperledger Fabric (`fabric_client.py`, `evidence_logger.py`)

- Connect to a **Hyperledger Fabric** network
- Submit artifact hashes and chain-of-custody records to the blockchain ledger via chaincode
- Store the blockchain transaction ID alongside local evidence files

```python
# evidence_logger.py — conceptual
def log_to_blockchain(artifact_name, sha256_hash, timestamp, investigator):
    payload = {
        "artifact": artifact_name,
        "hash": sha256_hash,
        "timestamp": timestamp,
        "investigator": investigator
    }
    # Submit via Fabric SDK / REST gateway
    tx_id = fabric_client.submit_transaction("LogEvidence", payload)
    return tx_id
```

#### 3.3 Timeline Builder (`timeline_builder.py`)

- Merge events from: Syslog, Auth.log, Bash history, file system metadata, network captures
- Normalize all timestamps to UTC
- Sort merged events chronologically
- Output a unified timeline JSON to `storage/processed/unified_timeline.json`

```python
def build_timeline(sources: list[list[dict]]) -> list[dict]:
    all_events = []
    for source in sources:
        all_events.extend(source)
    return sorted(all_events, key=lambda e: e["timestamp"])
```

#### 3.4 Multi-Device Correlator (`multi_device_correlator.py`)

- Link USB mount events (from udev logs) with subsequent file copy events
- Correlate events across multiple device timelines to reconstruct attack paths
- Example: detect `USB inserted → file copied → USB removed` sequence

---

### Module 4 — Reporting & Visualization

**Goal:** Present investigation results through an interactive dashboard and automated PDF reports.

#### 4.1 Interactive Web Dashboard (`dashboard/app.py`)

- Build using **Flask** or **FastAPI**
- Display:
  - Security timeline (sortable, filterable)
  - ML anomaly alerts
  - Anti-forensics findings
  - Threat intelligence matches
  - Chain-of-custody blockchain verification status

#### 4.2 Timeline Visualization (`dashboard/templates/timeline.html`)

- Render unified timeline as an interactive chronological view in the browser
- Allow filtering by event type, user, time range

#### 4.3 Automated PDF Report Generation (`report_generator.py`)

Two report templates generated via **Jinja2** → rendered to PDF via **ReportLab**:

| Report | Audience | Content |
|---|---|---|
| Technical Report | Forensic Investigators | Evidence artifacts, ML anomaly alerts, threat intel matches, blockchain logs |
| Executive Report | Management | Incident summary, business impact, investigation status |

```python
from jinja2 import Environment, FileSystemLoader
from reportlab.pdfgen import canvas

def generate_pdf_report(template_name, context, output_path):
    env = Environment(loader=FileSystemLoader("reporting/templates"))
    template = env.get_template(template_name)
    rendered_html = template.render(**context)
    # Convert rendered content to PDF using ReportLab
    ...
```

---

## Technology Stack Summary

| Technology | Purpose | Module |
|---|---|---|
| Python | Core logic | All |
| Shell Scripting | Automation wrappers | Acquisition |
| LiME | RAM dump acquisition | Acquisition |
| `dd` | Disk imaging | Acquisition |
| Netstat / `ss` | Network connection capture | Acquisition |
| scikit-learn (Isolation Forest) | ML anomaly detection | Analysis |
| YARA | Pattern matching on artifacts | Analysis |
| VirusTotal API | File hash malware lookup | Analysis |
| MISP | Threat intelligence | Analysis |
| MITRE ATT&CK | Technique mapping | Analysis |
| Hyperledger Fabric | Blockchain chain-of-custody | Integrity |
| Jinja2 | Report templating | Reporting |
| ReportLab | PDF generation | Reporting |
| Flask / FastAPI | Web dashboard | Reporting |

---

## Implementation Iterations (per Project Timeline)

| Iteration | Duration | Focus |
|---|---|---|
| 01 | 4 Weeks | Environment setup, basic log/history collectors, database setup |
| 02 | 7 Weeks | JSON artifact parsing, VirusTotal/MISP integration, basic timeline sorting |
| 03 | 2 Months | Isolation Forest ML, anti-forensics detection (timestomping, rootkits), Hyperledger Fabric setup |
| 04 | 2 Months | Interactive dashboard, automated PDF reports, validation against forensic datasets |

---

## Team Responsibilities

| Member | Registration | Deliverables |
|---|---|---|
| Muhammad Huzaifa | 22i-1627 | Backend DB setup, system log collection scripts, timeline logic, timestomping detector, LUKS extractor |
| Huzaifa Afzal | 22i-1592 | Disk artifact scripts, VirusTotal API integration, blockchain network setup, USB event linking, PDF report generation |
| Hamna Ejaz | 22i-1645 | UI skeleton, browser history scripts, JSON log parsing, ML anomaly detection model, interactive timeline UI |

---

## Key Design Principles

> [!IMPORTANT]
> Every artifact must be **hashed and logged to the Hyperledger Fabric blockchain immediately after collection**, before any analysis, to ensure the chain of custody is forensically sound.

> [!NOTE]
> The **Unification Pipeline** is the critical bridge between the Acquisition and Analysis modules. It maps disparate log formats (Syslog text vs Auth.log structured) into a common JSON feature vector so the Isolation Forest can process them uniformly.

> [!WARNING]
> **LiME requires a kernel module compiled for the exact kernel version of the target machine.** This must be prepared in advance or cross-compiled on a matched build environment.

> [!TIP]
> Anti-forensics detection (timestomping, rootkit, hidden dotfiles) should run **before** the ML analysis stage so its findings can be included as additional features in the anomaly detection pipeline.
