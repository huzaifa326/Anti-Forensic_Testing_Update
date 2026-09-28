# CyberForensX

> AI-Assisted Automated Digital Forensics & Incident Reconstruction Platform  
> Target: Linux endpoints | FYP — FAST-NUCES Islamabad

---

## Team

| Name | ID | Module |
|---|---|---|
| Hamna Ejaz | 22I-1645 | UI, JSON Parsing, ML Model, Timeline UI |
| Huzaifa Afzal | 22I-1592 | Disk Scripts, VirusTotal, Blockchain, PDF Reports |
| Muhammad Huzaifa | 22I-1627 | Database, Log Collection, Timeline Logic, Anti-Forensics |

**Supervisor:** Mr. Mehmood Ul Hassan

---

## What It Does

CyberForensX automates the complete digital forensics lifecycle on Linux:

1. **Evidence Acquisition** — Collects RAM, disk, logs, and network artifacts
2. **Forensic Analysis** — Isolation Forest ML anomaly detection, anti-forensics detection, threat intel
3. **Integrity & Correlation** — Hyperledger Fabric blockchain chain-of-custody, timeline reconstruction
4. **Reporting** — Interactive dashboard, automated PDF reports (Technical & Executive)

---

## Folder Structure

```
CyberForensX/
├── acquisition/          # Module 1: Evidence Acquisition
│   ├── log_collector.py          # Syslog + Auth.log
│   ├── bash_history_collector.py # Bash history (all users)
│   ├── disk_collector.py         # Config files + EXT4 metadata
│   ├── network_collector.py      # ss/netstat connections
│   ├── memory_collector.py       # RAM dump via LiME
│   └── scripts/
│       ├── lime_loader.sh        # LiME kernel module loader
│       └── disk_image.sh         # dd disk imager
│
├── analysis/             # Module 2: Forensic Analysis & Intelligence
│   ├── pipeline/
│   │   ├── log_parser.py         # Raw logs → JSON (Iteration 2)
│   │   └── feature_engineer.py   # Unification pipeline (Iteration 2)
│   ├── ml/
│   │   ├── anomaly_detector.py   # Isolation Forest (Iteration 3)
│   │   └── model_trainer.py      # (Iteration 3)
│   ├── anti_forensics/
│   │   ├── timestomping_detector.py  # (Iteration 3)
│   │   ├── dotfile_detector.py       # (Iteration 3)
│   │   ├── rootkit_detector.py       # (Iteration 3)
│   │   └── luks_extractor.py         # (Iteration 3)
│   └── threat_intel/
│       ├── virustotal_client.py  # (Iteration 2)
│       ├── misp_client.py        # (Iteration 2)
│       ├── yara_scanner.py       # (Iteration 2)
│       └── mitre_mapper.py       # (Iteration 2)
│
├── integrity/            # Module 3: Integrity & Correlation
│   ├── hashing.py                # SHA-256/MD5 artifact hashing ✅
│   ├── blockchain/
│   │   ├── fabric_client.py      # Hyperledger Fabric (Iteration 3)
│   │   ├── evidence_logger.py    # (Iteration 3)
│   │   └── chain_of_custody.py   # (Iteration 3)
│   ├── timeline_builder.py       # (Iteration 2)
│   └── multi_device_correlator.py # (Iteration 2)
│
├── reporting/            # Module 4: Reporting & Visualization
│   ├── dashboard/
│   │   ├── app.py                # Flask dashboard (Iteration 4)
│   │   ├── static/css/
│   │   ├── static/js/
│   │   └── templates/
│   │       ├── index.html        # (Iteration 4)
│   │       └── timeline.html     # (Iteration 4)
│   ├── report_generator.py       # (Iteration 4)
│   ├── templates/
│   │   ├── technical_report.j2   # (Iteration 4)
│   │   └── executive_report.j2   # (Iteration 4)
│   └── exporters/pdf_exporter.py # (Iteration 4)
│
├── storage/
│   ├── raw/memory/       # RAM dumps (.lime files)
│   ├── raw/disk/         # Disk images + config copies
│   ├── raw/logs/         # Syslog, Auth.log copies
│   ├── raw/network/      # Netstat output
│   └── processed/        # Parsed JSON artifacts
│
├── database/
│   ├── db_setup.py       # SQLite init + CRUD ✅
│   ├── models.py         # Cases, Artifacts, Alerts, CustodyLog ✅
│   └── cyberforensX.db   # (auto-created on first run)
│
├── config/
│   ├── settings.py       # Global configuration ✅
│   └── yara_rules/malware.yar
│
├── tests/
│   └── test_acquisition.py  # Pytest suite ✅
│
├── main.py               # CLI entry point ✅
└── requirements.txt      # Python dependencies ✅
```

✅ = Implemented in Iteration 1

---

## Quick Start — Iteration 1

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Initialise the database

```bash
python main.py --init-db
```

### 3. Run evidence collection

```bash
# Collect logs, bash history, config files, network connections
sudo python main.py \
  --case CASE-2026-001 \
  --investigator "Hamna Ejaz" \
  --collect

# With optional EXT4 metadata from a disk device
sudo python main.py \
  --case CASE-2026-001 \
  --investigator "Hamna Ejaz" \
  --collect \
  --device /dev/sda1
```

### 4. Run tests

```bash
python -m pytest tests/ -v
```

---

## Technologies

| Technology | Purpose | Iteration |
|---|---|---|
| Python | Core logic | All |
| Shell Scripting | LiME + dd wrappers | 1 |
| SQLite | Case & artifact database | 1 |
| scikit-learn (Isolation Forest) | ML anomaly detection | 3 |
| YARA | Pattern matching | 2 |
| VirusTotal API | Hash malware lookup | 2 |
| MISP | Threat intelligence | 2 |
| Hyperledger Fabric | Blockchain chain-of-custody | 3 |
| Jinja2 + ReportLab | PDF reports | 4 |
| Flask | Web dashboard | 4 |

---

## Important Notes

> **LiME** requires a kernel module compiled for the **exact kernel version** of the target machine (`uname -r`). See `acquisition/scripts/lime_loader.sh` for instructions.

> All artifacts are **hashed (SHA-256) immediately after collection** and before any analysis, establishing a forensically sound chain of custody.

> The system is scoped to **Linux endpoints only**. Network forensics, mobile forensics, and Windows/macOS are out of scope.
