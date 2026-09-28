# CyberForensX
### AI-Assisted Automated Digital Forensics & Incident Reconstruction Platform

CyberForensX is a **Final Year Project** that provides an **AI-powered digital forensics platform for Linux systems**.  
The platform automates the digital forensics lifecycle including **evidence acquisition, analysis, correlation, and reporting**.

It integrates **Machine Learning, Blockchain, and Threat Intelligence** to help investigators reconstruct cyber incidents efficiently.

---

# Project Information

**Project Team**

- Hamna Ejaz (22I-1645)
- Huzaifa Afzal (22I-1592)
- Muhammad Huzaifa (22I-1627)

**Supervisor**

Mr. Mehmood Ul Hassan

**Department**

Department of Cyber Security  
National University of Computer and Emerging Sciences (FAST-NUCES)  
Islamabad, Pakistan  

**Session:** 2022 – 2027

---

# Table of Contents

- Introduction
- Problem Statement
- Scope
- System Modules
- User Classes
- Functional Requirements
- Non-Functional Requirements
- System Architecture
- Design Models
- Data Design
- References

---

# Introduction

CyberForensX is an **AI-assisted digital forensics platform** designed to automate the investigation of cyber incidents on **Linux endpoints**.

Traditional digital forensic investigations rely on **multiple disconnected tools**, manual evidence collection, and time-consuming analysis. CyberForensX addresses these issues by creating a **unified automated system** capable of:

- Collecting digital evidence automatically
- Detecting anomalies using machine learning
- Correlating events across devices
- Ensuring evidence integrity using blockchain
- Generating automated investigation reports

---

# Problem Statement

Modern digital forensic investigations face several major challenges:

### 1. Fragmented Forensics Tools
Investigators typically use separate tools such as:

- Autopsy
- Volatility
- Log analyzers

These tools lack integration and require manual workflows.

### 2. Massive Data Volume
Cyber attacks generate **large volumes of system logs, memory artifacts, and disk data**, making manual analysis slow and inefficient.

### 3. Limited Linux Forensics Automation
Most forensic frameworks focus on **Windows systems**, leaving gaps in automated Linux artifact analysis.

### 4. Lack of Intelligent Detection
Traditional tools rely on **signature-based detection**, which may fail to identify sophisticated attacks or anti-forensics techniques.

### 5. Evidence Integrity Issues
Traditional chain-of-custody mechanisms can be **tampered with**, potentially compromising legal admissibility.

---

# Project Scope

CyberForensX focuses specifically on **host-based Linux digital forensics**.

The system performs the entire **digital forensic lifecycle**, including:

1. Automated evidence acquisition
2. Artifact processing
3. Threat analysis
4. Timeline reconstruction
5. Evidence verification
6. Report generation

### Supported Artifacts

- EXT4 filesystem metadata
- Syslog
- Auth.log
- Bash history
- Memory dumps
- Network connections

### Technologies Used

- Python
- Machine Learning (Isolation Forest)
- Hyperledger Fabric (Blockchain)
- VirusTotal API
- MISP Threat Intelligence
- YARA rules
- Jinja2
- ReportLab

### Excluded Scope

The project **does not include**:

- Network forensics
- Mobile forensics
- Windows/macOS analysis

---

# System Modules

CyberForensX consists of **four core modules**.

---

# 1. Evidence Acquisition Module

This module automates the collection of digital evidence from Linux systems.

### Features

- RAM dump collection using **LiME**
- Network connection capture using **Netstat**
- Disk artifact extraction
- Log file collection
- Structured evidence storage

### Collected Data

- Memory artifacts
- Bash history
- Configuration files
- EXT4 metadata
- Syslog
- Auth.log

---

# 2. Forensic Analysis & Intelligence Module

This module analyzes collected artifacts using **rule-based and machine learning techniques**.

### Features

- Log normalization pipeline
- ML-based anomaly detection
- Anti-forensics detection
- Rootkit detection
- Threat intelligence integration

### Detection Capabilities

- Timestomping detection
- Hidden dotfiles detection
- Rootkit indicators
- Encrypted LUKS partitions
- Malware hash matching

### Machine Learning

Algorithm used:

```
Isolation Forest
```

This model identifies unusual system behavior patterns.

---

# 3. Integrity & Correlation Module

This module ensures **evidence authenticity and timeline reconstruction**.

### Features

- Blockchain-based evidence verification
- Chain of custody management
- Cross-device correlation
- Unified attack timeline reconstruction

### Blockchain Technology

CyberForensX uses **Hyperledger Fabric** to:

- Store artifact hashes
- Ensure evidence integrity
- Provide tamper-proof logging

---

# 4. Reporting & Visualization Module

This module provides **visual and documented investigation results**.

### Features

- Interactive web dashboard
- Timeline visualization
- Automated report generation
- Executive-level summaries

### Generated Reports

Two report types are produced:

#### Technical Report
For investigators, including:

- Evidence artifacts
- ML anomaly alerts
- Threat intelligence matches
- Blockchain logs

#### Executive Report
For management:

- Incident summary
- Business impact
- Investigation status

---

# User Classes

CyberForensX supports multiple user roles.

| User | Role |
|-----|-----|
| Forensic Investigator | Performs deep forensic analysis |
| Security Team | Responds to active incidents |
| Executive Leadership | Reviews summarized reports |
| Legal Auditor | Verifies chain of custody |
| Project Supervisor | Evaluates project implementation |

---

# Functional Requirements

### Evidence Acquisition

- Capture RAM using LiME
- Collect network connection data
- Extract system logs
- Capture filesystem metadata

### Analysis

- Detect anomalies using ML
- Identify anti-forensic techniques
- Integrate external threat intelligence

### Integrity

- Generate artifact hashes
- Store hashes in blockchain
- Maintain immutable evidence logs

### Reporting

- Display investigation dashboard
- Generate PDF reports
- Visualize attack timeline

---

# Non-Functional Requirements

### Reliability
System must maintain accurate evidence collection and analysis.

### Usability
The platform must provide a simple and intuitive dashboard.

### Performance
Evidence processing should occur efficiently even with large datasets.

### Security
Evidence integrity must be cryptographically protected.

### Maintainability
The system should support modular updates.

### Portability
The platform should run on Linux systems.

---

# System Architecture

CyberForensX uses a **layered architecture**.

```
+-------------------------------+
|   Reporting & Visualization   |
+-------------------------------+
|   Integrity & Correlation     |
+-------------------------------+
|   Analysis & Intelligence     |
+-------------------------------+
|   Evidence Acquisition        |
+-------------------------------+
|        Linux Endpoint         |
+-------------------------------+
```

---

# Design Models

The project includes several system design diagrams:

- Use Case Diagram
- Domain Model
- Activity Diagram
- Class Diagram
- Sequence Diagram
- State Transition Diagram

These diagrams illustrate system workflow, architecture, and component interactions.

---

# Data Design

The system converts raw artifacts into **structured JSON format** for processing.

This enables:

- Log normalization
- Efficient analysis
- Event correlation
- Timeline reconstruction

---

# Key Technologies

| Technology | Purpose |
|---|---|
| Python | Core development |
| LiME | Memory acquisition |
| Isolation Forest | ML anomaly detection |
| Hyperledger Fabric | Evidence integrity |
| VirusTotal API | Malware intelligence |
| MISP | Threat intelligence |
| YARA | Malware detection |
| Jinja2 | Report templating |
| ReportLab | PDF report generation |

---

# Expected Outcomes

CyberForensX will provide:

- Faster digital investigations
- Automated forensic workflows
- Intelligent anomaly detection
- Secure chain of custody
- Comprehensive forensic reports

---

# References

Key references include research on:

- Digital Forensics Automation
- Machine Learning for Cybersecurity
- Blockchain Evidence Integrity
- Linux Forensic Analysis