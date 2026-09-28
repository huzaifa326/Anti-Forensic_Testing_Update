**CyberForensX ![ref1]**

Project Team 

Hamna Ejaz  22I-1645 Huzaifa Afzal  22I-1592 Muhammad Huzaifa  22I-1627 

Session 2022-2027 

Supervised by 

Mr. Mehmood Ul Hassan 

![](Aspose.Words.eb831a2a-9224-4f9f-a5d6-0c14aaa3a727.002.png)

**Department of Cyber Security** 

**National University of Computer and Emerging Sciences Islamabad, Pakistan** 

**January, 2027** 

**Contents ![ref1]**

**1  Introduction** [` `**1** ](#_page3_x75.00_y96.04)

1. Problem Statement ..............................................................................................[ 1 ](#_page3_x75.00_y518.04)
1. Motivation ...........................................................................................................[ 2 ](#_page5_x75.00_y89.04)
1. Problem Solution ................................................................................................[. 3 ](#_page5_x75.00_y548.04)
1. Stake Holders ......................................................................................................[ 4 ](#_page6_x75.00_y488.04)

**2  Project Description**  **[**5** ](#_page7_x75.00_y96.04)**

1. Scope ...................................................................................................................[ 5 ](#_page7_x75.00_y235.04)
1. Modules...............................................................................................................[ 6 ](#_page8_x75.00_y292.04)
1. Evidence Acquisition Module ................................................................[ 6 ](#_page8_x75.00_y349.04)
1. Forensic Analysis & Intelligence Module ..............................................[ 6 ](#_page8_x75.00_y639.04)
1. Integrity & Correlation Module ..............................................................[ 7 ](#_page9_x75.00_y274.04)
1. Reporting & Visualization Module .........................................................[ 7 ](#_page9_x75.00_y485.04)
3. Tools and Technologies .......................................................................................[ 7 ](#_page9_x75.00_y672.04)
4. Work Division .....................................................................................................[ 8 ](#_page10_x75.00_y262.04)
4. TimeLine ............................................................................................................. 9 

**References**  **12** 

2 

**List of Tables ![ref1]**

1. Comparison of CyberForensX vs. Existing Tools...............................................[ 6 ](#_page8_x204.00_y113.04)
1. Team Responsibilities..........................................................................................[ 8 ](#_page10_x267.00_y318.04)
1. Project Timeline ................................................................................................[.. 9 ](#_page11_x281.00_y129.04)

0 

<a name="_page3_x75.00_y96.04"></a>**Chapter 1 ![ref1]Introduction** 

The purpose of this project proposal document is to outline the development of “**CyberForensX**,” an **AI-Assisted Automated Digital Forensics and Incident Reconstruction Platform** designed to revolutionize incident response. The system is specifically engineered to **au- tomate crime investigation** on PCs and laptops by collecting, analyzing, and reporting evidence with high integrity. The background of this system is rooted in the increasing complexity of modern cyber threats and the limitations of current forensic methodologies 

[(1)](#_page12_x75.00_y165.04): 

- **Manual Processes:** Traditional investigations rely on **manual processes** that strug- gle to keep pace with overwhelming data volumes [(2)](#_page12_x75.00_y198.04). 
- **Fragmented Tools:** Investigators currently use **disparate tools** for disk, memory, and log analysis, leading to fragmented workflows. 
- **Modernization Needs:**  CyberForensX aims to modernize this outdated tooling by integrating **artificial intelligence** and **blockchain technology** to ensure faster, smarter, and more trustworthy investigations ([3)](#_page12_x75.00_y258.04). 
1. **Problem<a name="_page3_x75.00_y518.04"></a> Statement** 

The domain of digital forensics is currently hindered by significant inefficiencies and lim- itations in existing open-source tools [(1). ](#_page12_x75.00_y165.04)While tools like **Autopsy**, **KAPE**, and **Truxton** exist, they present specific gaps that this project aims to solve: 

- **limitations of Existing Tools:** 
- **Autopsy:** While powerful, it is resource-intensive, slow to process large datasets,high resource consumption, heavily reliant on manual review of artifacts, and a lack 

  of advanced AI/blockchain analysis tools

- **KAPE (Kroll Artifact Parser and Extractor):** Primarily designed for Win- ![ref1]dows environments. While it is highly configurable and can collect files from Linux systems, its native, pre-configured modules and deep, automated pars- ing capabilities (such as EXT4 inode analysis) are heavily focused on Win- dows artifacts like registry hives, event logs, and shimcache 
- **Truxton (Community):** It is an automated digital forensics platform designed to consolidate, analyze, and visualize data from multiple sources (computers, mobile devices, drones) to reduce backlog.  Despite its strengths as a force multiplier for large data sets, its limitations often relate to its automation- heavy nature, high cost, and dependence on initial ingestion. 
- **Volatility:** Volatility is a powerful memory forensics framework, but its lim- itations include high, time-consuming data-intensity, inability to determine process normalcy, and potential for false positives. It requires precise„ some- times difficult-to-acquire memory snapshots, often lagging behind the latest operating system updates. 
- **Sleuth Kit:** The Sleuth Kit (TSK) is a powerful open-source forensic tool, but it faces limitations, including lack of support for modern pooled storage file systems (e.g., Zettabyte File System ZFS), limited capability to analyze data directly from live, mounted systems, and reliance on command-line skills for advanced tasks 
- **Manual Inefficiency & Data Overload:** Investigators face “**data overload**” and manual inefficiencies, making it nearly impossible to sift through logs and artifacts to find relevant evidence in a reasonable timeframe. 
- **Format Friction & Integration Gaps:** Current tooling suffers from “**format fric- tion**,” as investigators must manually convert data between separate tools for mem- ory (Volatility) and disk analysis, preventing unified analysis. 
- **Isolated Analysis:** There is a lack of correlation between devices, leading to “**isolated analysis**” where events cannot be linked across different endpoints to reconstruct a full **attack path**. 
- **Evidence Integrity Issues:** Current reliance on paper logs or basic databases makes the **chain of custody** vulnerable to tampering ([3)](#_page12_x75.00_y258.04). 
2. **Motivation<a name="_page5_x75.00_y89.04"></a> ![ref1]**

The  motivation  behind  developing  CyberForensX  stems  from  the  critical  need  to address  the  limitations  of  current  forensic  methodologies  and  the  escalating sophistication of cyber-attacks. The key motivators include: 

- **Addressing Manual Inefficiencies:** To move away from slow, error-prone manual acquisition methods and **automate the collection** of evidence from disks, memory, and logs[ (2)](#_page12_x75.00_y198.04). 
- **Handling Data Overload:**  To develop a system capable of processing and ana- lyzing **overwhelming volumes** of forensic data that are unmanageable for human analysts alone. 
- **Reducing Incident Response Time:** To minimize the delay between incident de- tection and resolution, ensuring **faster mitigation** of security threats. 
- **Enhancing Evidence Integrity:** To replace vulnerable paper trails with **immutable, blockchain-verified audit trails** that ensure the chain of custody is tamper-proof [(3)](#_page12_x75.00_y258.04). 
- **Reconstructing Attack Paths:** To bridge the gap between isolated data points by using **multi-device correlation engines** that can reconstruct comprehensive time- lines of an attack. 
- **Modernizing Forensic Tooling:** To replace outdated, fragmented tools with a **uni- fied interoperable platform** that integrates advanced detection capabilities. 
3. **Problem<a name="_page5_x75.00_y548.04"></a> Solution** 

The proposed solution, **CyberForensX**, is a comprehensive **AI-integrated platform** that automates the digital forensics lifecycle, specifically targeting **Linux endpoints**. To ad- dress the identified problems, the solution implements the following core capabilities: 

- **Automated Acquisition:** The software utilizes **Python scripts** wrapping tools like **LiME** and **dd** to automate the acquisition of host-based data, including disk meta- data, logs, and volatile memory ([2)](#_page12_x75.00_y198.04). 
- **Intelligent Analysis:** Unlike traditional tools, it employs **Machine Learning (ML)** to intelligently prioritize artifacts and detect **anomalies** within system logs that 

  would otherwise go unnoticed. ![ref1]

- **Blockchain Integrity:** A core component is the integration of **Hyperledger Fab- ric**, which provides a **blockchain-based chain of custody** to guarantee that evi- dence remains immutable and legally admissible ([3)](#_page12_x75.00_y258.04). 
- **Incident Reconstruction:** The system features a **multi-device correlation engine** that stitches together isolated events into a coherent timeline. 
- **Unified Reporting:** The final output is streamlined through an **automated report- ing engine** that generates multi-stakeholder documents for both technical and ex- ecutive audiences. 

**Technically Challenging Features:** This project involves significant technical depth and effort in the following areas: 

- **Unification Pipeline Engineering:**  Designing a feature engineering pipeline to map disparate log formats (Syslog vs. Auth.log) into a normalized vector space for ML processing. 
- **Anti-Forensics Detection:** Developing custom algorithms to detect sophisticated evasion tactics like **Timestomping** (manipulating file metadata) and identifying **Rootkits** that hide processes from standard tools ([4)](#_page12_x75.00_y317.04). 
- **Blockchain Integration:**  Implementing a lightweight consensus mechanism on endpoints to ensure evidence hashing does not significantly impact system perfor- mance. 
4. **Stake<a name="_page6_x75.00_y488.04"></a> Holders** 

The key stakeholders who will benefit from or utilize this system include: 

- **Security Teams:** Operational teams responsible for monitoring and defending or- ganizational infrastructure. 
- **Forensic Investigators:**  Professionals who require **automated tools** to conduct deep-dive analyses of compromised systems. 
- **Executive Leadership:** Management requiring **high-level, automated reports** to understand the impact of security incidents ([5)](#_page12_x75.00_y377.04). 
- **Legal Auditors/Compliance Officers:** Stakeholders who rely on the **blockchain- verified chain of custody** to ensure evidence is admissible. 

<a name="_page7_x75.00_y96.04"></a>**Chapter 2 ![ref1]**

**Project Description** 

1. **Scope<a name="_page7_x75.00_y235.04"></a>** 

The scope of “CyberForensX” is strictly defined as a host-based digital forensics platform tailored specifically for Linux environments. The project encompasses the following key boundaries and functionalities: 

- **Target Environment:** The system focuses on Linux laptops, desktops, and PCs. 
- **Automated Acquisition (The Imager Tool):** 

  The system replaces manual "drag-and-drop" copying with a Python-based **Imager Tool**. This tool programmatically executes commands to fetch specific artifacts [(2)](#_page12_x75.00_y198.04): 

- **Volatile Data:** RAM dumps via LiME and active network connections (Net- stat). 
- **Non-Volatile Data:** Syslog, Auth.log, Bash History, and EXT4 Inode meta- data. 
- **Advanced Analysis:** The solution parses raw data into JSON and utilizes Machine Learning (Isolation Forest) to detect anomalies in logs. 
- **Anti-Forensics Detection:** The scope includes detecting evasion tactics such as timestomping, hidden files (Dotfiles), and rootkits ([4)](#_page12_x75.00_y317.04). 
- **Evidence Integrity:** A Hyperledger Fabric blockchain module is included to en- sure an immutable chain of custody for all collected artifacts. 
- **Correlation & Reporting:** The system reconstructs attack timelines across multi- ple devices and generates automated reports. 

**Novelty & Comparison with Existing Tools: ![ref1]**

Table[ 2.1 ](#_page8_x204.00_y113.04)highlights how CyberForensX differentiates itself from standard tools. 

Table 2.1:<a name="_page8_x204.00_y113.04"></a> Comparison of CyberForensX vs. Existing Tools 

|**Feature** |**Autopsy** |**KAPE** |**CyberForensX** |
| - | - | - | - |
|**Primary OS** |Windows/Linux |Windows |**Linux Specialized** |
|**Automation** |<p>Partial  (Ingest </p><p>Modules) </p>|Scripted Targets |**Fully  Automated Pipeline** |
|**Integrity** |Hash Calculation |Hash Calculation |**Blockchain  Im- mutable Ledger** |
|**Analysis Method** |Signature Based |Artifact Parsing |<p>**AI/ML  Anomaly** </p><p>**Detection** </p>|

2. **Modules<a name="_page8_x75.00_y292.04"></a>** 

The proposed project is divided into the following core modules, distinguishing between <a name="_page8_x75.00_y349.04"></a>data collection, analysis, and presentation layers. 

1. **Evidence Acquisition Module** 

This module allows the investigator to run automated scripts on the target Linux machine to capture both volatile and non-volatile data. 

1. **Automated Disk Collection:** Executes Python/Shell scripts to harvest disk arti- facts, including Bash history and system configuration files. 
1. **Memory Forensics:** Utilizes LiME to create full memory dumps for analyzing running processes and active connections. 
1. **Log Extraction:** Automatically copies and aggregates critical Linux logs (Syslog, Auth.log) for downstream analysis. 
2. **Forensic<a name="_page8_x75.00_y639.04"></a> Analysis & Intelligence Module** 

This module processes the raw data, applying AI and rule-based logic to uncover threats. 

1. **Unification Pipeline (Feature Engineering):** 

   To address format friction, a unification pipeline is implemented.  Raw text logs ![ref1](Syslog) and structured logs (Auth.log) are parsed and mapped to a **common fea- ture set** (e.g., Timestamp, User\_ID, Command\_Type, Origin\_IP). This derived fea- ture set allows the ML model to process heterogeneous data sources uniformly. 

2. **Anomaly Detection:** Deploys Machine Learning models (Isolation Forest) on the unified features to flag unusual user activity. 
2. **Anti-Forensics Detection:** Implements algorithms to detect hidden data (LUKS, Dotfiles) and identify fake timestamps (Timestomping) ([4)](#_page12_x75.00_y317.04). 
2. **Threat Intelligence Integration:** Connects with APIs like VirusTotal and MISP to automatically check file hashes against known malware databases [(5)](#_page12_x75.00_y377.04). 
3. **Integrity<a name="_page9_x75.00_y274.04"></a> & Correlation Module** 

This backend module ensures data trustworthiness and reconstructs the sequence of events. 

1. **Blockchain Logging:** Records the checksums and metadata of collected evidence onto a Hyperledger Fabric network to create an immutable audit trail[ (3)](#_page12_x75.00_y258.04). 
1. **Timeline Reconstruction:** Merges logs, history, and file events into a unified time- line to visualize the attack path. 
1. **Multi-Device Correlation:** Links events across different devices (e.g., USB usage vs. file copies) to reconstruct comprehensive incident scenarios. 
4. **Reporting<a name="_page9_x75.00_y485.04"></a> & Visualization Module** 

This module serves as the frontend interface for investigators to view results and generate documentation. 

1. **Interactive Dashboard:** Provides a web-based UI to visualize the security timeline and view alerts generated by the analysis engine. 
1. **Automated Reporting:** Generates PDF documents using Jinja2 templates, tailored for both technical and executive audiences. 
3. **Tools<a name="_page9_x75.00_y672.04"></a> and Technologies** 

Provide a detail of the tools and technologies required for this project. 

- **Languages & Frameworks:** Python (Core logic), Shell Scripting (Automation). ![ref1]
- **Data Acquisition:** LiME (Linux Memory Extractor), dd (Disk Imaging), Volatility (Memory Analysis). 
- **Analysis & AI:** scikit-learn (ML models), YARA (Pattern matching), Custom Parsers (Log analysis). 
- **Threat Intelligence:** VirusTotal API, MISP, MITRE ATT&CK mapping. 
- **Blockchain:** Hyperledger Fabric (Chain of Custody/Evidence Integrity). 
- **Reporting:** Python ReportLab, Jinja2 (Templating). 
4. **Work<a name="_page10_x75.00_y262.04"></a> Division** 

Table 2.2:<a name="_page10_x267.00_y318.04"></a> Team Responsibilities 

|**Name** |**Registration**|`  `**Responsibility / Module / Feature** |
| - | - | - |
|Muhammad Huzaifa |22i-1627 |<p>- Backend Database Setup </p><p>- System Log Collection Scripts </p><p>- Timeline Logic </p><p>- Timestomping Detector </p><p>- LUKS Extractor </p>|
|Huzaifa Afzal |22i-1592 |<p>- Disk Artifact Scripts </p><p>- VirusTotal API Integration </p><p>- Blockchain Network Setup </p><p>- USB Event Linking </p><p>- PDF Report Generation </p>|
|Hamna Ejaz |22i-1645 |<p>- UI Skeleton </p><p>- Browser History Scripts </p><p>- JSON Log Parsing </p><p>- ML Anomaly Detection Model </p><p>- Interactive Timeline UI </p>|
5. **TimeLine ![](Aspose.Words.eb831a2a-9224-4f9f-a5d6-0c14aaa3a727.003.png)**

Table 2.3: <a name="_page11_x281.00_y129.04"></a>Project Timeline 

|**Iteration#** |**Time frame** |**Tasks/Modules** |
| - | - | - |
|01 |4 Weeks |<p>- Foundation & Environment Setup </p><p>- Basic Evidence Collectors (Logs, History) </p><p>- Database Setup </p>|
|02 |7 Weeks |<p>- Artifact Parsing (JSON) </p><p>- Threat Intel Integration </p><p>- Basic Timeline Sorting </p>|
|03 |2 Months |<p>- ML Anomaly Detection </p><p>- Anti-Forensics (Timestomping, Rootkits) </p><p>- Blockchain Logging </p>|
|04 |2 Months |<p>- Interactive Dashboard </p><p>- Automated PDF Reports </p><p>- Validation against datasets </p>|

**Bibliography ![ref1]**

1. G.<a name="_page12_x75.00_y165.04"></a> Johansen, *Digital Forensics and Incident Response: Incident Response Tools and Techniques for Effective Cyber Threat Response*. Packt Publishing, 3rd ed., 2022. 
1. EC-Council,<a name="_page12_x75.00_y198.04"></a> “Data Acquisition in Digital Forensics.” [https://www.eccouncil.org/cybersecurity-exchange/computer-forensics/data-acquis ](https://www.eccouncil.org/cybersecurity-exchange/computer-forensics/data-acquisition-digital-forensics/)Accessed: 2024.
1. RecordsKeeper,<a name="_page12_x75.00_y258.04"></a> “Immutable Audit Trails.” [https://www.recordskeeper.ai/immutable-audit-trails/.](https://www.recordskeeper.ai/immutable-audit-trails/) Accessed: 2024.
1. ResearchGate,<a name="_page12_x75.00_y317.04"></a> “Analysis of steganographic on digital evidence using general computer forensic investigation model framework,” *ResearchGate Publication*, 2020.  [https://www.researchgate.net/publication/346527069.](https://www.researchgate.net/publication/346527069) 
1. Palo<a name="_page12_x75.00_y377.04"></a> Alto Networks, “Indicators of Compromise (IoCs).” [https://www.paloaltonetworks.com/cyberpedia/indicators-of-compromise.](https://www.paloaltonetworks.com/cyberpedia/indicators-of-compromise) Accessed: 2024
10 

[ref1]: Aspose.Words.eb831a2a-9224-4f9f-a5d6-0c14aaa3a727.001.png
