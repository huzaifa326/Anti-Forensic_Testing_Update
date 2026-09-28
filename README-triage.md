# Zero-Footprint Live Triage Field Manual

CyberForensX offers a standalone, **Zero-Footprint USB Triage Agent** to collect forensic evidence on suspect endpoints without modifying disk state or installing dependencies.

## 1. Preparing the USB Toolkit

The triage agent must be pre-compiled on the secure forensic workstation.

1. Mount your blank USB drive (e.g. to `/media/usb`).
2. Run the builder script:
   ```bash
   chmod +x build_usb_agent.sh
   ./build_usb_agent.sh
   ```
3. A standalone executable binary will be generated at `triage_agent/dist/cyberforensx-triage`.
4. Copy ONLY this binary to your USB drive:
   ```bash
   cp triage_agent/dist/cyberforensx-triage /media/usb/
   ```

*(Your USB now contains a fully portable triage engine!)*

## 2. Using the Agent on a Suspect Machine

When deploying strictly for evidence collection, do not boot from the disk or install any analysis tools on the target machine.

1. Insert the USB drive and mount it.
2. Navigate to the USB drive: `cd /path/to/usb/`
3. Run the agent using `sudo` to acquire privileged logs and network structures:
   ```bash
   sudo ./cyberforensx-triage --auto --case-id CASE-SUSPECT-001
   ```

*(This runs the completely headless version of the agent.)*

**Web GUI Mode**
If you wish to interact manually over localhost, just run:
```bash
sudo ./cyberforensx-triage
```
Then navigate to http://127.0.0.1:5000 inside the suspect environment's browser.

**Outputs:**
A new folder `CASE-SUSPECT-001_TIMESTAMP/` will be generated ON THE USB containing raw logs, history, volatile network data, and a `manifest.json` sealing SHA-256 integrity hashes for each acquired artifact.

## 3. Station Ingestion Pipeline

To analyze the acquired raw data natively in CyberForensX:

1. Bring the USB back to the main forensic workstation.
2. Start the main CyberForensX dashboard.
3. On the left panel under "New Investigation", locate the **Offline Triage Folder Path** input.
4. Input the folder path (e.g., `/media/username/USB/CASE-SUSPECT-001_202611...`) and click **Import Offline Case**.
5. The pipeline automatically recalculates hashes and triggers an anti-tamper check against the `manifest.json`. Data will be pushed to the core UNIFICATION, ANOMALY DETECTION, and THREAT INTEL mechanisms.
