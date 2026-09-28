import os
import json
import logging
from integrity.hashing import verify_artifact
from database.db_setup import insert_case, insert_artifact, get_case, insert_case_activity, insert_custody_entry
from database.models import Case, Artifact, CaseActivityEntry, CustodyEntry
import re

logger = logging.getLogger(__name__)

def ingest_usb_case(case_dir: str, custom_case_id: str = None) -> dict:
    """
    Ingests an offline USB case folder.
    Reads manifest.json, validates hashes, and returns case artifacts.
    Supports keeping the original case ID or overriding with custom_case_id.
    """
    manifest_path = os.path.join(case_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {"success": False, "error": f"manifest.json missing in {case_dir}"}

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    # 1. Determine Case ID based on user choice / manifest / folder structure
    if custom_case_id and str(custom_case_id).strip():
        case_id = str(custom_case_id).strip()
    elif manifest.get("case_id"):
        case_id = manifest.get("case_id")
    elif manifest.get("original_case_id"):
        case_id = manifest.get("original_case_id")
    else:
        # Extract Base CASE ID (e.g. CASE-1000 from CASE_CASE-1000_20260817...)
        dir_name = os.path.basename(os.path.normpath(case_dir))
        match = re.search(r'CASE_(CASE-[A-Za-z0-9\-_]+)_', dir_name)
        if match:
            case_id = match.group(1)
        else:
            # Fallback: extract between CASE_ and timestamp _YYYYMMDD
            match_generic = re.search(r'^CASE_(.+?)_\d{8}_\d{6}$', dir_name)
            if match_generic:
                case_id = match_generic.group(1)
            else:
                case_id = dir_name if dir_name.startswith("CASE-") else "CASE-OFFLINE-001"

    case_title = manifest.get("title") or "Offline Triage Import"
    case_investigator = manifest.get("investigator") or "USB Agent"

    results = []
    # Verify all artifacts
    for artifact in manifest.get("artifacts", []):
        file_path = artifact.get("file_path")
        expected_hash = artifact.get("sha256")
        
        basename = os.path.basename(file_path)
        local_path = os.path.join(case_dir, basename)

        if not os.path.isfile(local_path):
            results.append({"filename": basename, "status": "missing"})
            continue

        if verify_artifact(local_path, expected_hash):
            results.append({"filename": basename, "status": "verified (OK)"})
            
            # Ensure the case exists in the database
            if not get_case(case_id):
                insert_case(Case(case_id, case_title, case_investigator))
                insert_case_activity(CaseActivityEntry(case_id, "opened", case_investigator))
            
            # Insert into database
            art = Artifact(
                case_id=case_id, 
                artifact_name=basename,
                artifact_type="offline_evidence",
                file_path=local_path,
                sha256_hash=expected_hash,
                notes="Ingested from Zero-Footprint USB Agent"
            )
            art_id = insert_artifact(art)
            
            # Insert Custody Entry
            entry = CustodyEntry(
                case_id=case_id,
                artifact_id=art_id,
                action="collected",
                performed_by=case_investigator,
                notes="Artifact ingested via USB Triage Agent"
            )
            insert_custody_entry(entry)
        else:
            results.append({"filename": basename, "status": "integrity failure (TAMPERED)"})

    return {
        "success": True, 
        "case_id": case_id, 
        "artifacts": results, 
        "manifest_timestamp": manifest.get("generated_at")
    }

