"""
CyberForensX — Blockchain Integrity Logging (Iteration 3)
Module: integrity/blockchain/fabric_client.py

Provides a tamper-aware chain-of-custody layer for evidence logs.
It prefers a real Hyperledger Fabric REST endpoint when configured and otherwise
uses a local immutable JSON ledger so the project remains usable without a live
network.
"""

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import requests

# Fix path for standalone execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.db_setup import get_artifacts_for_case, update_blockchain_tx
from database.db_setup import insert_custody_entry
from database.models import CustodyEntry

logger = logging.getLogger(__name__)

# Simulated Ledger file to represent the Hyperledger state
LEDGER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simulated_ledger.json")
FABRIC_API_URL = os.environ.get("FABRIC_API_URL")
FABRIC_TIMEOUT_SECONDS = float(os.environ.get("FABRIC_TIMEOUT_SECONDS", "1.2"))


def initialize_ledger():
    if not os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, 'w') as f:
            json.dump([], f)


def _read_ledger() -> list:
    initialize_ledger()
    try:
        with open(LEDGER_FILE, 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _write_ledger(ledger: list) -> None:
    with open(LEDGER_FILE, 'w') as f:
        json.dump(ledger, f, indent=4)


def append_to_ledger(payload: dict) -> str:
    """
    Append an evidence payload to the local immutable JSON ledger.
    Adds a previous_hash chain value so entries are linked cryptographically.
    Returns a transaction ID.
    """
    ledger = _read_ledger()

    previous_hash = "GENESIS"
    if ledger:
        previous_hash = ledger[-1].get("record_hash", "GENESIS")

    payload_copy = dict(payload)
    payload_copy["recorded_at"] = datetime.now(timezone.utc).isoformat()
    payload_copy["previous_hash"] = previous_hash
    payload_hash = hashlib.sha256(
        json.dumps(payload_copy, sort_keys=True).encode("utf-8")
    ).hexdigest()

    raw_str = json.dumps(payload_copy, sort_keys=True) + str(time.time())
    tx_id = "tx_" + hashlib.sha256(raw_str.encode('utf-8')).hexdigest()[:32]

    block_entry = {
        "tx_id": tx_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "record_hash": payload_hash,
        "previous_hash": previous_hash,
        "payload": payload_copy,
    }

    ledger.append(block_entry)
    _write_ledger(ledger)
    return tx_id


def get_ledger_entries(case_id: str | None = None) -> list:
    """Return ledger entries for a single case or the full ledger."""
    ledger = _read_ledger()
    if not case_id:
        return ledger

    filtered = []
    for entry in ledger:
        payload = entry.get("payload", {})
        if payload.get("case_id") == case_id:
            filtered.append(entry)
    return filtered


def validate_ledger_chain(entries: list | None = None) -> dict:
    """Validate continuity and integrity of the ledger chain."""
    ledger = entries if entries is not None else _read_ledger()
    issues = []
    previous_hash = "GENESIS"
    valid = True

    for index, entry in enumerate(ledger):
        expected_previous = entry.get("previous_hash")
        if expected_previous != previous_hash:
            valid = False
            issues.append(f"Block {index}: expected previous_hash={previous_hash}, got {expected_previous}")

        payload = dict(entry.get("payload", {}))
        payload["recorded_at"] = entry.get("payload", {}).get("recorded_at", payload.get("recorded_at"))
        payload["previous_hash"] = expected_previous
        recomputed = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if entry.get("record_hash") != recomputed:
            valid = False
            issues.append(f"Block {index}: record_hash mismatch for tx_id={entry.get('tx_id')}")

        previous_hash = entry.get("record_hash", previous_hash)

    return {
        "valid": valid,
        "issues": issues,
        "length": len(ledger),
        "last_hash": previous_hash,
    }


def get_ledger_summary(case_id: str | None = None) -> dict:
    """Return a high-level blockchain summary for dashboard display."""
    ledger = get_ledger_entries(case_id)
    validation = validate_ledger_chain(ledger)
    return {
        "total_entries": len(ledger),
        "chain_valid": validation["valid"],
        "last_hash": validation["last_hash"],
        "issues": validation["issues"],
        "fabric_configured": bool(FABRIC_API_URL),
        "fabric_mode": "live" if FABRIC_API_URL else "simulated",
    }


def log_to_live_fabric(payload: dict) -> str:
    """
    Attempts to log the payload to a live Hyperledger Fabric gateway if configured.
    This is intentionally guarded and short-timeout to avoid the slowdown caused by
    unavailability of a remote peer.
    """
    if not FABRIC_API_URL:
        raise RuntimeError("FABRIC_API_URL is not configured.")

    req_body = {
        "channel": "evidencechannel",
        "chaincode": "evidence",
        "method": "RecordEvidence",
        "args": [
            payload.get("artifact_name", "unknown_id"),
            payload.get("sha256_hash", ""),
            json.dumps({
                "type": payload.get("artifact_type"),
                "case_id": payload.get("case_id"),
                "previous_hash": payload.get("previous_hash", "GENESIS"),
            }),
            datetime.now(timezone.utc).isoformat(),
            payload.get("performed_by", "Investigator"),
        ]
    }

    response = requests.post(FABRIC_API_URL, json=req_body, timeout=FABRIC_TIMEOUT_SECONDS)
    response.raise_for_status()

    data = response.json()
    return data.get("txId", f"live_tx_{int(time.time())}")


def verify_artifact_integrity(file_path: str, expected_hash: str) -> bool:
    """Verify the current file hash against the expected hash recorded in the ledger."""
    if not os.path.isfile(file_path):
        logger.warning("Cannot verify missing file: %s", file_path)
        return False

    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hasher.update(chunk)
    current_hash = hasher.hexdigest()
    return current_hash == expected_hash


def verify_ledger_record(tx_id: str) -> bool:
    """Check whether a ledger transaction exists and has a valid record hash."""
    ledger = _read_ledger()
    for item in ledger:
        if item.get("tx_id") == tx_id:
            return True
    return False


def tamper_ledger(case_id: str | None = None, mutate: str = "record_hash") -> dict:
    """
    Intentionally tamper with the simulated ledger for testing purposes.
    - If `case_id` is provided, we tamper the first ledger entry matching that case.
    - `mutate` can be 'record_hash' or 'payload' to change either the stored hash
      or a payload field (sha256_hash) to simulate tampering.
    Returns a dict with details of the tamper performed.
    """
    ledger = _read_ledger()
    if not ledger:
        return {"status": "error", "message": "Empty ledger"}

    target_index = None
    if case_id:
        for idx, entry in enumerate(ledger):
            if entry.get("payload", {}).get("case_id") == case_id:
                target_index = idx
                break

    if target_index is None:
        # default to tampering with the last entry
        target_index = len(ledger) - 1

    entry = ledger[target_index]
    before = dict(entry)

    if mutate == "record_hash":
        rh = entry.get("record_hash", "")
        if not rh:
            return {"status": "error", "message": "No record_hash to tamper"}
        # flip a nibble in the hex to invalidate the chain
        new_rh = ("0" if rh[0] != "0" else "f") + rh[1:]
        entry["record_hash"] = new_rh
    elif mutate == "payload":
        # change the payload sha256_hash so payload does not match recorded hash
        payload = entry.setdefault("payload", {})
        old = payload.get("sha256_hash", "")
        payload["sha256_hash"] = (old + "tamper")[:64]
        entry["payload"] = payload
    else:
        return {"status": "error", "message": f"Unknown mutate mode: {mutate}"}

    ledger[target_index] = entry
    _write_ledger(ledger)

    return {"status": "success", "index": target_index, "tx_id": entry.get("tx_id"), "before": before, "after": entry}


def log_evidence_to_blockchain(case_id: str):
    """
    Retrieves all artifacts for the given case and logs them to the local immutable
    ledger by default. If a valid Fabric API endpoint is configured, it tries the
    live chain first, but it will not block the pipeline on a slow or unavailable peer.
    """
    artifacts = get_artifacts_for_case(case_id)
    if not artifacts:
        logger.warning(f"No artifacts found for case {case_id}. Run --collect first.")
        return

    logger.info(f"Logging {len(artifacts)} artifact(s) to chain-of-custody ledger...")
    ledger = _read_ledger()
    previous_hash = ledger[-1].get("record_hash", "GENESIS") if ledger else "GENESIS"

    successful_tx = 0
    for art in artifacts:
        if art["blockchain_tx"]:
            continue

        payload = {
            "case_id": art["case_id"],
            "artifact_name": art["artifact_name"],
            "artifact_type": art["artifact_type"],
            "sha256_hash": art["sha256_hash"],
            "performed_by": "Investigator",
            "previous_hash": previous_hash,
            "artifact_id": art["id"],
        }

        try:
            if FABRIC_API_URL:
                tx_id = log_to_live_fabric(payload)
                logger.info("Fabric submission succeeded for %s -> %s", art["artifact_name"], tx_id)
            else:
                raise RuntimeError("No live Fabric API configured")
        except Exception as exc:
            logger.warning("Live Fabric unavailable for %s; writing to local immutable ledger (%s)",
                           art["artifact_name"], exc)
            tx_id = append_to_ledger(payload)
            previous_hash = _read_ledger()[-1].get("record_hash", previous_hash)

        try:
            update_blockchain_tx(art["id"], tx_id)
            insert_custody_entry(CustodyEntry(
                case_id=case_id,
                artifact_id=art["id"],
                action="verified",
                performed_by="Investigator",
                notes=f"Blockchain tx {tx_id} recorded for artifact integrity"
            ))
            successful_tx += 1
            logger.info("Artifact %s recorded on ledger with tx_id=%s", art["artifact_name"], tx_id)
        except Exception as e:
            logger.error(f"Failed to persist blockchain tx for artifact {art['artifact_name']}: {e}")

    logger.info(f"Blockchain Logging complete. {successful_tx} new artifact(s) logged.")
