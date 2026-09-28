import pytest
import os
import sys
import json
import uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrity.blockchain.fabric_client import log_evidence_to_blockchain, LEDGER_FILE
from database.db_setup import init_db, insert_case, insert_artifact, get_artifacts_for_case
from database.models import Case, Artifact

def test_blockchain_logging():
    init_db()
    
    uid = "CASE-" + uuid.uuid4().hex
    
    # Insert a dummy case
    case = Case(uid, "BC Test", "Tester")
    insert_case(case)
    
    # Insert dummy artifact
    art = Artifact(uid, "test_file.txt", "disk_image", "/fake/path", "fakehash123")
    insert_artifact(art)
    
    # Clean up ledger if exists
    if os.path.exists(LEDGER_FILE):
        os.remove(LEDGER_FILE)
        
    log_evidence_to_blockchain(uid)
    
    # Verify artifact updated in DB
    updated_arts = get_artifacts_for_case(uid)
    assert len(updated_arts) == 1
    assert updated_arts[0]["blockchain_tx"] is not None
    assert updated_arts[0]["blockchain_tx"].startswith("tx_")
    
    # Verify ledger file created
    assert os.path.exists(LEDGER_FILE)
    
    with open(LEDGER_FILE, 'r') as f:
        ledger = json.load(f)
        
    assert len(ledger) == 1
    assert ledger[0]["tx_id"] == updated_arts[0]["blockchain_tx"]
    assert ledger[0]["payload"]["sha256_hash"] == "fakehash123"
