"""
CyberForensX — Iteration 1 Tests
Module: tests/test_acquisition.py

Tests for the evidence acquisition module collectors.
Run with: python -m pytest tests/ -v
"""

import os
import sys
import tempfile
import shutil
import uuid
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_setup import init_db
from integrity.hashing import compute_sha256, hash_artifact, verify_artifact


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def tmp_db(tmp_path_factory):
    """Initialise a temp DB for the test session."""
    import config.settings as cfg
    cfg.DATABASE_PATH = str(tmp_path_factory.mktemp("db") / "test.db")
    init_db()
    return cfg.DATABASE_PATH


@pytest.fixture()
def sample_file(tmp_path):
    """Create a temporary text file with known content."""
    f = tmp_path / "sample_artifact.txt"
    f.write_text("CyberForensX test artifact content.\nLine 2.\n")
    return str(f)


@pytest.fixture()
def bash_history_file(tmp_path):
    """Create a fake .bash_history file."""
    f = tmp_path / ".bash_history"
    content = (
        "#1709900000\n"
        "ls -la\n"
        "cat /etc/passwd\n"
        "sudo rm -rf /tmp/evil\n"
        "history\n"
    )
    f.write_text(content)
    return str(f)


# ─────────────────────────────────────────────────────────────────────────────
# Hashing Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHashing:
    def test_compute_sha256_returns_64_char_hex(self, sample_file):
        digest = compute_sha256(sample_file)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_compute_sha256_deterministic(self, sample_file):
        """Same file must always produce the same hash."""
        assert compute_sha256(sample_file) == compute_sha256(sample_file)

    def test_hash_artifact_returns_correct_keys(self, sample_file):
        record = hash_artifact(sample_file)
        for key in ("file_path", "filename", "sha256", "md5", "size_bytes", "hashed_at"):
            assert key in record, f"Missing key: {key}"

    def test_verify_artifact_pass(self, sample_file):
        digest = compute_sha256(sample_file)
        assert verify_artifact(sample_file, digest) is True

    def test_verify_artifact_fail_after_modification(self, sample_file):
        digest = compute_sha256(sample_file)
        # Tamper with file
        with open(sample_file, "a") as f:
            f.write("TAMPERED\n")
        assert verify_artifact(sample_file, digest) is False

    def test_hash_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            compute_sha256("/nonexistent/path/file.txt")


# ─────────────────────────────────────────────────────────────────────────────
# Bash History Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBashHistoryParser:
    def test_parse_returns_list(self, bash_history_file):
        from acquisition.bash_history_collector import parse_bash_history
        entries = parse_bash_history(bash_history_file)
        assert isinstance(entries, list)

    def test_parse_extracts_commands(self, bash_history_file):
        from acquisition.bash_history_collector import parse_bash_history
        entries = parse_bash_history(bash_history_file)
        commands = [e["command"] for e in entries]
        assert "ls -la" in commands
        assert "cat /etc/passwd" in commands
        assert "sudo rm -rf /tmp/evil" in commands

    def test_parse_extracts_timestamp(self, bash_history_file):
        from acquisition.bash_history_collector import parse_bash_history
        entries = parse_bash_history(bash_history_file)
        # First command should have a timestamp parsed from #1709900000
        first = entries[0]
        assert first["timestamp"] is not None
        assert "T" in first["timestamp"]   # ISO-8601 format

    def test_parse_raises_for_missing_file(self):
        from acquisition.bash_history_collector import parse_bash_history
        with pytest.raises(FileNotFoundError):
            parse_bash_history("/nonexistent/.bash_history")


# ─────────────────────────────────────────────────────────────────────────────
# Database CRUD Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabase:
    def test_insert_and_retrieve_case(self, tmp_db):
        from database.db_setup import insert_case, get_case
        from database.models import Case
        case_id = f"CASE-TEST-{uuid.uuid4().hex[:8].upper()}"
        case = Case(case_id, "Test Investigation", "Hamna Ejaz")
        insert_case(case)
        row = get_case(case_id)
        assert row is not None
        assert row["case_id"] == case_id
        assert row["investigator"] == "Hamna Ejaz"

    def test_insert_and_retrieve_artifact(self, tmp_db, sample_file):
        from database.db_setup import insert_artifact, get_artifacts_for_case
        from database.models import Artifact
        artifact = Artifact(
            case_id       = "CASE-TEST-001",
            artifact_name = "sample_artifact.txt",
            artifact_type = "syslog",
            file_path     = sample_file,
            sha256_hash   = compute_sha256(sample_file)
        )
        artifact_id = insert_artifact(artifact)
        assert artifact_id > 0
        rows = get_artifacts_for_case("CASE-TEST-001")
        names = [r["artifact_name"] for r in rows]
        assert "sample_artifact.txt" in names

    def test_insert_alert(self, tmp_db):
        from database.db_setup import insert_alert, get_alerts_for_case
        from database.models import Alert
        alert = Alert(
            case_id     = "CASE-TEST-001",
            alert_type  = "ml_anomaly",
            description = "Unusual sudo activity at 03:00 UTC",
            severity    = "high"
        )
        alert_id = insert_alert(alert)
        assert alert_id > 0
        rows = get_alerts_for_case("CASE-TEST-001")
        assert any(r["alert_type"] == "ml_anomaly" for r in rows)

    def test_custody_log(self, tmp_db, sample_file):
        from database.db_setup import insert_artifact, insert_custody_entry, get_custody_log
        from database.models import Artifact, CustodyEntry
        artifact = Artifact("CASE-TEST-001", "custody_test.txt", "syslog",
                            sample_file, compute_sha256(sample_file))
        artifact_id = insert_artifact(artifact)
        entry = CustodyEntry("CASE-TEST-001", artifact_id, "analyzed", "Hamna Ejaz")
        insert_custody_entry(entry)
        log = get_custody_log("CASE-TEST-001")
        actions = [r["action"] for r in log]
        assert "collected" in actions or "analyzed" in actions
