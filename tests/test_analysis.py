"""
CyberForensX — Iteration 2 Tests
Module: tests/test_analysis.py

Tests for the Iteration 2 analysis pipeline:
  - Log Parser (syslog, auth.log)
  - Feature Engineer (unification pipeline)
  - VirusTotal Client (mocked HTTP)
  - MISP Client (mocked)
  - Timeline Builder (merge + sort)

Run with: python -m pytest tests/test_analysis.py -v
"""

import os
import sys
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.pipeline.log_parser import (
    parse_syslog, parse_authlog, parse_all_logs,
    save_parsed_logs, _parse_syslog_timestamp,
)
from analysis.pipeline.feature_engineer import (
    unify_logs, save_unified_logs,
    _unify_syslog_entry, _unify_authlog_entry,
)
from analysis.threat_intel.virustotal_client import (
    check_hash, check_file, compute_file_sha256,
    save_threat_intel_results,
)
from integrity.timeline_builder import (
    build_timeline, normalize_timestamp, save_timeline,
    build_timeline_from_processed,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def syslog_file(tmp_path):
    """Create a realistic syslog file."""
    content = (
        "Apr  7 14:23:01 myhost sshd[1234]: Accepted password for root from 192.168.1.100 port 22\n"
        "Apr  7 14:23:05 myhost CRON[5678]: (root) CMD (test -x /usr/sbin/anacron)\n"
        "Apr  7 14:24:00 myhost kernel: [12345.678] eth0: link up\n"
        "THIS IS A BAD LINE WITH NO FORMAT\n"
        "Apr  7 14:25:30 myhost sudo: hamna : TTY=pts/0 ; PWD=/home/hamna ; COMMAND=/bin/ls\n"
    )
    f = tmp_path / "syslog_test"
    f.write_text(content)
    return str(f)


@pytest.fixture()
def authlog_file(tmp_path):
    """Create a realistic auth.log file."""
    content = (
        "Apr  7 10:00:01 server sshd[2001]: Failed password for admin from 10.0.0.5 port 443\n"
        "Apr  7 10:00:15 server sshd[2001]: Accepted password for hamna from 192.168.1.50 port 22\n"
        "Apr  7 10:01:00 server sudo[2050]: hamna : session opened for user root\n"
        "Apr  7 10:02:00 server sshd[2100]: Invalid user test from 10.0.0.99 port 9999\n"
    )
    f = tmp_path / "auth.log_test"
    f.write_text(content)
    return str(f)


@pytest.fixture()
def mixed_log_dir(tmp_path, syslog_file, authlog_file):
    """Create a directory with both log types."""
    import shutil
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(syslog_file, str(log_dir / "syslog_20260407"))
    shutil.copy(authlog_file, str(log_dir / "auth.log_20260407"))
    return str(log_dir)


@pytest.fixture()
def sample_artifact(tmp_path):
    """Create a sample file for hash testing."""
    f = tmp_path / "malware_sample.bin"
    f.write_bytes(b"This is a test binary file for VT scanning.")
    return str(f)


# ─────────────────────────────────────────────────────────────────────────────
# Log Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLogParser:
    def test_parse_syslog_timestamp(self):
        result = _parse_syslog_timestamp("Apr  7 14:23:01", 2026)
        assert "2026-04-07" in result
        assert "14:23:01" in result

    def test_parse_syslog_returns_list(self, syslog_file):
        records = parse_syslog(syslog_file, reference_year=2026)
        assert isinstance(records, list)
        assert len(records) >= 3  # 4 valid lines, 1 malformed

    def test_parse_syslog_fields(self, syslog_file):
        records = parse_syslog(syslog_file, reference_year=2026)
        first = records[0]
        assert "timestamp" in first
        assert "hostname" in first
        assert "process" in first
        assert "message" in first
        assert "source" in first
        assert first["source"] == "syslog"
        assert first["hostname"] == "myhost"

    def test_parse_syslog_extracts_pid(self, syslog_file):
        records = parse_syslog(syslog_file, reference_year=2026)
        first = records[0]
        assert first["pid"] == "1234"

    def test_parse_syslog_skips_malformed(self, syslog_file):
        records = parse_syslog(syslog_file, reference_year=2026)
        messages = [r["message"] for r in records]
        assert not any("BAD LINE" in m for m in messages)

    def test_parse_syslog_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_syslog("/nonexistent/syslog")

    def test_parse_authlog_returns_list(self, authlog_file):
        records = parse_authlog(authlog_file, reference_year=2026)
        assert isinstance(records, list)
        assert len(records) == 4

    def test_parse_authlog_extracts_user(self, authlog_file):
        records = parse_authlog(authlog_file, reference_year=2026)
        users = [r["user"] for r in records]
        assert "admin" in users
        assert "hamna" in users

    def test_parse_authlog_extracts_ip(self, authlog_file):
        records = parse_authlog(authlog_file, reference_year=2026)
        ips = [r["ip"] for r in records]
        assert "10.0.0.5" in ips
        assert "192.168.1.50" in ips

    def test_parse_authlog_extracts_event_type(self, authlog_file):
        records = parse_authlog(authlog_file, reference_year=2026)
        event_types = [r["event_type"] for r in records]
        assert "failed" in event_types
        assert "accepted" in event_types

    def test_parse_authlog_source_field(self, authlog_file):
        records = parse_authlog(authlog_file, reference_year=2026)
        assert all(r["source"] == "auth_log" for r in records)

    def test_parse_all_logs(self, mixed_log_dir):
        result = parse_all_logs(mixed_log_dir, reference_year=2026)
        assert "syslog" in result
        assert "authlog" in result
        assert len(result["syslog"]) >= 3
        assert len(result["authlog"]) == 4

    def test_save_parsed_logs(self, mixed_log_dir, tmp_path):
        result = parse_all_logs(mixed_log_dir, reference_year=2026)
        output = str(tmp_path / "parsed_output.json")
        save_parsed_logs(result, output)
        assert os.path.isfile(output)
        with open(output) as f:
            data = json.load(f)
        assert "syslog" in data
        assert "authlog" in data
        assert "generated_at" in data


# ─────────────────────────────────────────────────────────────────────────────
# Feature Engineer Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureEngineer:
    def test_unify_syslog_entry(self):
        entry = {
            "timestamp": "2026-04-07T14:23:01+00:00",
            "hostname": "myhost",
            "process": "sshd",
            "message": "test message",
        }
        result = _unify_syslog_entry(entry)
        assert result["event_type"] == "system"
        assert result["source"] == "syslog"
        assert result["user_id"] == "system"
        assert result["timestamp"] == entry["timestamp"]

    def test_unify_authlog_entry(self):
        entry = {
            "timestamp": "2026-04-07T10:00:01+00:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "failed",
            "message": "Failed password for admin",
        }
        result = _unify_authlog_entry(entry)
        assert result["event_type"] == "auth"
        assert result["source"] == "auth_log"
        assert result["user_id"] == "admin"
        assert result["origin_ip"] == "10.0.0.5"

    def test_unify_logs_combined(self, syslog_file, authlog_file):
        syslog_records = parse_syslog(syslog_file, reference_year=2026)
        auth_records = parse_authlog(authlog_file, reference_year=2026)
        unified = unify_logs(
            syslog_entries=syslog_records,
            authlog_entries=auth_records,
        )
        assert isinstance(unified, list)
        assert len(unified) == len(syslog_records) + len(auth_records)

    def test_unify_logs_sorted_by_timestamp(self, syslog_file, authlog_file):
        syslog_records = parse_syslog(syslog_file, reference_year=2026)
        auth_records = parse_authlog(authlog_file, reference_year=2026)
        unified = unify_logs(
            syslog_entries=syslog_records,
            authlog_entries=auth_records,
        )
        timestamps = [r["timestamp"] for r in unified]
        assert timestamps == sorted(timestamps)

    def test_unify_logs_common_fields(self, syslog_file):
        records = parse_syslog(syslog_file, reference_year=2026)
        unified = unify_logs(syslog_entries=records)
        required_fields = {"timestamp", "user_id", "command_type", "origin_ip", "event_type", "source"}
        for record in unified:
            assert required_fields.issubset(record.keys())

    def test_save_unified_logs(self, syslog_file, tmp_path):
        records = parse_syslog(syslog_file, reference_year=2026)
        unified = unify_logs(syslog_entries=records)
        output = str(tmp_path / "normalized.json")
        save_unified_logs(unified, output)
        assert os.path.isfile(output)
        with open(output) as f:
            data = json.load(f)
        assert data["total_records"] == len(unified)
        assert "records" in data

    def test_unify_empty_inputs(self):
        unified = unify_logs()
        assert unified == []


# ─────────────────────────────────────────────────────────────────────────────
# VirusTotal Client Tests (Mocked)
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalClient:
    def test_compute_file_sha256(self, sample_artifact):
        digest = compute_file_sha256(sample_artifact)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_compute_sha256_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            compute_file_sha256("/nonexistent/file.bin")

    def test_check_hash_no_api_key(self):
        """Without an API key, should return an error dict."""
        with patch("analysis.threat_intel.virustotal_client.VIRUSTOTAL_API_KEY", ""):
            result = check_hash("abc123def456")
        assert result["status"] == "error"
        assert "API key" in result["error"]

    @patch("analysis.threat_intel.virustotal_client.requests.get")
    def test_check_hash_found(self, mock_get):
        """Simulate a VT hit."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "undetected": 60,
                        "harmless": 0,
                    },
                    "last_analysis_date": "2026-01-01",
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.generic"
                    },
                }
            }
        }
        mock_get.return_value = mock_resp

        with patch("analysis.threat_intel.virustotal_client.VIRUSTOTAL_API_KEY", "FAKEKEY"):
            result = check_hash("abc123" * 10 + "abcd")
        assert result["status"] == "success"
        assert result["found"] is True
        assert result["positives"] == 6
        assert result["total"] == 66

    @patch("analysis.threat_intel.virustotal_client.requests.get")
    def test_check_hash_not_found(self, mock_get):
        """Simulate a VT miss (404)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with patch("analysis.threat_intel.virustotal_client.VIRUSTOTAL_API_KEY", "FAKEKEY"):
            result = check_hash("deadbeef" * 8)
        assert result["status"] == "not_found"
        assert result["found"] is False

    @patch("analysis.threat_intel.virustotal_client.requests.get")
    def test_check_hash_rate_limit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        with patch("analysis.threat_intel.virustotal_client.VIRUSTOTAL_API_KEY", "FAKEKEY"):
            result = check_hash("abc123" * 10 + "abcd")
        assert result["status"] == "error"
        assert "rate limit" in result["error"].lower()

    def test_save_threat_intel_results(self, tmp_path):
        results = [
            {"hash": "abc", "found": True, "positives": 3, "total": 60, "status": "success"},
            {"hash": "def", "found": False, "status": "not_found"},
        ]
        output = str(tmp_path / "vt_results.json")
        save_threat_intel_results(results, output)
        assert os.path.isfile(output)
        with open(output) as f:
            data = json.load(f)
        assert data["total_checked"] == 2
        assert data["total_flagged"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Builder Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTimelineBuilder:
    def test_normalize_iso_timestamp(self):
        ts = "2026-04-07T14:23:01+00:00"
        result = normalize_timestamp(ts)
        assert "2026-04-07" in result
        assert "14:23:01" in result

    def test_normalize_syslog_timestamp(self):
        result = normalize_timestamp("Apr  7 14:23:01")
        assert "14:23:01" in result

    def test_normalize_empty_timestamp(self):
        assert normalize_timestamp("") == ""

    def test_build_timeline_merges_sources(self):
        source_a = [
            {"timestamp": "2026-04-07T14:00:00+00:00", "event": "A1"},
            {"timestamp": "2026-04-07T14:30:00+00:00", "event": "A2"},
        ]
        source_b = [
            {"timestamp": "2026-04-07T14:15:00+00:00", "event": "B1"},
        ]
        timeline = build_timeline(source_a, source_b)
        assert len(timeline) == 3

    def test_build_timeline_sorted_chronologically(self):
        source_a = [{"timestamp": "2026-04-07T14:30:00+00:00", "event": "late"}]
        source_b = [{"timestamp": "2026-04-07T14:00:00+00:00", "event": "early"}]
        timeline = build_timeline(source_a, source_b)
        assert timeline[0]["event"] == "early"
        assert timeline[1]["event"] == "late"

    def test_build_timeline_empty_sources(self):
        timeline = build_timeline([], [], None)
        assert timeline == []

    def test_build_timeline_preserves_fields(self):
        source = [{"timestamp": "2026-04-07T14:00:00+00:00", "custom_field": "value"}]
        timeline = build_timeline(source)
        assert timeline[0]["custom_field"] == "value"

    def test_save_timeline(self, tmp_path):
        events = [
            {"timestamp": "2026-04-07T14:00:00+00:00", "event_type": "system", "source": "syslog"},
            {"timestamp": "2026-04-07T14:30:00+00:00", "event_type": "auth", "source": "auth_log"},
        ]
        output = str(tmp_path / "timeline.json")
        save_timeline(events, output)
        assert os.path.isfile(output)
        with open(output) as f:
            data = json.load(f)
        assert data["total_events"] == 2
        assert "events" in data
        assert "time_range" in data
        assert "source_distribution" in data

    def test_build_timeline_from_processed(self, tmp_path):
        """Test loading from processed directory with normalized_logs.json."""
        records = [
            {"timestamp": "2026-04-07T14:00:00+00:00", "event_type": "system", "source": "syslog"},
            {"timestamp": "2026-04-07T14:30:00+00:00", "event_type": "auth", "source": "auth_log"},
        ]
        normalized_path = tmp_path / "normalized_logs.json"
        with open(str(normalized_path), "w") as f:
            json.dump({"records": records}, f)

        events = build_timeline_from_processed(str(tmp_path))
        assert len(events) == 2
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)
