"""
CyberForensX — MISP Client
Module: analysis/threat_intel/misp_client.py

Integrates with a MISP (Malware Information Sharing Platform) instance
to search for matching IOCs (Indicators of Compromise) from collected
forensic artifacts.

Configuration:
  Set MISP_URL and MISP_API_KEY environment variables or configure
  in config/settings.py

MISP API Reference:
  https://www.misp-project.org/openapi/
"""

import os
import json
import logging
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.settings import MISP_URL, MISP_API_KEY, PROCESSED_DIR

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# MISP Connection
# ─────────────────────────────────────────────────────────────────────────────

def _get_misp_client():
    """
    Create and return a PyMISP client instance.

    Returns:
        PyMISP instance, or None if not configured.
    """
    if not MISP_URL or not MISP_API_KEY:
        logger.warning(
            "MISP not configured. Set MISP_URL and MISP_API_KEY environment variables."
        )
        return None

    try:
        from pymisp import PyMISP
        misp = PyMISP(MISP_URL, MISP_API_KEY, ssl=False)
        logger.info("Connected to MISP instance: %s", MISP_URL)
        return misp
    except ImportError:
        logger.warning("pymisp library not installed. Run: pip install pymisp")
        return None
    except Exception as e:
        logger.error("Failed to connect to MISP: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# IOC Searches
# ─────────────────────────────────────────────────────────────────────────────

def search_by_hash(file_hash: str) -> list[dict]:
    """
    Search MISP for events containing a given file hash (MD5, SHA-1, or SHA-256).

    Args:
        file_hash: File hash string.

    Returns:
        List of matching MISP event dicts with keys:
          event_id, info, threat_level, date, attributes
    """
    misp = _get_misp_client()
    if not misp:
        return []

    try:
        # Search for hash across common hash attribute types
        result = misp.search(
            controller="attributes",
            type_attribute=["md5", "sha1", "sha256"],
            value=file_hash,
            pythonify=True,
        )

        events = _extract_events(result)
        logger.info("MISP hash search for %s...: %d event(s) found",
                     file_hash[:16], len(events))
        return events

    except Exception as e:
        logger.error("MISP hash search failed: %s", e)
        return []


def search_by_ip(ip_address: str) -> list[dict]:
    """
    Search MISP for events containing a given IP address.

    Args:
        ip_address: IP address string (e.g. '192.168.1.100').

    Returns:
        List of matching MISP event dicts.
    """
    misp = _get_misp_client()
    if not misp:
        return []

    try:
        result = misp.search(
            controller="attributes",
            type_attribute=["ip-src", "ip-dst"],
            value=ip_address,
            pythonify=True,
        )

        events = _extract_events(result)
        logger.info("MISP IP search for %s: %d event(s) found",
                     ip_address, len(events))
        return events

    except Exception as e:
        logger.error("MISP IP search failed: %s", e)
        return []


def search_by_domain(domain: str) -> list[dict]:
    """
    Search MISP for events containing a given domain.

    Args:
        domain: Domain name string.

    Returns:
        List of matching MISP event dicts.
    """
    misp = _get_misp_client()
    if not misp:
        return []

    try:
        result = misp.search(
            controller="attributes",
            type_attribute=["domain", "hostname"],
            value=domain,
            pythonify=True,
        )

        events = _extract_events(result)
        logger.info("MISP domain search for %s: %d event(s) found",
                     domain, len(events))
        return events

    except Exception as e:
        logger.error("MISP domain search failed: %s", e)
        return []


def search_ioc(value: str, ioc_type: str = "auto") -> list[dict]:
    """
    Search MISP for an IOC, auto-detecting its type if needed.

    Args:
        value:    The IOC value (hash, IP, domain).
        ioc_type: One of 'hash', 'ip', 'domain', or 'auto' (auto-detect).

    Returns:
        List of matching MISP event dicts.
    """
    import re

    if ioc_type == "auto":
        # Auto-detect based on pattern
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            ioc_type = "ip"
        elif re.match(r"^[a-fA-F0-9]{32,64}$", value):
            ioc_type = "hash"
        else:
            ioc_type = "domain"

    if ioc_type == "hash":
        return search_by_hash(value)
    elif ioc_type == "ip":
        return search_by_ip(value)
    elif ioc_type == "domain":
        return search_by_domain(value)
    else:
        logger.warning("Unknown IOC type: %s", ioc_type)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Result Extraction
# ─────────────────────────────────────────────────────────────────────────────

_THREAT_LEVELS = {
    "1": "High",
    "2": "Medium",
    "3": "Low",
    "4": "Undefined",
}


def _extract_events(attributes) -> list[dict]:
    """
    Extract unique MISP events from a list of attribute search results.

    Args:
        attributes: List of MISPAttribute objects or dicts.

    Returns:
        List of de-duplicated event summary dicts.
    """
    seen_event_ids = set()
    events = []

    for attr in (attributes or []):
        # Handle both PyMISP objects and plain dicts
        if hasattr(attr, "to_dict"):
            attr_dict = attr.to_dict()
        elif isinstance(attr, dict):
            attr_dict = attr
        else:
            continue

        # Extract event info from the attribute's parent event
        event = attr_dict.get("Event", attr_dict.get("event", {}))
        if isinstance(event, dict):
            event_id = str(event.get("id", ""))
        else:
            event_id = str(getattr(event, "id", ""))

        if not event_id or event_id in seen_event_ids:
            continue

        seen_event_ids.add(event_id)

        if isinstance(event, dict):
            events.append({
                "event_id": event_id,
                "info": event.get("info", ""),
                "threat_level": _THREAT_LEVELS.get(
                    str(event.get("threat_level_id", "4")), "Undefined"
                ),
                "date": event.get("date", ""),
                "org": event.get("Orgc", {}).get("name", ""),
                "attribute_count": event.get("attribute_count", 0),
            })
        else:
            events.append({
                "event_id": event_id,
                "info": getattr(event, "info", ""),
                "threat_level": _THREAT_LEVELS.get(
                    str(getattr(event, "threat_level_id", "4")), "Undefined"
                ),
                "date": getattr(event, "date", ""),
                "org": "",
                "attribute_count": 0,
            })

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Save Results
# ─────────────────────────────────────────────────────────────────────────────

def save_misp_results(results: list[dict], query: str,
                      output_path: str = None) -> str:
    """
    Save MISP search results to a JSON file.

    Args:
        results:     List of MISP event dicts.
        query:       The IOC value that was searched.
        output_path: Destination path. Defaults to storage/processed/.

    Returns:
        Path written to.
    """
    if output_path is None:
        output_path = os.path.join(PROCESSED_DIR, "misp_results.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "misp",
            "query": query,
            "total_events": len(results),
            "events": results,
        }, f, indent=2)

    logger.info("MISP results saved to: %s", output_path)
    return output_path
