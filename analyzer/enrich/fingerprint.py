"""Vendor ID and peer fingerprinting enrichment — TASK-018.

Matches Vendor IDs extracted from IKE payloads against known registry,
displaying matched names labelled as "self-reported" or hex string if unknown.
"""

from __future__ import annotations

from typing import Any

from analyzer.ike.vendor_ids import lookup_vendor_id


def fingerprint_vendor_id(vid: bytes | str) -> dict[str, Any]:
    """Fingerprint a Vendor ID payload.

    Returns dict with:
    - raw_hex: str
    - matched_name: str
    - label: 'self-reported'
    - is_known: bool
    - category: str
    """
    if isinstance(vid, bytes):
        raw_hex = vid.hex().lower()
    else:
        raw_hex = vid.lower()

    match = lookup_vendor_id(vid)
    if match:
        return {
            "raw_hex": raw_hex,
            "matched_name": match.name,
            "label": match.confidence,  # "self-reported"
            "category": match.category,
            "is_known": True,
        }

    return {
        "raw_hex": raw_hex,
        "matched_name": raw_hex,
        "label": "self-reported",
        "category": "Unknown",
        "is_known": False,
    }


def fingerprint_vendor_ids(vids: list[bytes | str]) -> list[dict[str, Any]]:
    """Fingerprint a list of Vendor IDs."""
    return [fingerprint_vendor_id(v) for v in vids]
