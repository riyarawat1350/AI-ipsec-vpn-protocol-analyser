"""Vendor ID registry and lookup — TASK-018.

Maps known Vendor ID hashes and signatures to vendor/implementation names.
Matches are explicitly labelled as "self-reported" per RFC 7296 / SRS.
Unknown VIDs are displayed as hex only.
"""

from __future__ import annotations

import hashlib
from typing import Any, NamedTuple


class VendorMatch(NamedTuple):
    name: str
    category: str
    confidence: str = "self-reported"


# Standard known VIDs (hex string lowercase -> VendorMatch)
_KNOWN_VIDS: dict[str, VendorMatch] = {
    # strongSwan standard MD5 / signature
    "882fe56d6fd20dbc2251613b2ebe5beb": VendorMatch("strongSwan", "Implementation"),
    # DPD (Dead Peer Detection) RFC 3706
    "afcad71368a1f1c96b8696fc77570100": VendorMatch("RFC 3706 (Dead Peer Detection - DPD)", "Feature"),
    # XAUTH
    "09002689dfd6b712": VendorMatch("XAUTH", "Feature"),
    # IKE Fragmentation
    "4048b7d56ebce88525e7de7f00d6c2d3": VendorMatch("IKE Fragmentation", "Feature"),
    # Cisco Unity
    "12f5f28c457168a9702d9fe274cc0100": VendorMatch("Cisco Unity", "Vendor"),
    # Microsoft Windows
    "1e2b516905991c7d7c96fcbfb587e461": VendorMatch("Microsoft Windows (IKEv1)", "Vendor"),
    "fb1d30ef54456c22d45987f9f32292ce": VendorMatch("Microsoft Windows (IKEv2)", "Vendor"),
    # Check Point
    "f4487641304a2220a2be2d16711e247f": VendorMatch("Check Point", "Vendor"),
    # SonicWALL
    "404bf4cb61341edc65ab22618b679f50": VendorMatch("SonicWALL", "Vendor"),
    # Fortinet
    "8299031420b91eb0125e313f8fe8a328": VendorMatch("Fortinet", "Vendor"),
}

# Add standard MD5 string hashes
_STANDARD_STRINGS: dict[bytes, tuple[str, str]] = {
    b"RFC 3947": ("RFC 3947 (NAT-Traversal)", "Standard"),
    b"draft-ietf-ipsec-nat-t-ike-02\n": ("draft-ietf-ipsec-nat-t-ike-02", "Standard"),
    b"draft-ietf-ipsec-nat-t-ike-03": ("draft-ietf-ipsec-nat-t-ike-03", "Standard"),
}

for raw_s, (label, cat) in _STANDARD_STRINGS.items():
    _h = hashlib.md5(raw_s).hexdigest().lower()
    _KNOWN_VIDS[_h] = VendorMatch(label, cat)


def lookup_vendor_id(vid_bytes: bytes | str) -> VendorMatch | None:
    """Look up a Vendor ID.

    Accepts raw bytes or a hex string.
    Returns VendorMatch or None if unknown.
    """
    if isinstance(vid_bytes, str):
        hex_key = vid_bytes.lower()
        try:
            raw_b = bytes.fromhex(vid_bytes)
        except ValueError:
            raw_b = vid_bytes.encode()
    else:
        hex_key = vid_bytes.hex().lower()
        raw_b = vid_bytes

    # 1. Exact hex match
    if hex_key in _KNOWN_VIDS:
        return _KNOWN_VIDS[hex_key]

    # 2. General ASCII check (e.g. Cisco delete reason or implementation strings)
    try:
        ascii_text = raw_b.decode("ascii", errors="strict")
        if all(32 <= ord(c) <= 126 for c in ascii_text) and len(ascii_text) >= 3:
            if ascii_text.startswith("strongSwan"):
                return VendorMatch(f"strongSwan ({ascii_text})", "Implementation")
            if ascii_text.startswith("OpenS"):
                return VendorMatch("Openswan", "Implementation")
            if ascii_text.startswith("Libreswan"):
                return VendorMatch(f"Libreswan ({ascii_text})", "Implementation")
            return VendorMatch(ascii_text, "ASCII String")
    except UnicodeDecodeError:
        pass

    return None


def decode_vendor_id(vid_bytes: bytes | str) -> dict[str, Any]:
    """Decode a Vendor ID for UI and report presentation.

    - Resolves known hashes (e.g. IKE Fragmentation RFC 7383).
    - Decodes printable ASCII bytes (e.g. CISCO-DELETE-REASON).
    - Keeps raw hex distinct.
    - Always attaches 'peer-reported (may be spoofed)' label.
    """
    if isinstance(vid_bytes, str):
        hex_key = vid_bytes.lower().strip()
        try:
            raw_b = bytes.fromhex(hex_key)
        except ValueError:
            raw_b = hex_key.encode("ascii", errors="ignore")
    else:
        hex_key = vid_bytes.hex().lower()
        raw_b = vid_bytes

    match = lookup_vendor_id(vid_bytes)
    ascii_decoded: str | None = None
    try:
        decoded = raw_b.decode("ascii", errors="strict")
        if all(32 <= ord(c) <= 126 for c in decoded) and len(decoded) >= 2:
            ascii_decoded = decoded
    except UnicodeDecodeError:
        pass

    display_name = match.name if match else (ascii_decoded or hex_key)

    return {
        "raw_hex": hex_key,
        "name": match.name if match else None,
        "ascii_decoded": ascii_decoded,
        "display": display_name,
        "category": match.category if match else ("ASCII String" if ascii_decoded else "Unknown Hash"),
        "is_known": bool(match),
        "is_ascii": bool(ascii_decoded),
        "label": "peer-reported (may be spoofed)",
    }

