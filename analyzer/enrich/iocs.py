"""Indicator of Compromise (IOC) and Artifact Extraction — TASK-030.

Extracts peer IPs, SPIs, Vendor IDs, and identities into structured IOC lists.
"""

from __future__ import annotations

from typing import Any
from analyzer.models import Facts, Finding


def extract_iocs(facts: Facts, findings: list[Finding]) -> list[dict[str, Any]]:
    """Extract all relevant IOCs (IPs, SPIs, Vendor IDs, Identities) from Facts."""
    iocs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add_ioc(ioc_type: str, value: str, context: str) -> None:
        key = (ioc_type, value)
        if key not in seen and value:
            seen.add(key)
            iocs.append({
                "type": ioc_type,
                "value": value,
                "context": context,
            })

    # 1. Peer IPs from IKE sessions
    for s in facts.sessions:
        if s.initiator.ip:
            _add_ioc("ip_address", s.initiator.ip, f"IKE initiator (Session {s.id})")
        if s.responder.ip:
            _add_ioc("ip_address", s.responder.ip, f"IKE responder (Session {s.id})")

        # SPIs
        if s.spi_i and s.spi_i != "0000000000000000":
            _add_ioc("spi", s.spi_i, f"Initiator SPI for session {s.id}")
        if s.spi_r and s.spi_r != "0000000000000000":
            _add_ioc("spi", s.spi_r, f"Responder SPI for session {s.id}")

        # Vendor IDs
        for vid in s.vendor_ids:
            _add_ioc("vendor_id", vid, f"Reported vendor identity in session {s.id}")

    # 2. Flows (ESP / AH)
    for flow in facts.flows:
        _add_ioc("ip_address", flow.src, f"IPsec {flow.proto.upper()} source")
        _add_ioc("ip_address", flow.dst, f"IPsec {flow.proto.upper()} destination")
        if flow.spi:
            _add_ioc("spi", flow.spi, f"IPsec {flow.proto.upper()} SPI")

    # 3. Findings affected sessions / context
    for f in findings:
        if f.category in ("Reconnaissance", "DoS") or "scan" in f.rule_id.lower() or "flood" in f.rule_id.lower():
            for ev in f.evidence:
                if ev.note:
                    _add_ioc("suspicious_activity", ev.note, f"Associated with finding {f.rule_id}")

    return iocs
