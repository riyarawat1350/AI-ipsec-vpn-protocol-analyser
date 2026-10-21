"""ESP and AH protocol detectors — TASK-028 per SRS §12.2 and SPEC §5.6–§5.7.

Detects:
- ESP-NULL-001: ESP payload appears unencrypted
- ESP-SEQ-001: Sequence gaps / duplicates on ESP/AH flow
- ESP-SEQ-002: Sequence near wrap without observed rekey
- ESP-NOIKE-001: High volume ESP flow without observed IKE negotiation
- AH-001: Authentication Header (AH, proto 51) usage
"""

from __future__ import annotations

from typing import Any

from analyzer.models import Evidence, Facts, RawFinding


def detect_esp_anomalies(
    facts: Facts, settings: dict[str, Any] | None = None
) -> list[RawFinding]:
    """Detect anomalies across tracked ESP and AH flows."""
    findings: list[RawFinding] = []

    for flow in facts.flows:
        # 1. ESP-NULL-001: Plaintext / Unencrypted ESP payload
        if flow.null_suspected:
            ev_list = []
            for pkt_no in flow.sample_pkt_nos[:3]:
                ev_list.append(
                    Evidence(
                        packet_no=pkt_no,
                        ts=flow.first_ts,
                        message=f"ESP packet on flow {flow.src} -> {flow.dst} (SPI {flow.spi}) matches plaintext/tunnel heuristic",
                        field_path="esp.payload",
                        raw_value=flow.inferred_mode,
                        decoded=f"Inferred {flow.inferred_mode or 'plaintext'} unencrypted inner packet",
                        hex_excerpt=flow.spi,
                        note=f"Inferred mode: {flow.inferred_mode}, confidence: {flow.null_confidence or 0.85}",
                    )
                )

            findings.append(
                RawFinding(
                    rule_id="ESP-NULL-001",
                    origin="detector",
                    category="Cryptography",
                    title=f"ESP payload appears unencrypted (NULL cipher) on SPI {flow.spi}",
                    explanation=(
                        f"Heuristic inspection of ESP flow {flow.src} -> {flow.dst} (SPI {flow.spi}) "
                        f"detected inner packet structures with valid IPv4 header checksums. "
                        f"The traffic appears to be transmitted in cleartext without encryption."
                    ),
                    why_this_matters=(
                        "Using ESP with NULL encryption provides zero confidentiality protection. "
                        "All encapsulated payloads are exposed to eavesdropping."
                    ),
                    impact=5,
                    likelihood=5,
                    confidence=flow.null_confidence or 0.85,
                    evidence=ev_list,
                    affected_sessions=[flow.linked_ike_session_id] if flow.linked_ike_session_id else [],
                    count=1,
                    references=["RFC 4303", "RFC 2410 (The NULL Encryption Algorithm)", "NIST SP 800-77r1"],
                    mitre=[],
                    recommendation_id="REC-ESP-NULL-001",
                    params={"spi": flow.spi, "inferred_mode": flow.inferred_mode or "unknown"},
                    override_severity="Critical",
                )
            )

        # 2. ESP-SEQ-001: Sequence gaps and duplicates
        if flow.seq.gaps or flow.seq.duplicates > 0:
            ev_list = []
            for start_seq, end_seq, pkt_no in flow.seq.gaps[:3]:
                ev_list.append(
                    Evidence(
                        packet_no=pkt_no,
                        ts=flow.first_ts,
                        message=f"Sequence number gap from {start_seq} to {end_seq}",
                        field_path="esp.seq",
                        raw_value={"gap_start": start_seq, "gap_end": end_seq},
                        decoded=f"Sequence number gap [{start_seq}..{end_seq}]",
                        hex_excerpt=f"{start_seq:08x}",
                        note="Packet loss or out-of-order delivery observed",
                    )
                )
            if flow.seq.duplicates > 0:
                ev_list.append(
                    Evidence(
                        packet_no=flow.sample_pkt_nos[0] if flow.sample_pkt_nos else 1,
                        ts=flow.first_ts,
                        message=f"Observed {flow.seq.duplicates} duplicate ESP sequence numbers",
                        field_path="esp.seq",
                        raw_value={"duplicates": flow.seq.duplicates},
                        decoded=f"{flow.seq.duplicates} duplicate/replayed ESP sequence numbers",
                        hex_excerpt=f"{flow.seq.duplicates:04x}",
                        note="Replay or duplicate transmission detected",
                    )
                )

            findings.append(
                RawFinding(
                    rule_id="ESP-SEQ-001",
                    origin="detector",
                    category="Network",
                    title=f"Sequence gaps or duplicate packets on {flow.proto.upper()} SPI {flow.spi}",
                    explanation=(
                        f"Flow {flow.src} -> {flow.dst} experienced {len(flow.seq.gaps)} sequence gaps "
                        f"and {flow.seq.duplicates} duplicate sequence numbers over {flow.packets} packets."
                    ),
                    why_this_matters=(
                        "Packet sequence gaps cause tunnel packet loss and reduced throughput. "
                        "Duplicate sequence numbers may trigger replay-window drops at the receiving gateway."
                    ),
                    impact=2,
                    likelihood=3,
                    confidence=0.6,
                    evidence=ev_list[:5],
                    affected_sessions=[flow.linked_ike_session_id] if flow.linked_ike_session_id else [],
                    count=len(flow.seq.gaps) + flow.seq.duplicates,
                    references=["RFC 4303 §3.4.3 (Anti-Replay Mechanism)"],
                    mitre=[],
                    recommendation_id="REC-ESP-SEQ-001",
                    params={"spi": flow.spi, "duplicates": flow.seq.duplicates, "gaps_count": len(flow.seq.gaps)},
                    override_severity=None,
                )
            )

        # 3. ESP-SEQ-002: Sequence near wrap
        if flow.seq.wrap_near:
            findings.append(
                RawFinding(
                    rule_id="ESP-SEQ-002",
                    origin="detector",
                    category="Operational",
                    title=f"ESP sequence number near 32-bit wrap on SPI {flow.spi}",
                    explanation=(
                        f"Flow {flow.src} -> {flow.dst} reached max sequence number {flow.seq.max_seq} "
                        f"(> 0xFFFFFF00). Without Extended Sequence Numbers (ESN) or rekeying, the SA will expire."
                    ),
                    why_this_matters=(
                        "When sequence numbers wrap without ESN, the SA must be renegotiated or all subsequent "
                        "packets will be dropped to prevent keystream reuse attacks."
                    ),
                    impact=3,
                    likelihood=3,
                    confidence=0.7,
                    evidence=[
                        Evidence(
                            packet_no=flow.sample_pkt_nos[-1] if flow.sample_pkt_nos else 1,
                            ts=flow.last_ts,
                            message=f"Sequence number reached {flow.seq.max_seq}",
                            field_path="esp.seq",
                            raw_value=flow.seq.max_seq,
                            decoded=f"Sequence number 0x{flow.seq.max_seq:08x} near 32-bit limit",
                            hex_excerpt=f"{flow.seq.max_seq:08x}",
                            note="Sequence approaching 2^32 boundary",
                        )
                    ],
                    affected_sessions=[flow.linked_ike_session_id] if flow.linked_ike_session_id else [],
                    count=1,
                    references=["RFC 4303 §3.3.3"],
                    mitre=[],
                    recommendation_id="REC-IKE-V1-004",
                    params={"spi": flow.spi, "max_seq": flow.seq.max_seq},
                )
            )

        # 4. ESP-NOIKE-001: ESP without observed IKE
        if flow.packets >= 20 and not flow.linked_ike_session_id and len(facts.sessions) == 0:
            findings.append(
                RawFinding(
                    rule_id="ESP-NOIKE-001",
                    origin="detector",
                    category="Coverage",
                    title=f"Active ESP flow with no corresponding IKE negotiation seen (SPI {flow.spi})",
                    explanation=(
                        f"Flow {flow.src} -> {flow.dst} carried {flow.packets} packets, but no matching "
                        f"IKE handshake was observed in the capture."
                    ),
                    why_this_matters=(
                        "Without observed IKE negotiation, key exchange parameters and identity authentication "
                        "cannot be assessed from this capture."
                    ),
                    impact=1,
                    likelihood=3,
                    confidence=0.5,
                    evidence=[
                        Evidence(
                            packet_no=flow.sample_pkt_nos[0] if flow.sample_pkt_nos else 1,
                            ts=flow.first_ts,
                            message=f"ESP flow with {flow.packets} packets without observed IKE",
                            field_path="esp.spi",
                            raw_value=flow.spi,
                            decoded=f"ESP SPI 0x{flow.spi} ({flow.packets} packets)",
                            hex_excerpt=flow.spi,
                            note="Session negotiation unobserved",
                        )
                    ],
                    affected_sessions=[],
                    count=1,
                    references=["NIST SP 800-77r1"],
                    mitre=[],
                    recommendation_id="REC-CAPTURE-COMPLETE",
                    params={"spi": flow.spi, "packets": flow.packets},
                    override_severity="Info",
                )
            )

        # 5. AH-001: Authentication Header in use
        if flow.proto == "ah":
            findings.append(
                RawFinding(
                    rule_id="AH-001",
                    origin="detector",
                    category="Cryptography",
                    title=f"Authentication Header (AH, protocol 51) in use on SPI {flow.spi}",
                    explanation=(
                        f"Traffic between {flow.src} and {flow.dst} utilizes IPsec AH. "
                        f"AH provides integrity and authentication but no confidentiality, and breaks NAT traversal."
                    ),
                    why_this_matters=(
                        "AH is deprecated in favor of ESP with AEAD (RFC 8221 / RFC 8247). "
                        "AH packets cannot traverse NAT devices without special handling."
                    ),
                    impact=1,
                    likelihood=5,
                    confidence=1.0,
                    evidence=[
                        Evidence(
                            packet_no=flow.sample_pkt_nos[0] if flow.sample_pkt_nos else 1,
                            ts=flow.first_ts,
                            message=f"AH packet observed with SPI {flow.spi}",
                            field_path="ip.proto",
                            raw_value=51,
                            decoded="IP Protocol 51 (Authentication Header - AH)",
                            hex_excerpt="33",
                            note="Protocol 51 (AH)",
                        )
                    ],
                    affected_sessions=[flow.linked_ike_session_id] if flow.linked_ike_session_id else [],
                    count=1,
                    references=["RFC 4302", "RFC 8221 §4"],
                    mitre=[],
                    recommendation_id="REC-CRY-ENC-001",
                    params={"spi": flow.spi},
                    override_severity="Low",
                )
            )

    return findings
