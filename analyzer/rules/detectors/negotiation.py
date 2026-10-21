"""IKE negotiation anomaly detector — TASK-027.

Detects:
- IKE-NEG-001: Repeated NO_PROPOSAL_CHOSEN notifies (>= 3 in 60s per peer pair).
- IKE-NEG-002: Repeated INVALID_KE_PAYLOAD notifies (>= 3 per pair).
- IKE-NEG-003: Unanswered handshakes (SA_INIT with retransmissions >= 3).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from analyzer.models import Evidence, Facts, RawFinding


def detect_negotiation_anomalies(
    facts: Facts, settings: dict[str, Any] | None = None
) -> list[RawFinding]:
    """Detect repeated negotiation failures and unanswered handshakes."""
    cfg = settings or {}
    no_prop_threshold = int(cfg.get("no_proposal_threshold", 3))
    invalid_ke_threshold = int(cfg.get("invalid_ke_threshold", 3))
    unanswered_retrans_threshold = int(cfg.get("unanswered_retrans_threshold", 3))

    findings: list[RawFinding] = []

    # Track notifies per peer pair: (src_ip, dst_ip) -> list of (ts, pkt_no, type)
    no_proposal_events: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    invalid_ke_events: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    affected_sess_no_prop: dict[tuple[str, str], list[str]] = defaultdict(list)
    affected_sess_invalid_ke: dict[tuple[str, str], list[str]] = defaultdict(list)

    for session in facts.sessions:
        pair_key = (session.initiator.ip, session.responder.ip)
        for msg in session.messages:
            for notify in msg.notifies:
                # NO_PROPOSAL_CHOSEN is type 14 (IKEv2 & IKEv1)
                if notify.type == 14 or "NO_PROPOSAL_CHOSEN" in notify.name.upper():
                    no_proposal_events[pair_key].append((msg.ts, msg.pkt_no))
                    if session.id not in affected_sess_no_prop[pair_key]:
                        affected_sess_no_prop[pair_key].append(session.id)
                # INVALID_KE_PAYLOAD is type 17
                elif notify.type == 17 or "INVALID_KE" in notify.name.upper():
                    invalid_ke_events[pair_key].append((msg.ts, msg.pkt_no))
                    if session.id not in affected_sess_invalid_ke[pair_key]:
                        affected_sess_invalid_ke[pair_key].append(session.id)

        # IKE-NEG-003: Unanswered handshakes with retransmissions >= threshold
        if session.outcome == "unanswered" and session.retransmissions >= unanswered_retrans_threshold:
            first_msg = session.messages[0] if session.messages else None
            pkt_no = first_msg.pkt_no if first_msg else 1
            ts = first_msg.ts if first_msg else session.first_ts
            findings.append(
                RawFinding(
                    rule_id="IKE-NEG-003",
                    origin="detector",
                    category="Negotiation",
                    title=f"Unanswered IKE handshakes: {session.initiator.ip} -> {session.responder.ip}",
                    explanation=(
                        f"Initiator sent SA_INIT requests with {session.retransmissions} "
                        "retransmissions without receiving any response."
                    ),
                    why_this_matters="Indicates network routing issues, firewall drops, or non-responsive peer.",
                    impact=2,
                    likelihood=3,
                    confidence=0.7,
                    evidence=[
                        Evidence(
                            packet_no=pkt_no,
                            ts=ts,
                            message=f"SA_INIT with {session.retransmissions} retransmissions unanswered",
                            field_path="session.retransmissions",
                            raw_value=session.retransmissions,
                            decoded=f"{session.retransmissions} retransmits",
                            hex_excerpt="",
                            note="Outcome: unanswered",
                        )
                    ],
                    affected_sessions=[session.id],
                    count=1,
                    references=["RFC 7296 §2.1", "RFC 7296 §2.4"],
                    recommendation_id="REC-REACHABILITY",
                )
            )

    # IKE-NEG-001: Repeated NO_PROPOSAL_CHOSEN (>= 3)
    for pair, events in no_proposal_events.items():
        if len(events) >= no_prop_threshold:
            evidence_list = [
                Evidence(
                    packet_no=pkt,
                    ts=t,
                    message="NO_PROPOSAL_CHOSEN notify received",
                    field_path="message.notifies",
                    raw_value=14,
                    decoded="NO_PROPOSAL_CHOSEN",
                    hex_excerpt="",
                    note=f"Event {idx + 1} of {len(events)}",
                )
                for idx, (t, pkt) in enumerate(events[:5])
            ]
            findings.append(
                RawFinding(
                    rule_id="IKE-NEG-001",
                    origin="detector",
                    category="Negotiation",
                    title=f"Repeated negotiation failure (NO_PROPOSAL_CHOSEN) between {pair[0]} and {pair[1]}",
                    explanation=(
                        f"Observed {len(events)} NO_PROPOSAL_CHOSEN notifications between peers. "
                        "The peers could not agree on compatible cryptographic algorithms."
                    ),
                    why_this_matters="Negotiation cannot complete; IPsec tunnel fails to establish.",
                    impact=2,
                    likelihood=4,
                    confidence=0.9,
                    evidence=evidence_list,
                    affected_sessions=affected_sess_no_prop[pair],
                    count=len(events),
                    references=["RFC 7296 §2.7", "RFC 2408"],
                    recommendation_id="REC-ALIGN-PROPOSALS",
                )
            )

    # IKE-NEG-002: Repeated INVALID_KE_PAYLOAD (>= 3)
    for pair, events in invalid_ke_events.items():
        if len(events) >= invalid_ke_threshold:
            evidence_list = [
                Evidence(
                    packet_no=pkt,
                    ts=t,
                    message="INVALID_KE_PAYLOAD notify received",
                    field_path="message.notifies",
                    raw_value=17,
                    decoded="INVALID_KE_PAYLOAD",
                    hex_excerpt="",
                    note=f"Event {idx + 1} of {len(events)}",
                )
                for idx, (t, pkt) in enumerate(events[:5])
            ]
            findings.append(
                RawFinding(
                    rule_id="IKE-NEG-002",
                    origin="detector",
                    category="Negotiation",
                    title=f"Repeated Key Exchange mismatch (INVALID_KE_PAYLOAD) between {pair[0]} and {pair[1]}",
                    explanation=(
                        f"Observed {len(events)} INVALID_KE_PAYLOAD notifications. "
                        "The peers are repeatedly negotiating incompatible Diffie-Hellman groups."
                    ),
                    why_this_matters="Repeated KE retries introduce handshake delays and failure states.",
                    impact=2,
                    likelihood=4,
                    confidence=0.9,
                    evidence=evidence_list,
                    affected_sessions=affected_sess_invalid_ke[pair],
                    count=len(events),
                    references=["RFC 7296 §1.3", "RFC 7296 §2.6"],
                    recommendation_id="REC-ALIGN-PROPOSALS",
                )
            )

    return findings
