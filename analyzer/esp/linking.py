"""ESP/AH flow pairing and IKE session linking — TASK-021.

Pairs bidirectional ESP/AH flows (reverse IP src/dst with same encapsulation)
and heuristically links flows to IKE sessions based on matching endpoints,
NAT-T encapsulation, and temporal proximity.

In accordance with passive analysis principles (SPEC Non-negotiable Rule 3/4),
link confidence is capped at <= 0.7 (heuristic).
Unlinked flows report None.
"""

from __future__ import annotations

from typing import Sequence

from analyzer.models import IkeSession, IpsecFlow


def pair_flows(flows: list[IpsecFlow]) -> None:
    """Pair reverse directional flows in-place.

    Flow A (src=X, dst=Y, encap=E) pairs with Flow B (src=Y, dst=X, encap=E).
    """
    paired: set[str] = set()

    for i, flow_a in enumerate(flows):
        if flow_a.id in paired:
            continue
        for flow_b in flows[i + 1:]:
            if flow_b.id in paired:
                continue
            if (
                flow_a.src == flow_b.dst
                and flow_a.dst == flow_b.src
                and flow_a.proto == flow_b.proto
                and flow_a.encap == flow_b.encap
            ):
                flow_a.paired_flow_id = flow_b.id
                flow_b.paired_flow_id = flow_a.id
                paired.add(flow_a.id)
                paired.add(flow_b.id)
                break


def link_flows_to_ike_sessions(
    flows: list[IpsecFlow],
    sessions: Sequence[IkeSession],
    max_time_skew_s: float = 300.0,
) -> None:
    """Heuristically link IPsec flows to IKE sessions in-place.

    Matches by:
    1. Endpoint IP pairs: (flow.src == init and flow.dst == resp) or vice versa.
    2. Encapsulation: NAT-T flows match sessions with session.natt=True (or port 4500).
    3. Temporal: flow starts during or after IKE negotiation (within max_time_skew_s).

    Sets flow.linked_ike_session_id and flow.link_confidence <= 0.7.
    If no match, leaves both as None.
    """
    for flow in flows:
        best_session: IkeSession | None = None
        best_score = 0.0

        for session in sessions:
            init_ip = session.initiator.ip
            resp_ip = session.responder.ip

            # 1. IP matching
            ip_match = (
                (flow.src == init_ip and flow.dst == resp_ip)
                or (flow.src == resp_ip and flow.dst == init_ip)
            )
            if not ip_match:
                continue

            # 2. Encap matching
            if flow.encap == "natt" and not session.natt:
                # Flow is in UDP 4500 but session was not on 4500
                continue

            # 3. Temporal matching
            # Flow should start around or after session first_ts
            time_diff = flow.first_ts - session.first_ts
            if time_diff < -10.0:  # Flow started noticeably before IKE
                continue
            if time_diff > max_time_skew_s and flow.first_ts > session.last_ts + max_time_skew_s:
                continue

            # Base confidence score: endpoints + time
            score = 0.6
            if flow.encap == "natt" and session.natt:
                score += 0.1  # Matches NAT-T context
            elif flow.encap == "raw" and not session.natt:
                score += 0.05

            # Must never exceed 0.7 (SPEC acceptance criterion)
            score = min(score, 0.7)

            if score > best_score:
                best_score = score
                best_session = session

        if best_session is not None and best_score > 0.0:
            flow.linked_ike_session_id = best_session.id
            flow.link_confidence = round(best_score, 2)
        else:
            flow.linked_ike_session_id = None
            flow.link_confidence = None
