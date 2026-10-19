"""Capture-level statistics and complete Facts builder (FR-42, FR-49) — TASK-022.

Extracts Facts container from classifier results, reconstructed IKE sessions,
and tracked IPsec flows. Flattens session cryptographic proposals into
discrete Observation models for the declarative rules engine.
"""

from __future__ import annotations

from typing import Any, Literal
from analyzer.classify.classifier import ClassifierResult, PortStats, TalkerStats
from analyzer.models import Facts, IkeSession, IpsecFlow, Observation

# Mapping from transform kind uppercase to Observation kind lowercase
_KIND_MAP: dict[str, Literal["encr", "prf", "integ", "dh", "hash", "auth_method", "lifetime"]] = {
    "ENCR": "encr",
    "PRF": "prf",
    "INTEG": "integ",
    "DH": "dh",
    "HASH": "hash",
    "AUTH": "auth_method",
    "LIFE_TYPE": "lifetime",
    "LIFE_DURATION": "lifetime",
}


def build_capture_stats(result: ClassifierResult) -> dict[str, Any]:
    """Convert a :class:`ClassifierResult` into the `capture` dict for Facts."""
    duration = result.duration_seconds()
    return {
        "total_packets": result.total_packets,
        "total_bytes": result.total_bytes,
        "duration_seconds": duration,
        "first_ts": result.first_ts,
        "last_ts": result.last_ts,
        "interfaces": dict(result.interfaces),
        "link_types": dict(result.link_types),
    }


def build_protocol_stats(result: ClassifierResult, top_n: int = 10) -> dict[str, Any]:
    """Convert a :class:`ClassifierResult` into the `protocol_stats` dict for Facts."""
    top_talkers_raw: list[TalkerStats] = result.top_talkers(top_n)
    top_conversations_raw: list[ConversationStats] = result.top_conversations(top_n) if hasattr(result, "top_conversations") else []
    top_ports_raw: list[PortStats] = result.top_ports(top_n)

    return {
        "counts": dict(result.counts),
        "distribution": result.protocol_distribution(),
        "top_talkers": [
            {"ip": t.ip, "packets": t.packets, "bytes": t.bytes}
            for t in top_talkers_raw
        ],
        "conversations": [
            {
                "endpoint_a": c.endpoint_a,
                "endpoint_b": c.endpoint_b,
                "packets": c.packets,
                "bytes": c.bytes,
            }
            for c in top_conversations_raw
        ],
        "top_ports": [
            {"port": p.port, "proto": p.proto, "packets": p.packets}
            for p in top_ports_raw
        ],
    }


def build_observations_from_sessions(sessions: list[IkeSession]) -> list[Observation]:
    """Flatten cryptographic proposals from IKE sessions into Observation models.

    Adheres to SPEC §4 & §5.10. Each transform inside an offered or selected
    proposal produces one Observation.
    """
    observations: list[Observation] = []

    for session in sessions:
        # Find packet number for initiator message
        init_msg = next((m for m in session.messages if m.direction == "i2r" and m.proposals), None)
        init_pkt_no = init_msg.pkt_no if init_msg else 1

        # 1. Flatten offered proposals
        for p_idx, prop in enumerate(session.offered):
            for t_idx, t in enumerate(prop.transforms):
                kind_val = _KIND_MAP.get(t.kind)
                if not kind_val:
                    continue
                observations.append(
                    Observation(
                        session_id=session.id,
                        kind=kind_val,
                        id=t.id,
                        name=t.name,
                        key_length=t.key_length,
                        role="offered",
                        pkt_no=init_pkt_no,
                        field_path=f"session.offered[{p_idx}].transforms[{t_idx}]",
                        raw_hex=f"{t.id:04x}",
                        ike_version=session.version,
                    )
                )

        # 2. Flatten selected proposal if present
        if session.selected:
            resp_msg = next((m for m in session.messages if m.direction == "r2i" and m.proposals), None)
            resp_pkt_no = resp_msg.pkt_no if resp_msg else 2

            for t_idx, t in enumerate(session.selected.transforms):
                kind_val = _KIND_MAP.get(t.kind)
                if not kind_val:
                    continue
                observations.append(
                    Observation(
                        session_id=session.id,
                        kind=kind_val,
                        id=t.id,
                        name=t.name,
                        key_length=t.key_length,
                        role="selected",
                        pkt_no=resp_pkt_no,
                        field_path=f"session.selected.transforms[{t_idx}]",
                        raw_hex=f"{t.id:04x}",
                        ike_version=session.version,
                    )
                )

    return observations


def build_facts(
    classifier_result: ClassifierResult | None = None,
    capture_meta: dict[str, Any] | None = None,
    protocol_stats: dict[str, Any] | None = None,
    sessions: list[IkeSession] | None = None,
    flows: list[IpsecFlow] | None = None,
    observations: list[Observation] | None = None,
    warnings: list[str] | None = None,
    unsupported: list[str] | None = None,
    windows: list[dict[str, Any]] | None = None,
) -> Facts:
    """Build a complete Facts instance."""
    cap_dict = capture_meta or {}
    proto_dict = protocol_stats or {}
    warn_list = list(warnings or [])

    if classifier_result is not None:
        if not cap_dict:
            cap_dict = build_capture_stats(classifier_result)
        if not proto_dict:
            proto_dict = build_protocol_stats(classifier_result)
        warn_list.extend(classifier_result.warnings)

    sess_list = list(sessions or [])
    flow_list = list(flows or [])
    obs_list = list(observations) if observations is not None else build_observations_from_sessions(sess_list)

    unsupported_defaults = [
        "Encrypted IKE_AUTH payloads are not decrypted (passive analysis)",
        "ESP/AH payload encryption algorithms cannot be inspected without keys",
        "IPv6 ESP-NULL heuristic is not supported",
    ]
    unsupp_list = list(unsupported or unsupported_defaults)

    return Facts(
        capture=cap_dict,
        protocol_stats=proto_dict,
        sessions=sess_list,
        observations=obs_list,
        flows=flow_list,
        windows=list(windows or []),
        unsupported=unsupp_list,
        warnings=warn_list,
    )


def build_facts_from_classifier(result: ClassifierResult) -> Facts:
    """Construct Facts from classifier results with empty sessions and flows."""
    return build_facts(classifier_result=result)
