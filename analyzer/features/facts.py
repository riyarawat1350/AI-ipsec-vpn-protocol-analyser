"""Capture-level statistics and Facts builder stubs (FR-42, FR-49).

TASK-010: populate `capture` and `protocol_stats` sections of Facts.
Full facts builder (sessions, observations, flows) is TASK-022.
"""

from __future__ import annotations

from analyzer.classify.classifier import ClassifierResult, PortStats, TalkerStats
from analyzer.models import Facts


def build_capture_stats(result: ClassifierResult) -> dict:
    """Convert a :class:`ClassifierResult` into the `capture` dict for Facts.

    Keys mirror SRS §10 and the expected JSON schema from Document 5 §3.
    """
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


def build_protocol_stats(result: ClassifierResult, top_n: int = 10) -> dict:
    """Convert a :class:`ClassifierResult` into the `protocol_stats` dict for Facts.

    Keys:
        counts           – raw per-bucket packet counts
        distribution     – per-bucket fraction of total
        top_talkers      – top-n source IPs by packet count
        top_ports        – top-n ports by packet count
    """
    top_talkers_raw: list[TalkerStats] = result.top_talkers(top_n)
    top_ports_raw: list[PortStats] = result.top_ports(top_n)

    return {
        "counts": dict(result.counts),
        "distribution": result.protocol_distribution(),
        "top_talkers": [
            {"ip": t.ip, "packets": t.packets, "bytes": t.bytes}
            for t in top_talkers_raw
        ],
        "top_ports": [
            {"port": p.port, "proto": p.proto, "packets": p.packets}
            for p in top_ports_raw
        ],
    }


def build_facts_from_classifier(result: ClassifierResult) -> Facts:
    """Construct a :class:`~analyzer.models.Facts` object from classifier results.

    Sessions, observations, and flows are populated to empty lists; they will
    be filled in by TASK-022 (full facts builder).
    """
    return Facts(
        capture=build_capture_stats(result),
        protocol_stats=build_protocol_stats(result),
        sessions=[],
        observations=[],
        flows=[],
        windows=[],
        unsupported=[],
        warnings=list(result.warnings),
    )
