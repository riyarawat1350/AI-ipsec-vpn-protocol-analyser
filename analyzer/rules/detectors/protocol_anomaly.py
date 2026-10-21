"""IKE protocol anomaly detector — TASK-027.

Inspects packet-level anomalies, malformed structures, and invalid states.
"""

from __future__ import annotations

from typing import Any

from analyzer.models import Evidence, Facts, RawFinding


def detect_protocol_anomalies(
    facts: Facts, settings: dict[str, Any] | None = None
) -> list[RawFinding]:
    """Detect malformed frames, length inconsistencies, and protocol violations."""
    findings: list[RawFinding] = []

    session_anomalies: list[tuple[str, str, int]] = []
    for sess in facts.sessions:
        for msg in sess.messages:
            for anom in msg.anomalies:
                session_anomalies.append((sess.id, anom, msg.pkt_no))

    if session_anomalies:
        evidence_list = [
            Evidence(
                packet_no=pkt,
                ts=0.0,
                message=f"IKE protocol anomaly: {anom}",
                field_path="message.anomalies",
                raw_value=anom,
                decoded=anom,
                hex_excerpt="",
                note=f"Session {sid}",
            )
            for sid, anom, pkt in session_anomalies[:5]
        ]
        unique_sessions = list(dict.fromkeys(sid for sid, _, _ in session_anomalies))

        findings.append(
            RawFinding(
                rule_id="IKE-PROTO-001",
                origin="detector",
                category="Protocol",
                title=f"Malformed IKE structures ({len(session_anomalies)} anomalies detected)",
                explanation=(
                    f"Observed {len(session_anomalies)} structural anomalies in IKE packets, including "
                    "payload length inconsistencies, truncated attributes, or unexpected headers."
                ),
                why_this_matters="Can indicate packet tampering, network corruption, or aggressive fuzzing.",
                impact=2,
                likelihood=3,
                confidence=0.9,
                evidence=evidence_list,
                affected_sessions=unique_sessions,
                count=len(session_anomalies),
                references=["RFC 7296 §1.5", "RFC 2408"],
                recommendation_id="REC-INVESTIGATE-PEER",
            )
        )

    return findings
