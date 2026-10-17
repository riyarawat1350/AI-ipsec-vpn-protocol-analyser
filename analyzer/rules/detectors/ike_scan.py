"""IKE reconnaissance and scanning detector — TASK-027.

Detects:
- IKE-RECON-001: IKE scanning pattern (one source contacting >= 5 distinct hosts in 60s,
  or >= 5 distinct single-transform probes to a host without completing handshakes).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from analyzer.models import Evidence, Facts, RawFinding


def detect_ike_scans(
    facts: Facts, settings: dict[str, Any] | None = None
) -> list[RawFinding]:
    """Detect horizontal and vertical IKE network scanning."""
    cfg = settings or {}
    distinct_hosts_threshold = int(cfg.get("scan_distinct_hosts", 5))
    window_s = float(cfg.get("scan_window_s", 60.0))

    findings: list[RawFinding] = []

    # Map source IP -> list of (ts, responder_ip, pkt_no, session_id, transform_count)
    probes_by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for session in facts.sessions:
        if session.outcome in ("unanswered", "incomplete_capture", "unknown"):
            first_msg = session.messages[0] if session.messages else None
            pkt_no = first_msg.pkt_no if first_msg else 1
            ts = first_msg.ts if first_msg else session.first_ts

            trans_count = 0
            if session.offered:
                trans_count = sum(len(p.transforms) for p in session.offered)

            probes_by_src[session.initiator.ip].append({
                "ts": ts,
                "resp_ip": session.responder.ip,
                "pkt_no": pkt_no,
                "session_id": session.id,
                "trans_count": trans_count,
            })

    for src_ip, probes in probes_by_src.items():
        if not probes:
            continue

        probes.sort(key=lambda x: x["ts"])
        unique_targets = {p["resp_ip"] for p in probes}

        # Case A: Horizontal scan across >= distinct_hosts_threshold targets
        if len(unique_targets) >= distinct_hosts_threshold:
            evidence_list = [
                Evidence(
                    packet_no=p["pkt_no"],
                    ts=p["ts"],
                    message=f"IKE probe from {src_ip} targeting {p['resp_ip']}:500",
                    field_path="session.responder.ip",
                    raw_value=p["resp_ip"],
                    decoded=f"Target: {p['resp_ip']}",
                    hex_excerpt="",
                    note="Scan target",
                )
                for p in probes[:5]
            ]
            sess_ids = [p["session_id"] for p in probes[:15]]

            findings.append(
                RawFinding(
                    rule_id="IKE-RECON-001",
                    origin="detector",
                    category="Reconnaissance",
                    title=f"IKE network scanning pattern detected from {src_ip}",
                    explanation=(
                        f"Host {src_ip} probed {len(unique_targets)} distinct IP addresses on UDP ports "
                        "500/4500 without completing handshakes."
                    ),
                    why_this_matters="Indicates automated reconnaissance searching for vulnerable or responsive VPN endpoints.",
                    impact=2,
                    likelihood=4,
                    confidence=0.8,
                    evidence=evidence_list,
                    affected_sessions=sess_ids,
                    count=len(probes),
                    references=["NIST SP 800-77 Rev. 1 §3.2"],
                    mitre=["T1046"],
                    recommendation_id="REC-RESTRICT-EXPOSURE",
                )
            )
            continue

        # Case B: Vertical scan / algorithm probing against a single host
        # >= 5 single-transform or varied probes to the same host without completion
        for target_ip in unique_targets:
            target_probes = [p for p in probes if p["resp_ip"] == target_ip]
            if len(target_probes) >= 5 and all(p["trans_count"] <= 2 for p in target_probes):
                evidence_list = [
                    Evidence(
                        packet_no=p["pkt_no"],
                        ts=p["ts"],
                        message=f"Single-transform probe to {target_ip}",
                        field_path="session.offered",
                        raw_value=p["trans_count"],
                        decoded=f"{p['trans_count']} transforms",
                        hex_excerpt="",
                        note="Probing cipher/group support",
                    )
                    for p in target_probes[:5]
                ]
                findings.append(
                    RawFinding(
                        rule_id="IKE-RECON-001",
                        origin="detector",
                        category="Reconnaissance",
                        title=f"IKE transform enumeration probe against {target_ip} from {src_ip}",
                        explanation=(
                            f"Host {src_ip} sent {len(target_probes)} minimal or single-transform proposals "
                            f"to {target_ip} to enumerate supported cipher suites."
                        ),
                        why_this_matters="Attackers enumerate supported ciphers to find weak configurations.",
                        impact=2,
                        likelihood=4,
                        confidence=0.8,
                        evidence=evidence_list,
                        affected_sessions=[p["session_id"] for p in target_probes[:10]],
                        count=len(target_probes),
                        references=["NIST SP 800-77 Rev. 1 §3.2"],
                        mitre=["T1046"],
                        recommendation_id="REC-RESTRICT-EXPOSURE",
                    )
                )

    return findings
