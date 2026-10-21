"""IKE SA_INIT flood detector — TASK-027.

Detects:
- IKE-DOS-001: SA_INIT flood (high request rate sustained over time).
- IKE-DOS-002: No cookie challenge under load (responder generates full cryptographic
  replies instead of stateless cookie challenges).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from analyzer.models import Evidence, Facts, RawFinding


def detect_ike_floods(
    facts: Facts, settings: dict[str, Any] | None = None
) -> list[RawFinding]:
    """Detect IKE SA_INIT floods and missing COOKIE mitigation."""
    cfg = settings or {}
    rate_per_source = float(cfg.get("flood_rate_per_source", 50.0))
    min_total_reqs = int(cfg.get("flood_min_requests", 100))

    findings: list[RawFinding] = []

    # Map source IP -> list of init message timestamps & packet numbers
    src_inits: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
    responder_replies: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for session in facts.sessions:
        for msg in session.messages:
            # IKEv2 SA_INIT (34) or IKEv1 Main Mode (2) or Aggressive Mode (4) message 1
            if msg.direction == "i2r" and msg.exchange_type in (34, 2, 4):
                src_inits[session.initiator.ip].append((msg.ts, msg.pkt_no, session.id))
            elif msg.direction == "r2i" and msg.exchange_type in (34, 2, 4):
                has_cookie = any(
                    n.type == 16390 or "COOKIE" in n.name.upper()
                    for n in msg.notifies
                )
                has_ke = msg.ke_len is not None or msg.ke_group is not None or len(msg.proposals) > 0
                responder_replies[session.responder.ip].append({
                    "ts": msg.ts,
                    "pkt_no": msg.pkt_no,
                    "session_id": session.id,
                    "has_cookie": has_cookie,
                    "has_ke": has_ke,
                })

    for src_ip, inits in src_inits.items():
        total_inits = len(inits)
        if total_inits < min_total_reqs:
            continue

        timestamps = [t for t, _, _ in inits]
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        duration = max(0.1, max_ts - min_ts)
        rate = total_inits / duration

        if rate >= rate_per_source:
            evidence_list = [
                Evidence(
                    packet_no=pkt,
                    ts=t,
                    message=f"IKE SA_INIT request from {src_ip} ({rate:.1f} req/s)",
                    field_path="message.exchange_type",
                    raw_value=34,
                    decoded="IKE_SA_INIT",
                    hex_excerpt="",
                    note=f"Sample {idx + 1} of {total_inits}",
                )
                for idx, (t, pkt, _) in enumerate(inits[:5])
            ]
            sess_ids = list(dict.fromkeys(sid for _, _, sid in inits))[:20]

            findings.append(
                RawFinding(
                    rule_id="IKE-DOS-001",
                    origin="detector",
                    category="Denial of Service",
                    title=f"IKE SA_INIT flood detected from {src_ip} ({rate:.1f} req/s)",
                    explanation=(
                        f"Detected {total_inits} SA_INIT handshake requests from {src_ip} in "
                        f"{duration:.1f}s (rate {rate:.1f} req/s, threshold {rate_per_source} req/s)."
                    ),
                    why_this_matters="Floods exhaust cryptographic coprocessors and half-open SA state tables.",
                    impact=4,
                    likelihood=4,
                    confidence=0.8,
                    evidence=evidence_list,
                    affected_sessions=sess_ids,
                    count=total_inits,
                    references=["RFC 7296 §2.6", "NIST SP 800-77 Rev. 1"],
                    mitre=["T1498"],
                    recommendation_id="REC-COOKIES-RATELIMIT",
                )
            )

            # Check if responder sent full responses without COOKIE challenges
            for resp_ip, replies in responder_replies.items():
                if len(replies) >= 10:
                    cookie_count = sum(1 for r in replies if r["has_cookie"])
                    ke_count = sum(1 for r in replies if r["has_ke"])
                    if cookie_count == 0 and ke_count > 0:
                        resp_evidence = [
                            Evidence(
                                packet_no=r["pkt_no"],
                                ts=r["ts"],
                                message="Full SA_INIT response without COOKIE challenge",
                                field_path="message.notifies",
                                raw_value="0 (no notifies)",
                                decoded="No COOKIE notify present in SA_INIT response",
                                hex_excerpt="00",
                                note="Responder unmitigated under flood",
                            )
                            for r in replies[:5]
                        ]
                        findings.append(
                            RawFinding(
                                rule_id="IKE-DOS-002",
                                origin="detector",
                                category="Denial of Service",
                                title=f"No cookie challenge under load by responder {resp_ip}",
                                explanation=(
                                    f"During SA_INIT flood, responder {resp_ip} computed full cryptographic "
                                    f"responses (KE present) without issuing stateless COOKIE challenges."
                                ),
                                why_this_matters="Responder is vulnerable to complete resource exhaustion by spoofed requests.",
                                impact=3,
                                likelihood=4,
                                confidence=0.8,
                                evidence=resp_evidence,
                                affected_sessions=[r["session_id"] for r in replies[:10]],
                                count=len(replies),
                                references=["RFC 7296 §2.6", "RFC 7296 §2.6.1"],
                                recommendation_id="REC-COOKIES-RATELIMIT",
                            )
                        )

    return findings
