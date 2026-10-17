"""Unit tests for heuristic and behavioral detectors — TASK-027.

Tests:
- negotiation.py: IKE-NEG-001, IKE-NEG-002, IKE-NEG-003
- ike_flood.py: IKE-DOS-001, IKE-DOS-002
- ike_scan.py: IKE-RECON-001
- protocol_anomaly.py: IKE-PROTO-001
- Configurable thresholds via settings dictionary
"""

from __future__ import annotations

import pytest
from analyzer.features.facts import build_facts
from analyzer.models import Endpoint, IkeMessage, IkeNotify, IkeProposal, IkeSession, IkeTransform
from analyzer.rules.detectors.ike_flood import detect_ike_floods
from analyzer.rules.detectors.ike_scan import detect_ike_scans
from analyzer.rules.detectors.negotiation import detect_negotiation_anomalies
from analyzer.rules.detectors.protocol_anomaly import detect_protocol_anomalies
from analyzer.scoring.risk import calculate_risk, calculate_severity


def _make_msg(
    pkt_no: int,
    ts: float,
    src_ip: str,
    dst_ip: str,
    exchange_type: int = 34,
    direction: str = "i2r",
    notifies: list[IkeNotify] | None = None,
    anomalies: list[str] | None = None,
    proposals: list[IkeProposal] | None = None,
    ke_len: int | None = None,
) -> IkeMessage:
    return IkeMessage(
        pkt_no=pkt_no,
        ts=ts,
        src=Endpoint(ip=src_ip, port=500),
        dst=Endpoint(ip=dst_ip, port=500),
        natt=False,
        version=2,
        exchange_type=exchange_type,
        exchange_name="IKE_SA_INIT",
        flags=8 if direction == "i2r" else 32,
        message_id=0,
        length=200,
        spi_i="0123456789abcdef",
        spi_r="0000000000000000" if direction == "i2r" else "fedcba9876543210",
        direction="i2r" if direction == "i2r" else "r2i",
        payload_types=[],
        encrypted=False,
        proposals=proposals or [],
        ke_len=ke_len,
        notifies=notifies or [],
        vendor_ids=[],
        nat_detection=[],
        anomalies=anomalies or [],
    )


def test_negotiation_no_proposal_chosen() -> None:
    """IKE-NEG-001 triggers on >= 3 NO_PROPOSAL_CHOSEN notifies, score 30.4 Low."""
    notif = IkeNotify(type=14, name="NO_PROPOSAL_CHOSEN", protocol_id=1, data_len=0)
    msgs = [
        _make_msg(1, 100.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(2, 100.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
        _make_msg(3, 105.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(4, 105.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
        _make_msg(5, 110.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(6, 110.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
    ]
    sess = IkeSession(
        id="sess-neg-1",
        version=2,
        spi_i="0123456789abcdef",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=100.0,
        last_ts=110.1,
        messages=msgs,
        outcome="failed_notify",
    )
    facts = build_facts(sessions=[sess])
    findings = detect_negotiation_anomalies(facts)

    f = next((x for x in findings if x.rule_id == "IKE-NEG-001"), None)
    assert f is not None
    assert f.impact == 2
    assert f.likelihood == 4
    assert f.confidence == 0.9
    risk = calculate_risk(f.impact, f.likelihood, f.confidence)
    assert risk == 30.4
    assert calculate_severity(risk, f.impact) == "Low"
    assert f.recommendation_id == "REC-ALIGN-PROPOSALS"


def test_negotiation_invalid_ke() -> None:
    """IKE-NEG-002 triggers on >= 3 INVALID_KE_PAYLOAD notifies."""
    notif = IkeNotify(type=17, name="INVALID_KE_PAYLOAD", protocol_id=1, data_len=2)
    msgs = [
        _make_msg(1, 100.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(2, 100.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
        _make_msg(3, 102.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(4, 102.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
        _make_msg(5, 104.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(6, 104.1, "10.0.0.2", "10.0.0.1", direction="r2i", notifies=[notif]),
    ]
    sess = IkeSession(
        id="sess-ke-1",
        version=2,
        spi_i="0123456789abcdef",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=100.0,
        last_ts=104.1,
        messages=msgs,
        outcome="failed_notify",
    )
    facts = build_facts(sessions=[sess])
    findings = detect_negotiation_anomalies(facts)

    f = next((x for x in findings if x.rule_id == "IKE-NEG-002"), None)
    assert f is not None
    assert f.impact == 2
    assert f.likelihood == 4


def test_negotiation_unanswered_retransmissions() -> None:
    """IKE-NEG-003 triggers on unanswered session with retransmissions >= 3, score 20.4 Low."""
    msgs = [
        _make_msg(1, 100.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(2, 101.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(3, 103.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
        _make_msg(4, 107.0, "10.0.0.1", "10.0.0.2", direction="i2r"),
    ]
    sess = IkeSession(
        id="sess-unans-1",
        version=2,
        spi_i="0123456789abcdef",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=100.0,
        last_ts=107.0,
        messages=msgs,
        retransmissions=3,
        outcome="unanswered",
    )
    facts = build_facts(sessions=[sess])
    findings = detect_negotiation_anomalies(facts)

    f = next((x for x in findings if x.rule_id == "IKE-NEG-003"), None)
    assert f is not None
    assert f.impact == 2
    assert f.likelihood == 3
    assert f.confidence == 0.7
    risk = calculate_risk(f.impact, f.likelihood, f.confidence)
    assert risk == 20.4
    assert calculate_severity(risk, f.impact) == "Low"
    assert f.recommendation_id == "REC-REACHABILITY"


def test_ike_flood_detector() -> None:
    """IKE-DOS-001 and IKE-DOS-002 trigger on high rate flood without cookie mitigations."""
    sessions = []
    # 150 init requests in 2 seconds (rate 75 req/s > 50 threshold)
    for i in range(150):
        req_msg = _make_msg(i * 2 + 1, 100.0 + (i * 0.01), "192.168.1.50", "10.0.0.1", direction="i2r")
        resp_msg = _make_msg(i * 2 + 2, 100.0 + (i * 0.01) + 0.001, "10.0.0.1", "192.168.1.50",
                             direction="r2i", ke_len=256)
        s = IkeSession(
            id=f"flood-sess-{i}",
            version=2,
            spi_i=f"{i:016x}",
            initiator=Endpoint(ip="192.168.1.50", port=500),
            responder=Endpoint(ip="10.0.0.1", port=500),
            natt=False,
            first_ts=req_msg.ts,
            last_ts=resp_msg.ts,
            messages=[req_msg, resp_msg],
            outcome="unknown",
        )
        sessions.append(s)

    facts = build_facts(sessions=sessions)
    findings = detect_ike_floods(facts)

    # Check DOS-001
    f_dos1 = next((x for x in findings if x.rule_id == "IKE-DOS-001"), None)
    assert f_dos1 is not None
    assert f_dos1.impact == 4
    assert f_dos1.likelihood == 4
    assert f_dos1.confidence == 0.8
    risk1 = calculate_risk(f_dos1.impact, f_dos1.likelihood, f_dos1.confidence)
    assert risk1 == 57.6
    assert calculate_severity(risk1, f_dos1.impact) == "Medium"
    assert "T1498" in f_dos1.mitre

    # Check DOS-002 (no cookie challenge)
    f_dos2 = next((x for x in findings if x.rule_id == "IKE-DOS-002"), None)
    assert f_dos2 is not None
    assert f_dos2.impact == 3
    assert f_dos2.likelihood == 4
    risk2 = calculate_risk(f_dos2.impact, f_dos2.likelihood, f_dos2.confidence)
    assert risk2 == 43.2
    assert calculate_severity(risk2, f_dos2.impact) == "Medium"


def test_ike_scan_detector_horizontal() -> None:
    """IKE-RECON-001 triggers when 1 source probes >= 5 distinct targets, score 28.8 Low."""
    sessions = []
    for i in range(8):
        target_ip = f"10.0.0.{10 + i}"
        req = _make_msg(i + 1, 100.0 + i, "192.168.1.99", target_ip, direction="i2r")
        s = IkeSession(
            id=f"scan-sess-{i}",
            version=2,
            spi_i=f"{i:016x}",
            initiator=Endpoint(ip="192.168.1.99", port=500),
            responder=Endpoint(ip=target_ip, port=500),
            natt=False,
            first_ts=req.ts,
            last_ts=req.ts,
            messages=[req],
            outcome="unanswered",
        )
        sessions.append(s)

    facts = build_facts(sessions=sessions)
    findings = detect_ike_scans(facts)

    f_scan = next((x for x in findings if x.rule_id == "IKE-RECON-001"), None)
    assert f_scan is not None
    assert f_scan.impact == 2
    assert f_scan.likelihood == 4
    assert f_scan.confidence == 0.8
    risk = calculate_risk(f_scan.impact, f_scan.likelihood, f_scan.confidence)
    assert risk == 28.8
    assert calculate_severity(risk, f_scan.impact) == "Low"
    assert "T1046" in f_scan.mitre
    assert f_scan.recommendation_id == "REC-RESTRICT-EXPOSURE"


def test_protocol_anomaly_detector() -> None:
    """IKE-PROTO-001 triggers on parsed packet anomalies."""
    msg = _make_msg(1, 100.0, "10.0.0.1", "10.0.0.2", anomalies=["Header length lie: header says 200, buffer is 50"])
    sess = IkeSession(
        id="anom-sess-1",
        version=2,
        spi_i="0123456789abcdef",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=100.0,
        last_ts=100.0,
        messages=[msg],
        anomalies=["Header length lie: header says 200, buffer is 50"],
        has_anomalies=True,
        outcome="incomplete_capture",
    )
    facts = build_facts(sessions=[sess])
    findings = detect_protocol_anomalies(facts)

    f_proto = next((x for x in findings if x.rule_id == "IKE-PROTO-001"), None)
    assert f_proto is not None
    assert f_proto.impact == 2
    assert f_proto.likelihood == 3
