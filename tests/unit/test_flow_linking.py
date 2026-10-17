"""Tests for flow pairing and IKE session linking — TASK-021."""

from __future__ import annotations

from pathlib import Path
import pytest

from analyzer.capture.reader import CaptureReader
from analyzer.capture.decode import PacketDecoder
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.sessions import IkeSessionReconstructor, ikemessage_to_model
from analyzer.esp.tracker import FlowTracker, parse_esp_packet
from analyzer.esp.linking import pair_flows, link_flows_to_ike_sessions
from analyzer.models import Endpoint, FlowSeqStats, IkeSession, IpsecFlow

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def _make_flow(
    flow_id: str,
    src: str,
    dst: str,
    spi: str,
    proto: str = "esp",
    encap: str = "raw",
    first_ts: float = 1000.0,
) -> IpsecFlow:
    return IpsecFlow(
        id=flow_id,
        proto=proto,  # type: ignore[arg-type]
        src=src,
        dst=dst,
        spi=spi,
        encap=encap,  # type: ignore[arg-type]
        first_ts=first_ts,
        last_ts=first_ts + 10.0,
        packets=5,
        bytes=500,
        seq=FlowSeqStats(max_seq=5),
    )


def test_flow_pairing() -> None:
    f1 = _make_flow("f1", "10.0.0.1", "10.0.0.2", "11111111", encap="raw")
    f2 = _make_flow("f2", "10.0.0.2", "10.0.0.1", "22222222", encap="raw")
    f3 = _make_flow("f3", "192.168.1.1", "192.168.1.2", "33333333", encap="raw")

    flows = [f1, f2, f3]
    pair_flows(flows)

    assert f1.paired_flow_id == "f2"
    assert f2.paired_flow_id == "f1"
    assert f3.paired_flow_id is None


def test_ike_session_linking_and_confidence() -> None:
    session = IkeSession(
        id="s1",
        version=2,
        spi_i="deadbeef00000001",
        spi_r="cafebabe00000002",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=1000.0,
        last_ts=1001.0,
        outcome="established_observed",
    )

    # Matching flow
    flow_matched = _make_flow("f_match", "10.0.0.1", "10.0.0.2", "aaaaaaaa", first_ts=1002.0)
    # Unmatched flow (different IPs)
    flow_unmatched = _make_flow("f_unmatch", "192.168.100.1", "192.168.100.2", "bbbbbbbb", first_ts=1002.0)

    flows = [flow_matched, flow_unmatched]
    link_flows_to_ike_sessions(flows, [session])

    assert flow_matched.linked_ike_session_id == "s1"
    assert flow_matched.link_confidence is not None
    assert flow_matched.link_confidence <= 0.7  # Must not exceed 0.7

    assert flow_unmatched.linked_ike_session_id is None
    assert flow_unmatched.link_confidence is None


def test_fixture_mixed_ikev2_esp_linking() -> None:
    pcap_path = FIXTURES_DIR / "mixed_ikev2_esp.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    rec = IkeSessionReconstructor()
    tracker = FlowTracker()

    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if not parsed:
            continue
        if parsed.ip_proto == 17 and (parsed.sport in (500, 4500) or parsed.dport in (500, 4500)):
            if parsed.payload:
                ike_msg = parse_ikev2(parsed.payload)
                if ike_msg:
                    model = ikemessage_to_model(
                        ike_msg,
                        pkt_no=frame.pkt_no,
                        ts=frame.ts,
                        src_ip=parsed.src,
                        src_port=parsed.sport or 500,
                        dst_ip=parsed.dst,
                        dst_port=parsed.dport or 500,
                    )
                    rec.process_message(model)
        elif parsed.ip_proto == 50 and parsed.payload:
            esp = parse_esp_packet(parsed.payload)
            if esp:
                spi, seq, inner = esp
                tracker.process_esp(
                    src=parsed.src,
                    dst=parsed.dst,
                    spi=spi,
                    seq=seq,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    packet_len=len(parsed.payload),
                    payload_prefix=inner[:64],
                )

    sessions = rec.get_sessions()
    flows = tracker.get_flows()

    assert len(sessions) >= 1
    assert len(flows) >= 1

    link_flows_to_ike_sessions(flows, sessions)
    for flow in flows:
        if flow.linked_ike_session_id:
            assert flow.link_confidence is not None
            assert flow.link_confidence <= 0.7
