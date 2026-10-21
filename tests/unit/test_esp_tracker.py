"""Tests for ESP and AH tracker — TASK-019."""

from __future__ import annotations

from pathlib import Path

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.reader import CaptureReader
from analyzer.esp.ah import parse_ah_header
from analyzer.esp.tracker import FlowTracker, parse_esp_packet

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def test_esp_normal_sequential() -> None:
    tracker = FlowTracker()
    for seq in range(1, 11):
        tracker.process_esp(
            src="10.0.0.1",
            dst="10.0.0.2",
            spi=0x12345678,
            seq=seq,
            pkt_no=seq,
            ts=100.0 + seq,
            packet_len=100,
            payload_prefix=b"\x00" * 32,
        )

    flows = tracker.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.packets == 10
    assert f.seq.max_seq == 10
    assert len(f.seq.gaps) == 0
    assert f.seq.duplicates == 0
    assert f.seq.reorders == 0
    assert f.seq.wrap_near is False


def test_esp_gaps_duplicates_reorders() -> None:
    tracker = FlowTracker()
    # 1, 2, 5 (gap 3-4), 2 (dup + reorder), 6 (normal), 4 (reorder)
    seqs = [1, 2, 5, 2, 6, 4]
    for i, seq in enumerate(seqs):
        tracker.process_esp(
            src="10.0.0.1",
            dst="10.0.0.2",
            spi="aabbccdd",
            seq=seq,
            pkt_no=i + 1,
            ts=10.0 + i,
            packet_len=64,
            payload_prefix=b"\x11" * 16,
        )

    flows = tracker.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.seq.max_seq == 6
    assert len(f.seq.gaps) >= 1
    assert f.seq.duplicates >= 1
    assert f.seq.reorders >= 1


def test_esp_wrap_near() -> None:
    tracker = FlowTracker()
    tracker.process_esp(
        src="1.1.1.1",
        dst="2.2.2.2",
        spi=0x11111111,
        seq=0xFFFFFF50,
        pkt_no=1,
        ts=1.0,
        packet_len=100,
        payload_prefix=b"",
    )
    flows = tracker.get_flows()
    assert flows[0].seq.wrap_near is True


def test_esp_memory_bounded() -> None:
    tracker = FlowTracker()
    # Process 2000 packets with occasional gaps
    for i in range(1, 2001):
        seq = i if i % 10 != 0 else i + 2  # create occasional gaps
        tracker.process_esp(
            src="10.0.0.1",
            dst="10.0.0.2",
            spi=0x99999999,
            seq=seq,
            pkt_no=i,
            ts=1.0 + i * 0.01,
            packet_len=80,
            payload_prefix=b"\xab" * 100,
        )

    state = list(tracker.flows.values())[0]
    # Memory caps:
    assert len(state._recent_deque) <= 1024
    assert len(state.gaps) <= 200
    assert len(state.sample_pkt_nos) <= 50
    assert len(state.sample_payload_prefixes) <= 50
    assert len(state.downsampled_points) <= 500


def test_ah_header_parsing() -> None:
    # Next Header: 6 (TCP), Payload Len: 4 ((4+2)*4 = 24 bytes), Reserved: 0
    # SPI: 0x12345678, Seq: 42, ICV: 12 bytes
    import struct
    ah_hdr = struct.pack(">BBHII", 6, 4, 0, 0x12345678, 42) + (b"\xcc" * 12) + b"HELLO_INNER"
    parsed = parse_ah_header(ah_hdr)
    assert parsed is not None
    assert parsed.next_header == 6
    assert parsed.spi_hex == "12345678"
    assert parsed.seq == 42
    assert parsed.payload == b"HELLO_INNER"


def test_fixture_esp_seq_anomalies() -> None:
    pcap_path = FIXTURES_DIR / "esp_seq_anomalies.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    tracker = FlowTracker()

    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.ip_proto == 50 and parsed.payload:
            esp_parsed = parse_esp_packet(parsed.payload)
            if esp_parsed:
                spi, seq, inner = esp_parsed
                tracker.process_esp(
                    src=parsed.src,
                    dst=parsed.dst,
                    spi=spi,
                    seq=seq,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    packet_len=len(parsed.payload),
                    payload_prefix=inner[:64],
                    encap="raw",
                )

    flows = tracker.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.packets == 8
    assert f.seq.max_seq == 8
    assert len(f.seq.gaps) == 1
    assert f.seq.gaps[0] == (4, 5, 4)  # gap 4-5 at pkt_no 4
    assert f.seq.duplicates >= 1
    assert f.seq.reorders >= 1


def test_fixture_esp_flow() -> None:
    pcap_path = FIXTURES_DIR / "esp_flow.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    tracker = FlowTracker()

    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.ip_proto == 50 and parsed.payload:
            esp_parsed = parse_esp_packet(parsed.payload)
            if esp_parsed:
                spi, seq, inner = esp_parsed
                tracker.process_esp(
                    src=parsed.src,
                    dst=parsed.dst,
                    spi=spi,
                    seq=seq,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    packet_len=len(parsed.payload),
                    payload_prefix=inner[:64],
                    encap="raw",
                )

    flows = tracker.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.packets == 10
    assert f.seq.max_seq == 10
    assert len(f.seq.gaps) == 0
    assert f.seq.duplicates == 0
    assert f.seq.reorders == 0
