"""Tests for ESP-NULL heuristic detection — TASK-020."""

from __future__ import annotations

import os
import struct
from pathlib import Path

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.reader import CaptureReader
from analyzer.esp.null_heuristic import (
    check_esp_null,
    is_candidate_null_packet,
    verify_ipv4_checksum,
)
from analyzer.esp.tracker import parse_esp_packet

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def _make_ipv4_packet() -> bytes:
    """Build a minimal valid 20-byte IPv4 packet with valid checksum."""
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20
    ident = 1234
    flags_frag = 0
    ttl = 64
    proto = 6  # TCP
    src = (10 << 24) | (1 << 16) | (0 << 8) | 1
    dst = (10 << 24) | (1 << 16) | (0 << 8) | 2

    # Checksum 0 initially
    hdr_no_cksum = struct.pack(">BBHHHBBHII", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src, dst)
    words = struct.unpack(">10H", hdr_no_cksum)
    s = sum(words)
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    cksum = (~s) & 0xFFFF
    return struct.pack(">BBHHHBBHII", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, cksum, src, dst)


def test_ipv4_checksum_validation() -> None:
    pkt = _make_ipv4_packet()
    assert verify_ipv4_checksum(pkt) is True

    # Corrupt a byte
    corrupt = bytearray(pkt)
    corrupt[10] ^= 0xFF
    assert verify_ipv4_checksum(bytes(corrupt)) is False


def test_tunnel_ipv4_detected() -> None:
    pkt = _make_ipv4_packet()
    is_cand, mode = is_candidate_null_packet(pkt)
    assert is_cand is True
    assert mode == "tunnel (inferred)"


def test_fixture_esp_null() -> None:
    pcap_path = FIXTURES_DIR / "esp_null.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    prefixes = []

    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.ip_proto == 50 and parsed.payload:
            esp = parse_esp_packet(parsed.payload)
            if esp:
                _, _, inner = esp
                prefixes.append(inner[:64])

    assert len(prefixes) >= 10
    result = check_esp_null(prefixes)
    assert result.null_suspected is True
    assert result.confidence == 0.85
    assert result.inferred_mode is not None


def test_random_encrypted_bytes_zero_false_positives() -> None:
    """Test 1,000 simulated flows with random bytes (AES encrypted payload simulation)."""
    false_positives = 0
    total_flows = 1000

    for _flow_idx in range(total_flows):
        # 15 packets per flow with random 64-byte payload
        sample_prefixes = [os.urandom(64) for _ in range(15)]
        result = check_esp_null(sample_prefixes)
        if result.null_suspected:
            false_positives += 1

    assert false_positives == 0


def test_under_minimum_packets() -> None:
    sample_prefixes = [b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"] * 5
    result = check_esp_null(sample_prefixes)
    assert result.null_suspected is False
