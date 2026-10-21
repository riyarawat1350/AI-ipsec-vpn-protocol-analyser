"""Unit tests for protocol classifier (TASK-010)."""

from __future__ import annotations

import pytest

from analyzer.classify.classifier import Protocol, ProtocolClassifier
from analyzer.features.facts import build_facts_from_classifier
from analyzer.models import DecodedPacket

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_pkt(
    pkt_no: int = 1,
    ts: float = 1.0,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    ip_proto: int = 17,
    sport: int | None = 500,
    dport: int | None = 500,
    payload: bytes = b"\x00" * 28,
) -> DecodedPacket:
    return DecodedPacket(
        pkt_no=pkt_no, ts=ts, src=src, dst=dst,
        ip_proto=ip_proto, sport=sport, dport=dport,
        payload=payload, reassembled=False,
    )


def _ike_payload(major: int = 2) -> bytes:
    """Minimal 28-byte IKE header with the given major version."""
    # Bytes 0-7: initiator SPI, 8-15: responder SPI, 16: next_payload, 17: ver
    spi_i = b"\x01" * 8
    spi_r = b"\x00" * 8
    next_payload = b"\x00"
    version = bytes([(major << 4) | 0])
    rest = b"\x00" * 8  # exchange_type, flags, msg_id, length
    return spi_i + spi_r + next_payload + version + rest


# ---------------------------------------------------------------------------
# Protocol bucket classification
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_classify_ikev2_port500():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=17, sport=500, dport=500, payload=_ike_payload(2))
    bucket = clf.process(pkt)
    assert bucket == Protocol.IKEv2


@pytest.mark.unit
def test_classify_ikev1_port500():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=17, sport=500, dport=500, payload=_ike_payload(1))
    bucket = clf.process(pkt)
    assert bucket == Protocol.IKEv1


@pytest.mark.unit
def test_classify_esp_raw():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=50, sport=None, dport=None, payload=b"\xde\xad" * 16)
    bucket = clf.process(pkt)
    assert bucket == Protocol.ESP


@pytest.mark.unit
def test_classify_ah():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=51, sport=None, dport=None, payload=b"\x00" * 20)
    bucket = clf.process(pkt)
    assert bucket == Protocol.AH


@pytest.mark.unit
def test_classify_natt_keepalive():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=17, sport=4500, dport=4500, payload=b"\xff")
    bucket = clf.process(pkt)
    assert bucket == Protocol.KEEPALIVE


@pytest.mark.unit
def test_classify_natt_esp():
    """NAT-T encapsulated ESP (SPI ≠ 0 on port 4500)."""
    clf = ProtocolClassifier()
    # SPI = 0xdeadbeef (non-zero → ESP encapsulated in NAT-T)
    payload = b"\xde\xad\xbe\xef" + b"\x00" * 20
    pkt = make_pkt(ip_proto=17, sport=4500, dport=4500, payload=payload)
    bucket = clf.process(pkt)
    assert bucket == Protocol.NAT_T


@pytest.mark.unit
def test_classify_natt_ike():
    """NAT-T encapsulated IKE (SPI = 0x00000000 on port 4500)."""
    clf = ProtocolClassifier()
    # 4 zero bytes (non-ESP marker) + IKEv2 header
    payload = b"\x00\x00\x00\x00" + _ike_payload(2)
    pkt = make_pkt(ip_proto=17, sport=4500, dport=4500, payload=payload)
    bucket = clf.process(pkt)
    assert bucket == Protocol.IKEv2


@pytest.mark.unit
def test_classify_other_udp():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=17, sport=1234, dport=5678, payload=b"\x00" * 10)
    bucket = clf.process(pkt)
    assert bucket == Protocol.OTHER_UDP


@pytest.mark.unit
def test_classify_other_tcp():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=6, sport=443, dport=12345, payload=b"\x00" * 10)
    bucket = clf.process(pkt)
    assert bucket == Protocol.OTHER_TCP


@pytest.mark.unit
def test_classify_other_ip():
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=1, sport=None, dport=None, payload=b"\x00" * 8)  # ICMP
    bucket = clf.process(pkt)
    assert bucket == Protocol.OTHER_IP


# ---------------------------------------------------------------------------
# Accumulation statistics
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_total_packets_and_bytes():
    clf = ProtocolClassifier()
    for i in range(5):
        clf.process(make_pkt(pkt_no=i, ip_proto=50, sport=None, dport=None, payload=b"X" * 10))
    r = clf.result()
    assert r.total_packets == 5
    assert r.total_bytes == 50


@pytest.mark.unit
def test_first_last_timestamps():
    clf = ProtocolClassifier()
    clf.process(make_pkt(ts=1.0, pkt_no=1))
    clf.process(make_pkt(ts=5.0, pkt_no=2))
    clf.process(make_pkt(ts=3.0, pkt_no=3))
    r = clf.result()
    assert r.first_ts == pytest.approx(1.0)
    assert r.last_ts == pytest.approx(5.0)
    assert r.duration_seconds() == pytest.approx(4.0)


@pytest.mark.unit
def test_top_talkers():
    clf = ProtocolClassifier()
    # src="10.0.0.1" sends 3 packets, "10.0.0.2" sends 1
    for i in range(3):
        clf.process(make_pkt(pkt_no=i, src="10.0.0.1"))
    clf.process(make_pkt(pkt_no=4, src="10.0.0.2"))

    top = clf.result().top_talkers(2)
    assert top[0].ip == "10.0.0.1"
    assert top[0].packets == 3
    assert top[1].ip == "10.0.0.2"
    assert top[1].packets == 1


@pytest.mark.unit
def test_top_ports():
    clf = ProtocolClassifier()
    for _ in range(3):
        clf.process(make_pkt(pkt_no=1, sport=500, dport=500))
    clf.process(make_pkt(pkt_no=2, sport=4500, dport=4500, payload=b"\xff"))

    top = clf.result().top_ports(5)
    port_map = {p.port: p.packets for p in top}
    assert port_map.get(500, 0) >= 3


@pytest.mark.unit
def test_protocol_distribution_sums_to_one():
    clf = ProtocolClassifier()
    clf.process(make_pkt(ip_proto=50, sport=None, dport=None))    # ESP
    clf.process(make_pkt(ip_proto=51, sport=None, dport=None))    # AH
    clf.process(make_pkt(ip_proto=17, sport=500, dport=500, payload=_ike_payload(2)))  # IKEv2
    dist = clf.result().protocol_distribution()
    total = sum(dist.values())
    assert total == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Facts integration
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_build_facts_from_classifier():
    clf = ProtocolClassifier()
    clf.process(make_pkt(ip_proto=50, sport=None, dport=None))
    clf.process(make_pkt(ip_proto=17, sport=500, dport=500, payload=_ike_payload(2)))

    facts = build_facts_from_classifier(clf.result())
    assert facts.capture["total_packets"] == 2
    assert "esp" in facts.protocol_stats["counts"]
    assert "ikev2" in facts.protocol_stats["counts"]
    assert facts.sessions == []
    assert facts.flows == []


@pytest.mark.unit
def test_ike_short_payload_classified_unknown():
    """Payload too short to inspect IKE version → IKE_UNKNOWN."""
    clf = ProtocolClassifier()
    pkt = make_pkt(ip_proto=17, sport=500, dport=500, payload=b"\x00" * 5)
    bucket = clf.process(pkt)
    assert bucket == Protocol.IKE_UNKNOWN
