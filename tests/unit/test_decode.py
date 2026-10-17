"""Unit tests for L2-L4 packet decoder (TASK-008)."""

import socket
import struct

import pytest

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.linktypes import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW_IP_101,
)
from analyzer.capture.reader import RawFrame


def build_ipv4_udp_payload(src_ip="192.168.1.10", dst_ip="192.168.1.1", sport=500, dport=500, data=b"IKE_DATA"):
    """Build raw IPv4 header + UDP header + data."""
    # IPv4 header: ver_ihl(1), tos(1), total_len(2), id(2), flags_frag(2), ttl(1), proto(1), csum(2), src(4), dst(4)
    udp_len = 8 + len(data)
    total_len = 20 + udp_len
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 1234, 0x4000, 64, 17, 0, src_bytes, dst_bytes)
    udp_hdr = struct.pack(">HHHH", sport, dport, udp_len, 0)
    return ip_hdr + udp_hdr + data


@pytest.mark.unit
def test_decode_standard_ethernet():
    """Verify decoding of standard Ethernet frame with IPv4 and UDP."""
    l3_l4 = build_ipv4_udp_payload(sport=500, dport=500, data=b"PAYLOAD_ETH")
    # Ethernet header: dst_mac(6), src_mac(6), ethertype(2)=0x0800
    eth_hdr = b"\x00" * 6 + b"\x11" * 6 + struct.pack(">H", 0x0800)
    raw_packet = eth_hdr + l3_l4

    frame = RawFrame(pkt_no=1, ts=100.0, linktype=LINKTYPE_ETHERNET, raw_bytes=raw_packet, orig_len=len(raw_packet))
    decoder = PacketDecoder()
    pkt = decoder.decode(frame)

    assert pkt is not None
    assert pkt.pkt_no == 1
    assert pkt.src == "192.168.1.10"
    assert pkt.dst == "192.168.1.1"
    assert pkt.ip_proto == 17
    assert pkt.sport == 500
    assert pkt.dport == 500
    assert pkt.payload == b"PAYLOAD_ETH"


@pytest.mark.unit
def test_decode_vlan_and_qinq():
    """Verify decoding of 802.1Q single VLAN and QinQ double-tagged VLAN frames (FR-10)."""
    l3_l4 = build_ipv4_udp_payload(sport=4500, dport=4500, data=b"VLAN_PAYLOAD")
    decoder = PacketDecoder()

    # 1. Single VLAN (0x8100)
    # eth_hdr(12), tpid(2)=0x8100, tci(2)=100, ethertype(2)=0x0800
    vlan_frame_bytes = b"\x00" * 12 + struct.pack(">HHH", 0x8100, 100, 0x0800) + l3_l4
    f1 = RawFrame(pkt_no=1, ts=101.0, linktype=LINKTYPE_ETHERNET, raw_bytes=vlan_frame_bytes, orig_len=len(vlan_frame_bytes))
    pkt1 = decoder.decode(f1)
    assert pkt1 is not None
    assert pkt1.payload == b"VLAN_PAYLOAD"

    # 2. QinQ stacked VLAN (0x88A8 then 0x8100)
    qinq_frame_bytes = b"\x00" * 12 + struct.pack(">HHHHH", 0x88A8, 200, 0x8100, 100, 0x0800) + l3_l4
    f2 = RawFrame(pkt_no=2, ts=102.0, linktype=LINKTYPE_ETHERNET, raw_bytes=qinq_frame_bytes, orig_len=len(qinq_frame_bytes))
    pkt2 = decoder.decode(f2)
    assert pkt2 is not None
    assert pkt2.payload == b"VLAN_PAYLOAD"


@pytest.mark.unit
def test_decode_linux_sll_and_sll2():
    """Verify decoding of Linux Cooked SLL (v1) and SLL2 (v2) frames."""
    l3_l4 = build_ipv4_udp_payload(data=b"SLL_DATA")
    decoder = PacketDecoder()

    # SLL v1 (16 bytes): pkt_type(2), arphrd(2), addr_len(2), addr(8), proto(2)=0x0800
    sll_bytes = struct.pack(">HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + l3_l4
    f_sll = RawFrame(pkt_no=1, ts=100.0, linktype=LINKTYPE_LINUX_SLL, raw_bytes=sll_bytes, orig_len=len(sll_bytes))
    pkt_sll = decoder.decode(f_sll)
    assert pkt_sll is not None
    assert pkt_sll.payload == b"SLL_DATA"

    # SLL2 v2 (20 bytes): proto(2)=0x0800, res(2), ifindex(4), arphrd(2), pkt_type(1), addr_len(1), addr(8)
    sll2_bytes = struct.pack(">HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x00" * 8) + l3_l4
    f_sll2 = RawFrame(pkt_no=2, ts=101.0, linktype=LINKTYPE_LINUX_SLL2, raw_bytes=sll2_bytes, orig_len=len(sll2_bytes))
    pkt_sll2 = decoder.decode(f_sll2)
    assert pkt_sll2 is not None
    assert pkt_sll2.payload == b"SLL_DATA"


@pytest.mark.unit
def test_decode_raw_ip_and_loopback():
    """Verify decoding of Raw IP (LINKTYPE 101) and Loopback NULL (LINKTYPE 0)."""
    l3_l4 = build_ipv4_udp_payload(data=b"RAW_DATA")
    decoder = PacketDecoder()

    # Raw IP (no L2 header)
    f_raw = RawFrame(pkt_no=1, ts=100.0, linktype=LINKTYPE_RAW_IP_101, raw_bytes=l3_l4, orig_len=len(l3_l4))
    pkt_raw = decoder.decode(f_raw)
    assert pkt_raw is not None
    assert pkt_raw.payload == b"RAW_DATA"

    # Loopback (4-byte family = 2 for AF_INET)
    loopback_bytes = struct.pack("=I", 2) + l3_l4
    f_loop = RawFrame(pkt_no=2, ts=101.0, linktype=LINKTYPE_NULL, raw_bytes=loopback_bytes, orig_len=len(loopback_bytes))
    pkt_loop = decoder.decode(f_loop)
    assert pkt_loop is not None
    assert pkt_loop.payload == b"RAW_DATA"


@pytest.mark.unit
def test_unsupported_linktype_recorded_once():
    """Verify unsupported link types return None and are recorded once without duplicate warnings."""
    decoder = PacketDecoder()
    dummy_frame = RawFrame(pkt_no=1, ts=100.0, linktype=99999, raw_bytes=b"\x00" * 50, orig_len=50)

    res1 = decoder.decode(dummy_frame)
    res2 = decoder.decode(dummy_frame)

    assert res1 is None
    assert res2 is None
    assert 99999 in decoder.unsupported_linktypes
    assert len(decoder.unsupported_linktypes) == 1
