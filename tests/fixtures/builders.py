"""Byte-level packet builders for IKEv1, IKEv2, ESP, AH, NAT-T, fragmentation.

All builders are deterministic — no random.random(); use explicit seed where
randomness is needed. Suitable for generating the fixture corpus with
generate_fixtures.py.

TASK-011 — FR-20, FR-21, FR-22, FR-23, FR-25..FR-29.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

# ─────────────────────────────────────────────────────────────────────────────
# IKE Exchange type constants
# ─────────────────────────────────────────────────────────────────────────────
IKEv2_SA_INIT = 34
IKEv2_AUTH = 35
IKEv2_CREATE_CHILD_SA = 36
IKEv2_INFORMATIONAL = 37

IKEv1_MAIN = 2
IKEv1_AGGRESSIVE = 4
IKEv1_INFO = 5
IKEv1_QUICK = 32

# IKEv2 payload types
PL_SA = 33
PL_KE = 34
PL_NONCE = 40
PL_NOTIFY = 41
PL_VENDOR = 43
PL_SK = 46
PL_NONE = 0

# IKEv1 payload types
PL_V1_SA = 1
PL_V1_KE = 4
PL_V1_ID = 5
PL_V1_HASH = 8
PL_V1_NONCE = 10
PL_V1_VID = 13
PL_V1_NONE = 0

# IKEv2 flags
FLAG_INITIATOR = 0x08
FLAG_RESPONSE = 0x20

# IKEv1 flags
FLAG_V1_ENCRYPTION = 0x01


# ─────────────────────────────────────────────────────────────────────────────
# Helper: generic payload wrapper
# ─────────────────────────────────────────────────────────────────────────────

def _wrap_payload(next_type: int, payload_body: bytes) -> bytes:
    """Prepend IKE generic payload header (4 bytes: next, critical, length)."""
    total = 4 + len(payload_body)
    return struct.pack(">BBH", next_type, 0, total) + payload_body


def _chain_payloads(payloads: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """Chain a list of (payload_type, body) pairs with proper next-payload links.

    Returns (first_payload_type, concatenated_bytes).
    """
    if not payloads:
        return PL_NONE, b""
    result = b""
    for i, (_ptype, body) in enumerate(payloads):
        next_type = payloads[i + 1][0] if i + 1 < len(payloads) else PL_NONE
        result += _wrap_payload(next_type, body)
    return payloads[0][0], result


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 header builder
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_header(
    spi_i: bytes = b"\x01" * 8,
    spi_r: bytes = b"\x00" * 8,
    next_payload: int = PL_NONE,
    flags: int = FLAG_INITIATOR,
    exchange_type: int = IKEv2_SA_INIT,
    message_id: int = 0,
    body: bytes = b"",
) -> bytes:
    """Build a complete IKEv2 packet (header + body)."""
    length = 28 + len(body)
    header = (
        spi_i
        + spi_r
        + struct.pack(">BBII", next_payload, 0x20, flags, message_id)
        # version=0x20 (major=2, minor=0)
    )
    # Re-pack correctly: next_payload(1), version(1), exch_type(1), flags(1), msg_id(4), length(4)
    header = (
        spi_i
        + spi_r
        + bytes([next_payload, 0x20, exchange_type, flags])
        + struct.pack(">II", message_id, length)
    )
    return header + body


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 transform / proposal / SA
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_transform(transform_type: int, transform_id: int, key_length: int | None = None) -> bytes:
    """Build an IKEv2 Transform substructure (RFC 7296 §3.3.2)."""
    attr = b""
    if key_length is not None:
        # TV attribute: type=14 (Key Length), value=key_length
        attr = struct.pack(">HH", 0x800E, key_length)
    body = struct.pack(">BBH", transform_type, 0, transform_id) + attr
    total = 4 + len(body)
    last_more = 0  # 0=last, 3=more; caller sets
    return struct.pack(">BBH", last_more, 0, total) + body


def build_ikev2_proposal(
    proposal_num: int = 1,
    protocol_id: int = 1,  # 1=IKE, 3=ESP
    transforms: list[bytes] | None = None,
) -> bytes:
    """Build an IKEv2 Proposal substructure (RFC 7296 §3.3.1)."""
    if transforms is None:
        transforms = []
    # Fix last/more bits
    fixed_transforms = []
    for i, t in enumerate(transforms):
        more = 3 if i < len(transforms) - 1 else 0
        fixed_transforms.append(bytes([more]) + t[1:])
    transform_data = b"".join(fixed_transforms)

    # redo: last(1), reserved(1), proposal_len(2), proposal_num(1), proto_id(1), spi_size(1), num_transforms(1)
    spi_size = 0
    total = 8 + len(transform_data)
    last_more = 0
    return struct.pack(">BBH BBBB",
        last_more, 0, total,
        proposal_num, protocol_id, spi_size, len(transforms)
    ) + transform_data


def build_ikev2_sa_payload(proposals: list[bytes]) -> bytes:
    """Build IKEv2 SA payload body from list of proposal bytes."""
    fixed = []
    for i, p in enumerate(proposals):
        more = 2 if i < len(proposals) - 1 else 0
        fixed.append(bytes([more]) + p[1:])
    return b"".join(fixed)


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 KE payload
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_ke(dh_group: int = 14, key_data: bytes | None = None) -> bytes:
    """Build IKEv2 KE payload body (RFC 7296 §3.4)."""
    if key_data is None:
        # DH group 14 = 2048-bit = 256 bytes of zeros (placeholder)
        key_data = b"\x00" * 256
    return struct.pack(">HH", dh_group, 0) + key_data


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Nonce payload
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_nonce(nonce: bytes | None = None) -> bytes:
    """Build IKEv2 Nonce payload body (16–256 bytes per RFC 7296 §3.9)."""
    if nonce is None:
        nonce = b"\xab\xcd\xef\x01" * 4  # deterministic 16 bytes
    return nonce


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Notify payload
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_notify(notify_type: int, protocol_id: int = 0, spi: bytes = b"", data: bytes = b"") -> bytes:
    """Build IKEv2 Notify payload body (RFC 7296 §3.10)."""
    return struct.pack(">BBH", protocol_id, len(spi), notify_type) + spi + data


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Vendor-ID payload
# ─────────────────────────────────────────────────────────────────────────────

def build_vendor_id(vid_bytes: bytes) -> bytes:
    """Vendor-ID payload body is just the raw VID bytes."""
    return vid_bytes


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 SK (encrypted) payload stub
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev2_sk_stub(inner_payload_type: int = PL_NONE, data_len: int = 32) -> bytes:
    """Build an SK payload stub with random-looking encrypted data."""
    # IV (16 bytes) + ciphertext placeholder + ICV (12 bytes)
    iv = b"\x11" * 16
    ciphertext = b"\xcc" * data_len
    icv = b"\x22" * 12
    return struct.pack(">H", inner_payload_type) + struct.pack(">H", 0) + iv + ciphertext + icv


# ─────────────────────────────────────────────────────────────────────────────
# IKEv1 header builder
# ─────────────────────────────────────────────────────────────────────────────

def build_ikev1_header(
    cookie_i: bytes = b"\xAA" * 8,
    cookie_r: bytes = b"\x00" * 8,
    next_payload: int = PL_V1_NONE,
    exchange_type: int = IKEv1_MAIN,
    flags: int = 0,
    message_id: bytes = b"\x00" * 4,
    body: bytes = b"",
) -> bytes:
    """Build a complete IKEv1 ISAKMP packet."""
    length = 28 + len(body)
    header = (
        cookie_i
        + cookie_r
        + bytes([next_payload, 0x10, exchange_type, flags])  # 0x10 = v1
        + message_id
        + struct.pack(">I", length)
    )
    return header + body


def build_ikev1_sa_payload(
    doi: int = 1,
    situation: int = 1,
    proposal_data: bytes = b"",
) -> bytes:
    """Build IKEv1 SA payload body."""
    return struct.pack(">II", doi, situation) + proposal_data


def build_ikev1_proposal(
    proposal_num: int = 1,
    protocol_id: int = 1,
    spi: bytes = b"",
    transforms: list[bytes] | None = None,
) -> bytes:
    """Build IKEv1 proposal structure."""
    if transforms is None:
        transforms = []
    transform_data = b"".join(transforms)
    total = 8 + len(spi) + len(transform_data)
    return struct.pack(">BBHBBBB",
        0, 0,            # last/more, reserved
        total,           # length (2 bytes)
        proposal_num, protocol_id, len(spi), len(transforms)
    ) + spi + transform_data


# ─────────────────────────────────────────────────────────────────────────────
# ESP packet builder
# ─────────────────────────────────────────────────────────────────────────────

def build_esp_packet(
    spi: int = 0xDEADBEEF,
    seq: int = 1,
    payload: bytes | None = None,
) -> bytes:
    """Build an ESP packet (RFC 4303) — SPI + Seq + payload."""
    if payload is None:
        payload = b"\x00" * 32  # placeholder ciphertext
    return struct.pack(">II", spi, seq) + payload


# ─────────────────────────────────────────────────────────────────────────────
# AH packet builder
# ─────────────────────────────────────────────────────────────────────────────

def build_ah_packet(
    next_header: int = 59,  # 59 = No Next Header
    spi: int = 0xBEEFCAFE,
    seq: int = 1,
    icv: bytes | None = None,
) -> bytes:
    """Build an AH header (RFC 4302)."""
    if icv is None:
        icv = b"\xAA" * 12  # 96-bit ICV placeholder
    payload_len = (len(icv) + 8) // 4 - 2  # AH payload_len field
    return struct.pack(">BBHI I",
        next_header, payload_len, 0, spi, seq
    ) + icv


# ─────────────────────────────────────────────────────────────────────────────
# NAT-T encapsulation
# ─────────────────────────────────────────────────────────────────────────────

def natt_encap_ike(ike_packet: bytes) -> bytes:
    """Prepend 4-byte non-ESP marker (0x00000000) for NAT-T IKE encapsulation."""
    return b"\x00\x00\x00\x00" + ike_packet


def natt_encap_esp(esp_packet: bytes) -> bytes:
    """ESP in UDP (NAT-T) — no additional header, SPI != 0 distinguishes from IKE."""
    return esp_packet


# ─────────────────────────────────────────────────────────────────────────────
# PCAP writer
# ─────────────────────────────────────────────────────────────────────────────

PCAP_MAGIC_US = 0xA1B2C3D4  # microsecond timestamps
PCAP_LINK_RAW = 101          # Raw IPv4/IPv6
PCAP_LINK_ETHERNET = 1


class PcapPacket(NamedTuple):
    ts_sec: int
    ts_usec: int
    data: bytes


def write_pcap(packets: list[PcapPacket], link_type: int = PCAP_LINK_RAW) -> bytes:
    """Serialize packets to pcap format (little-endian, microsecond resolution)."""
    # Global header
    header = struct.pack("<IHHiIII",
        PCAP_MAGIC_US,  # magic
        2, 4,           # version_major, version_minor
        0,              # thiszone
        0,              # sigfigs
        65535,          # snaplen
        link_type,      # network
    )
    records = bytearray(header)
    for pkt in packets:
        caplen = len(pkt.data)
        records += struct.pack("<IIII",
            pkt.ts_sec, pkt.ts_usec, caplen, caplen
        )
        records += pkt.data
    return bytes(records)


# ─────────────────────────────────────────────────────────────────────────────
# UDP framing helpers (for wrapping IKE packets in UDP/IP)
# ─────────────────────────────────────────────────────────────────────────────

def build_udp(sport: int, dport: int, payload: bytes) -> bytes:
    """Build minimal UDP datagram."""
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def calc_ipv4_checksum(hdr: bytes) -> int:
    """Calculate 16-bit one's-complement checksum of IPv4 header."""
    words = struct.unpack(f">{len(hdr) // 2}H", hdr)
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4(
    src: str, dst: str, proto: int, payload: bytes,
    pkt_id: int = 1, ttl: int = 64,
) -> bytes:
    """Build minimal IPv4 packet (no options, with valid RFC 791 header checksum)."""
    def ip2int(s: str) -> int:
        parts = s.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

    total_len = 20 + len(payload)
    hdr_no_csum = struct.pack(">BBHHHBBHII",
        0x45, 0,        # version+IHL, DSCP+ECN
        total_len,
        pkt_id, 0,      # id, flags+fragment_offset
        ttl, proto, 0,  # ttl, proto, checksum(0)
        ip2int(src),
        ip2int(dst),
    )
    csum = calc_ipv4_checksum(hdr_no_csum)
    header = struct.pack(">BBHHHBBHII",
        0x45, 0,
        total_len,
        pkt_id, 0,
        ttl, proto, csum,
        ip2int(src),
        ip2int(dst),
    )
    return header + payload


def build_ike_raw_packet(
    src: str, dst: str,
    sport: int, dport: int,
    ike_payload: bytes,
    ts_sec: int = 1700000000,
    ts_usec: int = 0,
    pkt_id: int = 1,
) -> PcapPacket:
    """Wrap an IKE payload in UDP+IPv4 and return a PcapPacket."""
    udp = build_udp(sport, dport, ike_payload)
    ip = build_ipv4(src, dst, 17, udp, pkt_id=pkt_id)
    return PcapPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=ip)


def build_esp_raw_packet(
    src: str, dst: str,
    spi: int, seq: int,
    payload: bytes,
    ts_sec: int = 1700000100,
    ts_usec: int = 0,
    pkt_id: int = 100,
) -> PcapPacket:
    """Wrap an ESP packet in IPv4 and return a PcapPacket."""
    esp = build_esp_packet(spi=spi, seq=seq, payload=payload)
    ip = build_ipv4(src, dst, 50, esp, pkt_id=pkt_id)
    return PcapPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=ip)
