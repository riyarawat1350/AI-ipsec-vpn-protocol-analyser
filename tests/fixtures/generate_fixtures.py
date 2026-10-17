"""Fixture corpus generator — TASK-011.

Generates deterministic .pcap files and expected/*.json metadata for the
full test corpus described in Document 5 §3.

Run via:  python tests/fixtures/generate_fixtures.py
Or:       make fixtures
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

# Allow running as a script from the project root
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.fixtures.builders import (
    PcapPacket,
    PL_SA, PL_KE, PL_NONCE, PL_NOTIFY, PL_VENDOR, PL_SK, PL_NONE,
    PL_V1_SA, PL_V1_KE, PL_V1_NONCE, PL_V1_VID, PL_V1_NONE,
    FLAG_INITIATOR, FLAG_RESPONSE,
    IKEv2_SA_INIT, IKEv2_AUTH, IKEv2_CREATE_CHILD_SA, IKEv2_INFORMATIONAL,
    IKEv1_MAIN, IKEv1_AGGRESSIVE,
    build_ikev2_header, build_ikev2_sa_payload, build_ikev2_proposal,
    build_ikev2_transform, build_ikev2_ke, build_ikev2_nonce,
    build_ikev2_notify, build_vendor_id, build_ikev2_sk_stub,
    build_ikev1_header, build_ikev1_sa_payload,
    build_esp_packet, build_ah_packet,
    natt_encap_ike, natt_encap_esp,
    write_pcap, build_ike_raw_packet, build_esp_raw_packet,
    _chain_payloads, _wrap_payload,
)

FIXTURES_DIR = Path(__file__).parent
EXPECTED_DIR = FIXTURES_DIR / "expected"
PCAP_DIR = FIXTURES_DIR / "pcap"


def _mkdir() -> None:
    EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 1: IKEv2 SA_INIT exchange (initiator + responder)
# ─────────────────────────────────────────────────────────────────────────────

def gen_ikev2_sa_init() -> None:
    """Two-packet IKEv2 SA_INIT fixture (strong DH14 + AES-256-GCM)."""

    # Transform: ENCR AES-CBC-256 (id=12, key_len=256)
    t_encr = build_ikev2_transform(1, 12, key_length=256)
    # Transform: PRF HMAC-SHA2-256 (id=5)
    t_prf = build_ikev2_transform(2, 5)
    # Transform: INTEG HMAC-SHA2-256-128 (id=12)
    t_integ = build_ikev2_transform(3, 12)
    # Transform: DH group 14 (id=14)
    t_dh = build_ikev2_transform(4, 14)
    # Transform: ESN no (id=0)
    t_esn = build_ikev2_transform(5, 0)

    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_integ, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])

    ke_body = build_ikev2_ke(14, b"\x02" * 256)
    nonce_body = build_ikev2_nonce(b"\x11" * 16)
    # NAT-D notify
    nat_d_body = build_ikev2_notify(16388, 0, b"", b"\xaa" * 20)

    payloads_i = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body), (PL_NOTIFY, nat_d_body)]
    first_type, body_bytes = _chain_payloads(payloads_i)

    init_i = build_ikev2_header(
        spi_i=b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )

    # Responder reply — mirrors initiator, spi_r filled
    init_r = build_ikev2_header(
        spi_i=b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
        spi_r=b"\xFE\xDC\xBA\x98\x76\x54\x32\x10",
        next_payload=first_type,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,  # simplified: same body
    )

    packets = [
        build_ike_raw_packet("10.0.0.1", "10.0.0.2", 500, 500, init_i, 1700000000, 0, 1),
        build_ike_raw_packet("10.0.0.2", "10.0.0.1", 500, 500, init_r, 1700000000, 100000, 2),
    ]
    pcap_bytes = write_pcap(packets)
    (PCAP_DIR / "ikev2_sa_init.pcap").write_bytes(pcap_bytes)

    expected = {
        "fixture": "ikev2_sa_init",
        "protocol_counts": {"ikev2": 2},
        "ike_messages": 2,
        "version": 2,
        "exchange_type": IKEv2_SA_INIT,
        "spi_i": "0123456789abcdef",
        "spi_r_in_response": "fedcba9876543210",
        "proposals": [{"num": 1, "protocol": "IKE", "transform_count": 5}],
    }
    (EXPECTED_DIR / "ikev2_sa_init.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev2_sa_init.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 2: IKEv2 AUTH exchange (with SK stub)
# ─────────────────────────────────────────────────────────────────────────────

def gen_ikev2_auth() -> None:
    """IKEv2 IKE_AUTH packet with SK payload stub."""
    sk_body = build_ikev2_sk_stub(PL_NONE, 64)
    _, body_bytes = _chain_payloads([(PL_SK, sk_body)])

    auth_i = build_ikev2_header(
        spi_i=b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
        spi_r=b"\xFE\xDC\xBA\x98\x76\x54\x32\x10",
        next_payload=PL_SK,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_AUTH,
        message_id=1,
        body=body_bytes,
    )
    packets = [
        build_ike_raw_packet("10.0.0.1", "10.0.0.2", 500, 500, auth_i, 1700000001, 0, 3),
    ]
    pcap_bytes = write_pcap(packets)
    (PCAP_DIR / "ikev2_auth_sk.pcap").write_bytes(pcap_bytes)

    expected = {
        "fixture": "ikev2_auth_sk",
        "protocol_counts": {"ikev2": 1},
        "encrypted": True,
        "exchange_type": IKEv2_AUTH,
    }
    (EXPECTED_DIR / "ikev2_auth_sk.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev2_auth_sk.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 3: IKEv2 NAT-T (port 4500)
# ─────────────────────────────────────────────────────────────────────────────

def gen_ikev2_natt() -> None:
    """IKEv2 SA_INIT over NAT-T port 4500 with non-ESP marker."""
    nonce_body = build_ikev2_nonce(b"\x33" * 16)
    _, body_bytes = _chain_payloads([(PL_NONCE, nonce_body)])
    ike = build_ikev2_header(
        spi_i=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        spi_r=b"\x00" * 8,
        next_payload=PL_NONCE,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    natt_ike = natt_encap_ike(ike)
    packets = [
        build_ike_raw_packet("192.168.1.1", "203.0.113.1", 4500, 4500, natt_ike, 1700000002, 0, 4),
    ]
    (PCAP_DIR / "ikev2_natt.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "ikev2_natt",
        "protocol_counts": {"ikev2": 1},
        "natt": True,
        "ports": [4500],
    }
    (EXPECTED_DIR / "ikev2_natt.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev2_natt.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 4: IKEv1 Main Mode
# ─────────────────────────────────────────────────────────────────────────────

def gen_ikev1_main() -> None:
    """IKEv1 Main Mode SA proposal packet."""
    sa_body = build_ikev1_sa_payload()
    # wrap manually with IKEv1 next=NONE, reserved, length
    sa_len = 4 + len(sa_body)
    sa_wrapped = struct.pack(">BBH", PL_V1_NONE, 0, sa_len) + sa_body

    ike = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\x00" * 8,
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=sa_wrapped,
    )
    packets = [
        build_ike_raw_packet("172.16.0.1", "172.16.0.2", 500, 500, ike, 1700000010, 0, 10),
    ]
    (PCAP_DIR / "ikev1_main.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "ikev1_main",
        "protocol_counts": {"ikev1": 1},
        "version": 1,
        "exchange_type": IKEv1_MAIN,
    }
    (EXPECTED_DIR / "ikev1_main.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev1_main.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 5: ESP flow (raw, 10 packets)
# ─────────────────────────────────────────────────────────────────────────────

def gen_esp_flow() -> None:
    """10 sequential ESP packets from a single SPI."""
    packets = []
    for seq in range(1, 11):
        p = build_esp_raw_packet(
            "10.0.0.1", "10.0.0.2",
            spi=0xDEADBEEF, seq=seq,
            payload=b"\xcc" * 32,
            ts_sec=1700000100 + seq,
            ts_usec=0,
            pkt_id=100 + seq,
        )
        packets.append(p)
    (PCAP_DIR / "esp_flow.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "esp_flow",
        "protocol_counts": {"esp": 10},
        "spi": "deadbeef",
        "packet_count": 10,
        "max_seq": 10,
        "gaps": 0,
    }
    (EXPECTED_DIR / "esp_flow.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] esp_flow.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 6: ESP-NULL heuristic (short uniform payloads)
# ─────────────────────────────────────────────────────────────────────────────

def gen_esp_null() -> None:
    """ESP packets with NULL cipher (payload ~= plaintext pattern)."""
    # NULL cipher: payload looks structured, not uniformly random
    # Inner plaintext: HTTP GET request pattern repeated
    inner = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    # Pad to 32 bytes (typical ESP-NULL padding)
    inner = inner[:32].ljust(32, b"\x00")

    packets = []
    for seq in range(1, 21):
        p = build_esp_raw_packet(
            "10.1.0.1", "10.1.0.2",
            spi=0xCAFEBABE, seq=seq,
            payload=inner,
            ts_sec=1700001000 + seq,
            pkt_id=200 + seq,
        )
        packets.append(p)
    (PCAP_DIR / "esp_null.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "esp_null",
        "protocol_counts": {"esp": 20},
        "null_suspected": True,
        "null_confidence_min": 0.7,
    }
    (EXPECTED_DIR / "esp_null.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] esp_null.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 7: ESP gaps/reorder/duplicate
# ─────────────────────────────────────────────────────────────────────────────

def gen_esp_seq_anomalies() -> None:
    """ESP flow with gap, duplicate, and reorder."""
    # seq: 1,2,3, gap 4-5, 6, duplicate 3, reorder 7 before 6
    sequences = [1, 2, 3, 6, 3, 7, 6, 8]
    packets = []
    for i, seq in enumerate(sequences):
        p = build_esp_raw_packet(
            "10.2.0.1", "10.2.0.2",
            spi=0x12345678, seq=seq,
            payload=b"\xBB" * 16,
            ts_sec=1700002000 + i,
            pkt_id=300 + i,
        )
        packets.append(p)
    (PCAP_DIR / "esp_seq_anomalies.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "esp_seq_anomalies",
        "protocol_counts": {"esp": 8},
        "spi": "12345678",
        "max_seq": 8,
        "gaps_count": 1,
        "duplicates_min": 1,
        "reorders_min": 1,
    }
    (EXPECTED_DIR / "esp_seq_anomalies.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] esp_seq_anomalies.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 8: NAT-T keepalive
# ─────────────────────────────────────────────────────────────────────────────

def gen_natt_keepalive() -> None:
    """Single NAT-T keepalive packet (0xFF on port 4500)."""
    from tests.fixtures.builders import build_udp, build_ipv4
    udp = build_udp(4500, 4500, b"\xff")
    ip = build_ipv4("10.0.0.1", "10.0.0.2", 17, udp, pkt_id=50)
    packets = [PcapPacket(ts_sec=1700003000, ts_usec=0, data=ip)]
    (PCAP_DIR / "natt_keepalive.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "natt_keepalive",
        "protocol_counts": {"keepalive": 1},
    }
    (EXPECTED_DIR / "natt_keepalive.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] natt_keepalive.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 9: IKEv2 with weak DH group 1 (768-bit)
# ─────────────────────────────────────────────────────────────────────────────

def gen_ikev2_weak_dh() -> None:
    """IKEv2 SA_INIT offering only DH group 1 (weak — should trigger CRY-DH-001)."""
    t_encr = build_ikev2_transform(1, 3)   # 3DES — weak
    t_prf = build_ikev2_transform(2, 2)    # PRF HMAC-MD5 — weak
    t_integ = build_ikev2_transform(3, 1)  # HMAC-MD5-96 — weak
    t_dh = build_ikev2_transform(4, 1)     # DH group 1 (768-bit) — weak
    t_esn = build_ikev2_transform(5, 0)

    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_integ, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body = build_ikev2_ke(1, b"\x05" * 96)  # 768-bit
    nonce_body = build_ikev2_nonce(b"\x44" * 16)

    payloads_i = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    first_type, body_bytes = _chain_payloads(payloads_i)

    ike = build_ikev2_header(
        spi_i=b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    packets = [
        build_ike_raw_packet("192.168.10.1", "192.168.10.2", 500, 500, ike, 1700004000, 0, 1),
    ]
    (PCAP_DIR / "ikev2_weak_dh.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "ikev2_weak_dh",
        "protocol_counts": {"ikev2": 1},
        "weak_dh_groups": [1],
        "expected_findings": ["CRY-DH-001"],
    }
    (EXPECTED_DIR / "ikev2_weak_dh.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev2_weak_dh.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 10: IKEv2 with strongSwan VID
# ─────────────────────────────────────────────────────────────────────────────

STRONGSWAN_VID = bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb")

def gen_ikev2_strongswan_vid() -> None:
    """IKEv2 SA_INIT with strongSwan vendor-ID."""
    vid_body = build_vendor_id(STRONGSWAN_VID)
    nonce_body = build_ikev2_nonce(b"\x55" * 16)
    payloads_i = [(PL_NONCE, nonce_body), (PL_VENDOR, vid_body)]
    first_type, body_bytes = _chain_payloads(payloads_i)

    ike = build_ikev2_header(
        spi_i=b"\x11\x11\x11\x11\x11\x11\x11\x11",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    packets = [
        build_ike_raw_packet("10.5.0.1", "10.5.0.2", 500, 500, ike, 1700005000, 0, 1),
    ]
    (PCAP_DIR / "ikev2_strongswan_vid.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "ikev2_strongswan_vid",
        "protocol_counts": {"ikev2": 1},
        "vendor_ids": ["strongSwan"],
        "vid_hex": STRONGSWAN_VID.hex(),
    }
    (EXPECTED_DIR / "ikev2_strongswan_vid.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] ikev2_strongswan_vid.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 11: Mixed IKEv2 + ESP combined
# ─────────────────────────────────────────────────────────────────────────────

def gen_mixed_ikev2_esp() -> None:
    """Combined capture: IKEv2 SA_INIT + ESP data flow."""
    # IKE packet
    nonce_body = build_ikev2_nonce(b"\x66" * 16)
    _, body_bytes = _chain_payloads([(PL_NONCE, nonce_body)])
    ike = build_ikev2_header(
        spi_i=b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
        spi_r=b"\x00" * 8,
        next_payload=PL_NONCE,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    ike_pkt = build_ike_raw_packet("10.10.0.1", "10.10.0.2", 500, 500, ike, 1700006000, 0, 1)

    # ESP packets
    esp_pkts = [
        build_esp_raw_packet("10.10.0.1", "10.10.0.2", 0xAAAAAAAA, i, b"\xDD" * 64,
                             ts_sec=1700006100 + i, pkt_id=10 + i)
        for i in range(1, 6)
    ]
    packets = [ike_pkt] + esp_pkts
    (PCAP_DIR / "mixed_ikev2_esp.pcap").write_bytes(write_pcap(packets))
    expected = {
        "fixture": "mixed_ikev2_esp",
        "protocol_counts": {"ikev2": 1, "esp": 5},
        "total_packets": 6,
    }
    (EXPECTED_DIR / "mixed_ikev2_esp.json").write_text(json.dumps(expected, indent=2))
    print("  [OK] mixed_ikev2_esp.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Generating fixture corpus...")
    _mkdir()
    gen_ikev2_sa_init()
    gen_ikev2_auth()
    gen_ikev2_natt()
    gen_ikev1_main()
    gen_esp_flow()
    gen_esp_null()
    gen_esp_seq_anomalies()
    gen_natt_keepalive()
    gen_ikev2_weak_dh()
    gen_ikev2_strongswan_vid()
    gen_mixed_ikev2_esp()
    print(f"\nDone. Fixtures written to {PCAP_DIR}")
    print(f"Expected JSON written to {EXPECTED_DIR}")


if __name__ == "__main__":
    main()
