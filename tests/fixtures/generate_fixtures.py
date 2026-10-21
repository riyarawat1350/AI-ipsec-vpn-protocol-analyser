"""Fixture corpus generator — TASK-011 / Doc-05 §3.

Generates deterministic .pcap files and expected/*.json metadata for the full
test corpus F01–F24 described in Document 5 §3.

Run via:  python tests/fixtures/generate_fixtures.py
Or:       make fixtures

Naming convention matches Doc-05 §3 exactly.
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

from tests.fixtures.builders import (  # noqa: E402
    FLAG_INITIATOR,
    FLAG_RESPONSE,
    FLAG_V1_ENCRYPTION,
    PL_KE,
    PL_NONCE,
    PL_NONE,
    PL_NOTIFY,
    PL_SA,
    PL_SK,
    PL_V1_HASH,
    PL_V1_ID,
    PL_V1_KE,
    PL_V1_NONCE,
    PL_V1_NONE,
    PL_V1_SA,
    PL_VENDOR,
    IKEv1_AGGRESSIVE,
    IKEv1_MAIN,
    IKEv2_CREATE_CHILD_SA,
    IKEv2_SA_INIT,
    PcapPacket,
    _chain_payloads,
    build_ah_packet,
    build_esp_packet,
    build_esp_raw_packet,
    build_ike_raw_packet,
    build_ikev1_header,
    build_ikev1_proposal,
    build_ikev1_sa_payload,
    build_ikev2_header,
    build_ikev2_ke,
    build_ikev2_nonce,
    build_ikev2_notify,
    build_ikev2_proposal,
    build_ikev2_sa_payload,
    build_ikev2_sk_stub,
    build_ikev2_transform,
    build_ipv4,
    build_udp,
    build_vendor_id,
    natt_encap_esp,
    natt_encap_ike,
    write_pcap,
)

FIXTURES_DIR = Path(__file__).parent
EXPECTED_DIR = FIXTURES_DIR / "expected"
PCAP_DIR = FIXTURES_DIR / "pcap"

# IKEv2 transform type constants (RFC 7296)
T_ENCR = 1   # Encryption
T_PRF  = 2   # PRF
T_INTG = 3   # Integrity
T_DH   = 4   # Diffie-Hellman
T_ESN  = 5   # Extended Sequence Numbers

# Transform ID constants used in Doc-05 fixtures
# Encryption
ENCR_DES        = 2    # DES — Critical override
ENCR_3DES       = 3    # 3DES — weak
ENCR_AES_CBC    = 12   # AES-CBC — moderate (CBC mode info)
ENCR_AES_GCM_16 = 20   # AES-GCM-16 — strong

# PRF
PRF_HMAC_MD5    = 1
PRF_HMAC_SHA1   = 2
PRF_HMAC_SHA256 = 5

# Integrity
INTG_HMAC_MD5_96    = 1
INTG_HMAC_SHA1_96   = 2
INTG_HMAC_SHA256_128 = 12

# DH groups
DH_768    = 1    # weak
DH_MODP1024 = 2  # weak
DH_MODP1536 = 5  # moderate
DH_MODP2048 = 14 # strong
DH_X25519   = 31 # strong


PCAPS_DIR = FIXTURES_DIR / "pcaps"


def _mkdir() -> None:
    EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)


def _save(name: str, pcap_bytes: bytes, expected: dict) -> None:
    """Write the pcap and expected JSON for a fixture."""
    (PCAP_DIR / name).write_bytes(pcap_bytes)
    (PCAPS_DIR / name).write_bytes(pcap_bytes)
    stem = name.replace(".pcap", "").replace(".pcapng", "")
    (EXPECTED_DIR / f"{stem}.json").write_text(json.dumps(expected, indent=2))
    print(f"  [OK] {name}  ({len(pcap_bytes)} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# F01 — ikev2_modern_gcm_x25519.pcap
# IKEv2 SA_INIT: AES-GCM-16-256, PRF SHA2-256, DH 31 + ESP flows
# Expected: IKE-INFO-001 (Info) only, posture=100 grade A
# ─────────────────────────────────────────────────────────────────────────────
def gen_f01_ikev2_modern_gcm_x25519() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_GCM_16, key_length=256)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t_dh   = build_ikev2_transform(T_DH,   DH_X25519)
    t_esn  = build_ikev2_transform(T_ESN,  0)

    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_dh, t_esn])
    sa_body  = build_ikev2_sa_payload([proposal])
    ke_body  = build_ikev2_ke(DH_X25519, b"\x05" * 32)
    nonce_body = build_ikev2_nonce(b"\xAB" * 16)

    vid_body = build_vendor_id(b"strongSwan 5.9.11")
    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body), (PL_VENDOR, vid_body)]
    first_type, body_bytes = _chain_payloads(payloads)

    init_i = build_ikev2_header(
        spi_i=b"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    init_r = build_ikev2_header(
        spi_i=b"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8",
        spi_r=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        next_payload=first_type,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    esp_pkts = [
        build_esp_raw_packet("10.0.0.1", "10.0.0.2", 0xAABBCCDD, i,
                             b"\xee" * 64, ts_sec=1700010100 + i, pkt_id=200 + i)
        for i in range(1, 6)
    ]
    packets = [
        build_ike_raw_packet("10.0.0.1", "10.0.0.2", 500, 500, init_i, 1700010000, 0, 1),
        build_ike_raw_packet("10.0.0.2", "10.0.0.1", 500, 500, init_r, 1700010000, 200000, 2),
    ] + esp_pkts

    _save("ikev2_modern_gcm_x25519.pcap", write_pcap(packets), {
        "fixture": "F01",
        "file": "ikev2_modern_gcm_x25519.pcap",
        "expected_findings": ["IKE-INFO-001"],
        "expected_posture": {"score": 100.0, "grade": "A"},
        "protocol_counts": {"ikev2": 2, "esp": 5},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F02 — ikev2_modp1024_3des.pcap
# Offered = selected: 3DES, PRF HMAC_SHA1, INTEG HMAC_SHA1_96, DH 2
# Expected: CRY-DH-001:80.0 High; CRY-ENC-001:60.0 Medium; CRY-INT-001×2:20.0 Low
# Posture: (1-.48)(1-.36)(1-.12)(1-.12) ≈ 25.8 → grade F
# ─────────────────────────────────────────────────────────────────────────────
def gen_f02_ikev2_modp1024_3des() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_3DES)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA1)
    t_intg = build_ikev2_transform(T_INTG, INTG_HMAC_SHA1_96)
    t_dh   = build_ikev2_transform(T_DH,   DH_MODP1024)
    t_esn  = build_ikev2_transform(T_ESN,  0)

    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_intg, t_dh, t_esn])
    sa_body  = build_ikev2_sa_payload([proposal])
    ke_body  = build_ikev2_ke(DH_MODP1024, b"\x05" * 128)
    nonce_body = build_ikev2_nonce(b"\x44" * 16)

    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    first_type, body_bytes = _chain_payloads(payloads)

    init_i = build_ikev2_header(
        spi_i=b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    # Responder selects same (single) proposal
    init_r = build_ikev2_header(
        spi_i=b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE",
        spi_r=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        next_payload=first_type,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    packets = [
        build_ike_raw_packet("192.168.1.1", "192.168.1.2", 500, 500, init_i, 1700020000, 0, 1),
        build_ike_raw_packet("192.168.1.2", "192.168.1.1", 500, 500, init_r, 1700020000, 100000, 2),
    ]
    _save("ikev2_modp1024_3des.pcap", write_pcap(packets), {
        "fixture": "F02",
        "file": "ikev2_modp1024_3des.pcap",
        "expected_findings": [
            {"rule_id": "CRY-DH-001",  "risk_score": 80.0, "severity": "High"},
            {"rule_id": "CRY-ENC-001", "risk_score": 60.0, "severity": "Medium"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
        ],
        "expected_posture": {"score": 25.8, "grade": "F"},
        "protocol_counts": {"ikev2": 2},
        "dh_group": 2,
        "encryption": "3DES",
    })


# ─────────────────────────────────────────────────────────────────────────────
# F03 — ikev2_offered_weak_selected_strong.pcap
# Initiator offers {3DES/SHA1/DH2} AND {AES-CBC-256/SHA2-256/DH14}
# Responder selects second (strong) proposal
# Expected: CRY-DH-001(offered,gr2):48.0 Med; CRY-ENC-001(offered 3DES):36.0 Med;
#           CRY-INT-001(PRF SHA1 offered):12.0 Info; CRY-ENC-002(AES-CBC selected):Info
# Posture ≈ 55.8 → D
# ─────────────────────────────────────────────────────────────────────────────
def gen_f03_offered_weak_selected_strong() -> None:
    # Proposal 1 — weak
    t1_encr = build_ikev2_transform(T_ENCR, ENCR_3DES)
    t1_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA1)
    t1_intg = build_ikev2_transform(T_INTG, INTG_HMAC_SHA1_96)
    t1_dh   = build_ikev2_transform(T_DH,   DH_MODP1024)
    t1_esn  = build_ikev2_transform(T_ESN,  0)
    prop1   = build_ikev2_proposal(1, 1, [t1_encr, t1_prf, t1_intg, t1_dh, t1_esn])

    # Proposal 2 — strong
    t2_encr = build_ikev2_transform(T_ENCR, ENCR_AES_CBC, key_length=256)
    t2_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t2_intg = build_ikev2_transform(T_INTG, INTG_HMAC_SHA256_128)
    t2_dh   = build_ikev2_transform(T_DH,   DH_MODP2048)
    t2_esn  = build_ikev2_transform(T_ESN,  0)
    prop2   = build_ikev2_proposal(2, 1, [t2_encr, t2_prf, t2_intg, t2_dh, t2_esn])

    sa_body_init = build_ikev2_sa_payload([prop1, prop2])
    ke_body = build_ikev2_ke(DH_MODP1024, b"\x06" * 128)
    nonce_body = build_ikev2_nonce(b"\x55" * 16)
    payloads_i = [(PL_SA, sa_body_init), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    first_type, body_i = _chain_payloads(payloads_i)

    init_i = build_ikev2_header(
        spi_i=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_i,
    )
    # Responder selects proposal 2
    sa_body_resp = build_ikev2_sa_payload([prop2])
    ke_body_r = build_ikev2_ke(DH_MODP2048, b"\x07" * 256)
    nonce_body_r = build_ikev2_nonce(b"\x66" * 16)
    payloads_r = [(PL_SA, sa_body_resp), (PL_KE, ke_body_r), (PL_NONCE, nonce_body_r)]
    first_type_r, body_r = _chain_payloads(payloads_r)

    init_r = build_ikev2_header(
        spi_i=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        spi_r=b"\x99\x88\x77\x66\x55\x44\x33\x22",
        next_payload=first_type_r,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_r,
    )
    packets = [
        build_ike_raw_packet("10.1.1.1", "10.1.1.2", 500, 500, init_i, 1700030000, 0, 1),
        build_ike_raw_packet("10.1.1.2", "10.1.1.1", 500, 500, init_r, 1700030000, 100000, 2),
    ]
    _save("ikev2_offered_weak_selected_strong.pcap", write_pcap(packets), {
        "fixture": "F03",
        "file": "ikev2_offered_weak_selected_strong.pcap",
        "expected_findings": [
            {"rule_id": "CRY-DH-001",  "risk_score": 48.0, "severity": "Medium", "role": "offered"},
            {"rule_id": "CRY-ENC-001", "risk_score": 36.0, "severity": "Medium", "role": "offered"},
            {"rule_id": "CRY-INT-001", "risk_score": 12.0, "severity": "Info",   "role": "offered"},
            {"rule_id": "CRY-ENC-002", "severity": "Info", "role": "selected"},
        ],
        "expected_posture": {"score": 55.8, "grade": "D"},
        "protocol_counts": {"ikev2": 2},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F04 — ikev1_mainmode_psk.pcap
# Main Mode msgs 1-4 clear, 5-6 E-flag: AES-CBC, SHA1, PSK, group 2, lifetime 28800
# Expected: IKE-V1-001:40.0 Med; CRY-DH-001:80.0 High; IKE-V1-005:20.0 Low;
#           CRY-INT-001(SHA1):20.0 Low; CRY-ENC-002 Info. No IKE-V1-004
# ─────────────────────────────────────────────────────────────────────────────
def gen_f04_ikev1_mainmode_psk() -> None:
    # IKEv1 transform attribute encoding helpers
    def attr_tv(t: int, v: int) -> bytes:
        return struct.pack(">HH", 0x8000 | t, v)

    # Transform: AES-CBC(3)=7, SHA1(4)=2, PSK(4)=1, group2(2)=2, lifetime(11)=28800
    # IKEv1 transform attributes
    attrs = (
        attr_tv(1, 7) +   # encryption: AES-CBC (value=7 in IKEv1 cipher IDs)
        attr_tv(2, 2) +   # hash/PRF: SHA1
        attr_tv(3, 1) +   # auth: PSK
        attr_tv(4, 2) +   # DH group: 2
        attr_tv(11, 28800)  # lifetime seconds
    )
    # IKEv1 transform substructure
    def build_v1_transform(t_num: int, t_id: int, attrs: bytes) -> bytes:
        total = 8 + len(attrs)
        return struct.pack(">BBHBBH", 0, 0, total, t_num, t_id, 0) + attrs

    transform = build_v1_transform(1, 1, attrs)  # t_num=1, t_id=1 (IKE)

    sa_body = build_ikev1_sa_payload(
        doi=1, situation=1,
        proposal_data=build_ikev1_proposal(1, 1, spi=b"", transforms=[transform])
    )
    sa_len = 4 + len(sa_body)
    sa_wrapped = struct.pack(">BBH", PL_V1_NONE, 0, sa_len) + sa_body

    # Message 1: SA (initiator)
    msg1 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\x00" * 8,
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=sa_wrapped,
    )
    # Message 2: SA (responder)
    msg2 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=sa_wrapped,
    )
    # Messages 3-4: KE+Nonce (clear)
    ke_body = struct.pack(">IH", DH_MODP1024, 0) + b"\x07" * 128
    ke_len = 4 + len(ke_body)
    ke_wrapped = struct.pack(">BBH", PL_V1_NONCE, 0, ke_len) + ke_body
    nonce_body = b"\x33" * 16
    nonce_len = 4 + len(nonce_body)
    nonce_wrapped = struct.pack(">BBH", PL_V1_NONE, 0, nonce_len) + nonce_body

    msg3 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        next_payload=PL_V1_KE,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=ke_wrapped + nonce_wrapped,
    )
    msg4 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        next_payload=PL_V1_KE,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=ke_wrapped + nonce_wrapped,
    )
    # Messages 5-6: Encrypted (E-flag set)
    encrypted_body = b"\xEE" * 48
    msg5 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        next_payload=PL_V1_NONE,
        exchange_type=IKEv1_MAIN,
        flags=FLAG_V1_ENCRYPTION,
        message_id=b"\x00\x00\x00\x01",
        body=encrypted_body,
    )
    msg6 = build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11",
        next_payload=PL_V1_NONE,
        exchange_type=IKEv1_MAIN,
        flags=FLAG_V1_ENCRYPTION,
        message_id=b"\x00\x00\x00\x02",
        body=encrypted_body,
    )
    packets = [
        build_ike_raw_packet("172.16.0.1", "172.16.0.2", 500, 500, msg1, 1700040000, 0, 1),
        build_ike_raw_packet("172.16.0.2", "172.16.0.1", 500, 500, msg2, 1700040000, 100000, 2),
        build_ike_raw_packet("172.16.0.1", "172.16.0.2", 500, 500, msg3, 1700040001, 0, 3),
        build_ike_raw_packet("172.16.0.2", "172.16.0.1", 500, 500, msg4, 1700040001, 100000, 4),
        build_ike_raw_packet("172.16.0.1", "172.16.0.2", 500, 500, msg5, 1700040002, 0, 5),
        build_ike_raw_packet("172.16.0.2", "172.16.0.1", 500, 500, msg6, 1700040002, 100000, 6),
    ]
    _save("ikev1_mainmode_psk.pcap", write_pcap(packets), {
        "fixture": "F04",
        "file": "ikev1_mainmode_psk.pcap",
        "expected_findings": [
            {"rule_id": "IKE-V1-001", "risk_score": 40.0, "severity": "Medium"},
            {"rule_id": "CRY-DH-001", "risk_score": 80.0, "severity": "High"},
            {"rule_id": "IKE-V1-005", "risk_score": 20.0, "severity": "Low"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
            {"rule_id": "CRY-ENC-002", "severity": "Info"},
        ],
        "protocol_counts": {"ikev1": 6},
        "version": 1,
        "mode": "main",
    })


# ─────────────────────────────────────────────────────────────────────────────
# F05 — ikev1_aggressive_psk.pcap
# AM msgs 1-2 (ID+HASH clear), AES-CBC/SHA1/PSK/group 2
# Expected: IKE-V1-001:40.0 Med; IKE-V1-002:60.0 Med; IKE-V1-003:80.0 High;
#           CRY-DH-001:80.0 High; IKE-V1-005:20.0 Low; CRY-INT-001:20.0 Low
# ─────────────────────────────────────────────────────────────────────────────
def gen_f05_ikev1_aggressive_psk() -> None:
    def attr_tv(t: int, v: int) -> bytes:
        return struct.pack(">HH", 0x8000 | t, v)

    attrs = (
        attr_tv(1, 7) +   # AES-CBC
        attr_tv(2, 2) +   # SHA1
        attr_tv(3, 1) +   # PSK
        attr_tv(4, 2)     # DH group 2
    )

    def build_v1_transform(t_num: int, t_id: int, attrs: bytes) -> bytes:
        total = 8 + len(attrs)
        return struct.pack(">BBHBBH", 0, 0, total, t_num, t_id, 0) + attrs

    transform = build_v1_transform(1, 1, attrs)
    sa_body = build_ikev1_sa_payload(
        doi=1, situation=1,
        proposal_data=build_ikev1_proposal(1, 1, spi=b"", transforms=[transform])
    )
    sa_len = 4 + len(sa_body)
    sa_wrapped = struct.pack(">BBH", PL_V1_KE, 0, sa_len) + sa_body

    ke_body = struct.pack(">IH", DH_MODP1024, 0) + b"\x09" * 128
    ke_len = 4 + len(ke_body)
    ke_wrapped = struct.pack(">BBH", PL_V1_NONCE, 0, ke_len) + ke_body

    nonce_body = b"\xAB" * 16
    nonce_len = 4 + len(nonce_body)
    nonce_wrapped = struct.pack(">BBH", PL_V1_ID, 0, nonce_len) + nonce_body

    # ID payload — identity visible in cleartext in AM
    id_body = b"\x01\x00\x00\x00" + b"vpn-client.example.com"
    id_len = 4 + len(id_body)
    id_wrapped = struct.pack(">BBH", PL_V1_HASH, 0, id_len) + id_body

    # HASH payload (cleartext in aggressive mode)
    hash_body = b"\xCC" * 20  # SHA1 hash
    hash_len = 4 + len(hash_body)
    hash_wrapped = struct.pack(">BBH", PL_V1_NONE, 0, hash_len) + hash_body

    full_body = sa_wrapped + ke_wrapped + nonce_wrapped + id_wrapped + hash_wrapped

    # Message 1: AM initiate (SA+KE+Nonce+ID visible)
    msg1 = build_ikev1_header(
        cookie_i=b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44",
        cookie_r=b"\x00" * 8,
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_AGGRESSIVE,
        flags=0,
        message_id=b"\x00" * 4,
        body=full_body,
    )
    # Message 2: AM response (SA+KE+Nonce+ID+HASH visible)
    msg2 = build_ikev1_header(
        cookie_i=b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44",
        cookie_r=b"\x55\x66\x77\x88\x99\xAA\xBB\xCC",
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_AGGRESSIVE,
        flags=0,
        message_id=b"\x00" * 4,
        body=full_body,
    )
    packets = [
        build_ike_raw_packet("10.5.0.1", "10.5.0.2", 500, 500, msg1, 1700050000, 0, 1),
        build_ike_raw_packet("10.5.0.2", "10.5.0.1", 500, 500, msg2, 1700050000, 100000, 2),
    ]
    _save("ikev1_aggressive_psk.pcap", write_pcap(packets), {
        "fixture": "F05",
        "file": "ikev1_aggressive_psk.pcap",
        "expected_findings": [
            {"rule_id": "IKE-V1-001", "risk_score": 40.0, "severity": "Medium"},
            {"rule_id": "IKE-V1-002", "risk_score": 60.0, "severity": "Medium"},
            {"rule_id": "IKE-V1-003", "risk_score": 80.0, "severity": "High"},
            {"rule_id": "CRY-DH-001", "risk_score": 80.0, "severity": "High"},
            {"rule_id": "IKE-V1-005", "risk_score": 20.0, "severity": "Low"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
        ],
        "protocol_counts": {"ikev1": 2},
        "version": 1,
        "mode": "aggressive",
    })


# ─────────────────────────────────────────────────────────────────────────────
# F06 — natt_ikev2_esp.pcap
# IKE on UDP/4500 with non-ESP marker, ESP-in-UDP, 10 keepalives, strong crypto
# Expected: IKE-INFO-002 Info; IKE-INFO-001 Info; posture 100 → A
# ─────────────────────────────────────────────────────────────────────────────
def gen_f06_natt_ikev2_esp() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_GCM_16, key_length=256)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t_dh   = build_ikev2_transform(T_DH,   DH_MODP2048)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_dh, t_esn])
    sa_body  = build_ikev2_sa_payload([proposal])
    nonce_body = build_ikev2_nonce(b"\xBB" * 16)
    vid_body = build_vendor_id(b"strongSwan 5.9.13")
    payloads = [(PL_SA, sa_body), (PL_NONCE, nonce_body), (PL_VENDOR, vid_body)]
    first_type, body_bytes = _chain_payloads(payloads)

    ike = build_ikev2_header(
        spi_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_bytes,
    )
    natt_ike = natt_encap_ike(ike)

    # Keepalives (0xff byte)
    keepalives = []
    for i in range(10):
        udp = build_udp(4500, 4500, b"\xff")
        ip = build_ipv4("10.0.0.1", "10.0.0.2", 17, udp, pkt_id=300 + i)
        keepalives.append(PcapPacket(ts_sec=1700060100 + i * 20, ts_usec=0, data=ip))

    # ESP-in-UDP
    esp_pkts = []
    for i in range(1, 6):
        esp = build_esp_packet(0xDEADC0DE, i, b"\xDD" * 64)
        natt_esp = natt_encap_esp(esp)
        udp = build_udp(4500, 4500, natt_esp)
        ip = build_ipv4("10.0.0.1", "10.0.0.2", 17, udp, pkt_id=400 + i)
        esp_pkts.append(PcapPacket(ts_sec=1700060200 + i, ts_usec=0, data=ip))

    packets = [
        build_ike_raw_packet("10.0.0.1", "10.0.0.2", 4500, 4500, natt_ike, 1700060000, 0, 1),
    ] + keepalives + esp_pkts

    _save("natt_ikev2_esp.pcap", write_pcap(packets), {
        "fixture": "F06",
        "file": "natt_ikev2_esp.pcap",
        "expected_findings": ["IKE-INFO-002", "IKE-INFO-001"],
        "expected_posture": {"score": 100.0, "grade": "A"},
        "natt": True,
        "keepalive_count": 10,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F07 — ikev2_cookie_retry.pcap
# SA_INIT → COOKIE notify → SA_INIT+COOKIE → response
# Expected: one session, cookie_used=true; no findings above Info
# ─────────────────────────────────────────────────────────────────────────────
def gen_f07_ikev2_cookie_retry() -> None:
    nonce_body = build_ikev2_nonce(b"\x77" * 16)
    _, body1 = _chain_payloads([(PL_NONCE, nonce_body)])

    init1 = build_ikev2_header(
        spi_i=b"\x77\x77\x77\x77\x77\x77\x77\x77",
        spi_r=b"\x00" * 8,
        next_payload=PL_NONCE,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body1,
    )
    # COOKIE notify (type 16390)
    cookie_data = b"\xC0\x0c\x1E\xAB" * 4
    cookie_body = build_ikev2_notify(16390, 0, b"", cookie_data)
    _, body_cookie = _chain_payloads([(PL_NOTIFY, cookie_body)])

    cookie_resp = build_ikev2_header(
        spi_i=b"\x77\x77\x77\x77\x77\x77\x77\x77",
        spi_r=b"\x00" * 8,
        next_payload=PL_NOTIFY,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_cookie,
    )
    # Retry with COOKIE
    cookie_pl_body = build_ikev2_notify(16390, 0, b"", cookie_data)
    payloads = [(PL_NONCE, nonce_body), (PL_NOTIFY, cookie_pl_body)]
    first_type, body2 = _chain_payloads(payloads)

    init2 = build_ikev2_header(
        spi_i=b"\x77\x77\x77\x77\x77\x77\x77\x77",
        spi_r=b"\x00" * 8,
        next_payload=first_type,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body2,
    )
    init2_r = build_ikev2_header(
        spi_i=b"\x77\x77\x77\x77\x77\x77\x77\x77",
        spi_r=b"\x88\x88\x88\x88\x88\x88\x88\x88",
        next_payload=PL_NONCE,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body1,
    )
    packets = [
        build_ike_raw_packet("10.7.0.1", "10.7.0.2", 500, 500, init1, 1700070000, 0, 1),
        build_ike_raw_packet("10.7.0.2", "10.7.0.1", 500, 500, cookie_resp, 1700070000, 100000, 2),
        build_ike_raw_packet("10.7.0.1", "10.7.0.2", 500, 500, init2, 1700070001, 0, 3),
        build_ike_raw_packet("10.7.0.2", "10.7.0.1", 500, 500, init2_r, 1700070001, 100000, 4),
    ]
    _save("ikev2_cookie_retry.pcap", write_pcap(packets), {
        "fixture": "F07",
        "file": "ikev2_cookie_retry.pcap",
        "cookie_used": True,
        "expected_max_severity": "Info",
        "protocol_counts": {"ikev2": 4},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F08 — ikev2_invalid_ke_retry.pcap
# KE group 2 → INVALID_KE_PAYLOAD → retry group 14
# Expected: ke_retries=1; CRY-DH-001(offered gr2):48.0 Medium
# ─────────────────────────────────────────────────────────────────────────────
def gen_f08_invalid_ke_retry() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_CBC, key_length=256)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t_dh1  = build_ikev2_transform(T_DH,   DH_MODP1024)  # offered first (weak)
    t_dh2  = build_ikev2_transform(T_DH,   DH_MODP2048)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_dh1, t_dh2, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body1 = build_ikev2_ke(DH_MODP1024, b"\x08" * 128)
    nonce_body = build_ikev2_nonce(b"\x08" * 16)
    payloads1 = [(PL_SA, sa_body), (PL_KE, ke_body1), (PL_NONCE, nonce_body)]
    ft1, body1 = _chain_payloads(payloads1)

    init1 = build_ikev2_header(
        spi_i=b"\x08\x08\x08\x08\x08\x08\x08\x08",
        spi_r=b"\x00" * 8,
        next_payload=ft1,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body1,
    )
    # Responder: INVALID_KE_PAYLOAD notify (type 17)
    # notify data: suggested DH group 14
    inv_ke_body = build_ikev2_notify(17, 0, b"", struct.pack(">H", 14))
    _, body_inv = _chain_payloads([(PL_NOTIFY, inv_ke_body)])
    inv_resp = build_ikev2_header(
        spi_i=b"\x08\x08\x08\x08\x08\x08\x08\x08",
        spi_r=b"\x00" * 8,
        next_payload=PL_NOTIFY,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body_inv,
    )
    # Retry with group 14
    ke_body2 = build_ikev2_ke(DH_MODP2048, b"\x09" * 256)
    payloads2 = [(PL_SA, sa_body), (PL_KE, ke_body2), (PL_NONCE, nonce_body)]
    ft2, body2 = _chain_payloads(payloads2)
    init2 = build_ikev2_header(
        spi_i=b"\x08\x08\x08\x08\x08\x08\x08\x08",
        spi_r=b"\x00" * 8,
        next_payload=ft2,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body2,
    )
    init2_r = build_ikev2_header(
        spi_i=b"\x08\x08\x08\x08\x08\x08\x08\x08",
        spi_r=b"\x09\x09\x09\x09\x09\x09\x09\x09",
        next_payload=ft2,
        flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body2,
    )
    packets = [
        build_ike_raw_packet("10.8.0.1", "10.8.0.2", 500, 500, init1, 1700080000, 0, 1),
        build_ike_raw_packet("10.8.0.2", "10.8.0.1", 500, 500, inv_resp, 1700080000, 100000, 2),
        build_ike_raw_packet("10.8.0.1", "10.8.0.2", 500, 500, init2, 1700080001, 0, 3),
        build_ike_raw_packet("10.8.0.2", "10.8.0.1", 500, 500, init2_r, 1700080001, 100000, 4),
    ]
    _save("ikev2_invalid_ke_retry.pcap", write_pcap(packets), {
        "fixture": "F08",
        "ke_retries": 1,
        "expected_findings": [{"rule_id": "CRY-DH-001", "risk_score": 48.0, "severity": "Medium"}],
        "expected_posture": {"score": 71.0, "grade": "C"},
        "protocol_counts": {"ikev2": 4},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F09 — ikev2_no_proposal_chosen.pcap
# 5 SA_INIT answered by NO_PROPOSAL_CHOSEN within 60s
# Expected: IKE-NEG-001:30.4 Low
# ─────────────────────────────────────────────────────────────────────────────
def gen_f09_no_proposal_chosen() -> None:
    nonce_body = build_ikev2_nonce(b"\x09" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])
    # NO_PROPOSAL_CHOSEN = notify type 14
    no_prop_body = build_ikev2_notify(14, 0, b"", b"")
    _, body_no_prop = _chain_payloads([(PL_NOTIFY, no_prop_body)])

    packets = []
    for i in range(5):
        spi = bytes([0x09 + i] * 8)
        init = build_ikev2_header(
            spi_i=spi, spi_r=b"\x00" * 8,
            next_payload=PL_NONCE, flags=FLAG_INITIATOR,
            exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
        )
        resp = build_ikev2_header(
            spi_i=spi, spi_r=b"\x00" * 8,
            next_payload=PL_NOTIFY, flags=FLAG_RESPONSE,
            exchange_type=IKEv2_SA_INIT, message_id=0, body=body_no_prop,
        )
        packets.append(build_ike_raw_packet("10.9.0.1", "10.9.0.2", 500, 500, init,
                                             1700090000 + i * 10, 0, 10 + i * 2))
        packets.append(build_ike_raw_packet("10.9.0.2", "10.9.0.1", 500, 500, resp,
                                             1700090000 + i * 10, 200000, 11 + i * 2))
    _save("ikev2_no_proposal_chosen.pcap", write_pcap(packets), {
        "fixture": "F09",
        "expected_findings": [{"rule_id": "IKE-NEG-001", "risk_score": 30.4, "severity": "Low"}],
        "failed_negotiations": 5,
        "protocol_counts": {"ikev2": 10},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F10 — lab_ike_init_flood.pcap
# 2000 SA_INIT in 10s from one source; full responses, no COOKIE
# Expected: IKE-DOS-001:57.6 Medium; IKE-DOS-002:43.2 Medium
# ─────────────────────────────────────────────────────────────────────────────
def gen_f10_ike_init_flood() -> None:
    nonce_body = build_ikev2_nonce(b"\x10" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])

    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_GCM_16, key_length=256)
    t_dh   = build_ikev2_transform(T_DH,   DH_MODP2048)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body = build_ikev2_ke(DH_MODP2048, b"\x20" * 256)
    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    ft, body_full = _chain_payloads(payloads)

    packets = []
    for i in range(2000):
        spi = struct.pack(">Q", 0x1000000000000000 + i)
        spi_r = struct.pack(">Q", 0x2000000000000000 + i)
        init = build_ikev2_header(
            spi_i=spi, spi_r=b"\x00" * 8,
            next_payload=ft, flags=FLAG_INITIATOR,
            exchange_type=IKEv2_SA_INIT, message_id=0, body=body_full,
        )
        resp = build_ikev2_header(
            spi_i=spi, spi_r=spi_r,
            next_payload=ft, flags=FLAG_RESPONSE,
            exchange_type=IKEv2_SA_INIT, message_id=0, body=body_full,
        )
        ts_sec = 1700100000 + (i // 200)  # 2000 inits over 10s = 200 req/s
        ts_usec = (i % 200) * 5000
        packets.append(build_ike_raw_packet("10.10.0.1", "10.10.0.2", 500, 500,
                                             init, ts_sec, ts_usec, 1000 + i * 2))
        packets.append(build_ike_raw_packet("10.10.0.2", "10.10.0.1", 500, 500,
                                             resp, ts_sec, ts_usec + 2000, 1001 + i * 2))
    _save("lab_ike_init_flood.pcap", write_pcap(packets), {
        "fixture": "F10",
        "file": "lab_ike_init_flood.pcap",
        "expected_findings": [
            {"rule_id": "IKE-DOS-001", "risk_score": 57.6, "severity": "Medium"},
            {"rule_id": "IKE-DOS-002", "risk_score": 43.2, "severity": "Medium"},
        ],
        "packet_count": 4000,
        "unique_initiators": 1,
        "duration_seconds": 10,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F11 — ikev1_scan_multihost.pcap
# One source → 12 hosts, Main Mode msg1 only, no replies
# Expected: IKE-RECON-001:28.8 Low; IKE-V1-001:40.0 Medium
# ─────────────────────────────────────────────────────────────────────────────
def gen_f11_ikev1_scan_multihost() -> None:
    def attr_tv(t: int, v: int) -> bytes:
        return struct.pack(">HH", 0x8000 | t, v)

    attrs = (
        attr_tv(1, 7) +   # AES-CBC
        attr_tv(2, 4) +   # SHA2-256 (id=4 in IKEv1)
        attr_tv(3, 1) +   # PSK
        attr_tv(4, 14)    # DH group 14
    )

    def build_v1_transform(t_num: int, t_id: int, attrs: bytes) -> bytes:
        total = 8 + len(attrs)
        return struct.pack(">BBHBBH", 0, 0, total, t_num, t_id, 0) + attrs

    transform = build_v1_transform(1, 1, attrs)
    sa_body = build_ikev1_sa_payload(
        doi=1, situation=1,
        proposal_data=build_ikev1_proposal(1, 1, spi=b"", transforms=[transform])
    )
    sa_len = 4 + len(sa_body)
    sa_wrapped = struct.pack(">BBH", PL_V1_NONE, 0, sa_len) + sa_body

    packets = []
    for i in range(12):
        spi = struct.pack(">Q", 0x1100000000000000 + i)
        msg = build_ikev1_header(
            cookie_i=spi,
            cookie_r=b"\x00" * 8,
            next_payload=PL_V1_SA,
            exchange_type=IKEv1_MAIN,
            flags=0,
            message_id=b"\x00" * 4,
            body=sa_wrapped,
        )
        dst_ip = f"192.168.1.{10 + i}"
        packets.append(build_ike_raw_packet(
            "10.11.0.1", dst_ip, 500, 500, msg,
            1700110000 + i * 2, 0, 1100 + i
        ))
    _save("ikev1_scan_multihost.pcap", write_pcap(packets), {
        "fixture": "F11",
        "file": "ikev1_scan_multihost.pcap",
        "expected_findings": [
            {"rule_id": "IKE-RECON-001", "risk_score": 28.8, "severity": "Low"},
            {"rule_id": "IKE-V1-001",    "risk_score": 40.0, "severity": "Medium"},
        ],
        "unique_destinations": 12,
        "protocol_counts": {"ikev1": 12},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F12 — esp_seq_gaps.pcap
# 1000 ESP packets, 3 gaps (15 missing total), 2 duplicates, 1 reorder
# Expected: ESP-SEQ-001:18.0 Low; ESP-NOIKE-001:9.0 Info
# ─────────────────────────────────────────────────────────────────────────────
def gen_f12_esp_seq_gaps() -> None:
    # Build a sequence with gaps, duplicates, reorders
    # Normal: 1..1000, skip 100-104, 500-509, 800 (3 gap events, 15 missing)
    # Duplicate: 200 and 201 sent twice
    # Reorder: 700 sent after 705
    skip = set(range(100, 105)) | set(range(500, 510)) | {800}
    seqs = []
    for s in range(1, 1001):
        if s in skip:
            continue
        seqs.append(s)
        if s in (200, 201):
            seqs.append(s)  # duplicate

    # Inject reorder: find 700 and move it after 705
    idx700 = seqs.index(700) if 700 in seqs else -1
    idx705 = seqs.index(705) if 705 in seqs else -1
    if idx700 >= 0 and idx705 >= 0:
        seqs.pop(idx700)
        seqs.insert(idx705, 700)

    packets = []
    for i, seq in enumerate(seqs):
        p = build_esp_raw_packet(
            "10.12.0.1", "10.12.0.2",
            spi=0x12345678, seq=seq,
            payload=b"\xBB" * 32,
            ts_sec=1700120000 + i,
            ts_usec=0,
            pkt_id=12000 + i,
        )
        packets.append(p)
    _save("esp_seq_gaps.pcap", write_pcap(packets), {
        "fixture": "F12",
        "file": "esp_seq_gaps.pcap",
        "expected_findings": [
            {"rule_id": "ESP-SEQ-001",  "risk_score": 18.0, "severity": "Low"},
            {"rule_id": "ESP-NOIKE-001", "risk_score": 9.0,  "severity": "Info"},
        ],
        "spi": "12345678",
        "total_packets": len(packets),
        "gaps_count": 3,
        "duplicates": 2,
        "reorders": 1,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F13 — esp_null.pcap
# Tunnel-mode ESP whose payload is plaintext IPv4/TCP (valid checksums)
# Expected: ESP-NULL-001:92.5 Critical; ESP-NOIKE-001:9.0 Info
# ─────────────────────────────────────────────────────────────────────────────
def gen_f13_esp_null() -> None:
    # Construct an inner IPv4/TCP packet that would pass NULL cipher detection
    # Inner: TCP SYN from 10.0.0.1:12345 -> 10.0.0.2:80
    def inner_tcp() -> bytes:
        # TCP header (minimal, no options)
        tcp = struct.pack(">HHIIBBHHH",
            12345,   # sport
            80,      # dport
            1000,    # seq
            0,       # ack
            0x50,    # data_offset (5*4=20 bytes, no options)
            0x02,    # flags: SYN
            65535,   # window
            0,       # checksum (0 = not computed)
            0,       # urgent
        )
        # Inner IPv4 wrapping the TCP
        return build_ipv4("172.30.0.1", "172.30.0.2", 6, tcp, pkt_id=1)

    inner = inner_tcp()
    # ESP-NULL: the payload IS the inner packet (no encryption)
    # Pad to block boundary (1 byte pad + next_header=4/IPv4)
    pad_len = (4 - (len(inner) % 4)) % 4
    payload = inner + bytes([0] * pad_len) + bytes([pad_len, 4])

    packets = []
    for seq in range(1, 26):
        p = build_esp_raw_packet(
            "10.13.0.1", "10.13.0.2",
            spi=0xCAFEBABE, seq=seq,
            payload=payload,
            ts_sec=1700130000 + seq,
            ts_usec=0,
            pkt_id=13000 + seq,
        )
        packets.append(p)
    _save("esp_null.pcap", write_pcap(packets), {
        "fixture": "F13",
        "file": "esp_null.pcap",
        "expected_findings": [
            {"rule_id": "ESP-NULL-001",  "risk_score": 92.5, "severity": "Critical"},
            {"rule_id": "ESP-NOIKE-001", "risk_score": 9.0,  "severity": "Info"},
        ],
        "spi": "cafebabe",
        "null_suspected": True,
        "null_confidence_min": 0.9,
        "packet_count": 25,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F14 — ah_flow.pcap
# AH packets both directions
# Expected: AH-001:20.0 Low
# ─────────────────────────────────────────────────────────────────────────────
def gen_f14_ah_flow() -> None:
    packets = []
    for i in range(1, 11):
        ah = build_ah_packet(next_header=4, spi=0xABCDEF00, seq=i)
        ip = build_ipv4("10.14.0.1", "10.14.0.2", 51, ah, pkt_id=14000 + i)
        packets.append(PcapPacket(ts_sec=1700140000 + i, ts_usec=0, data=ip))
    _save("ah_flow.pcap", write_pcap(packets), {
        "fixture": "F14",
        "expected_findings": [{"rule_id": "AH-001", "risk_score": 20.0, "severity": "Low"}],
        "protocol_counts": {"ah": 10},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F15 — ikev2_malformed.pcap
# Header length > UDP payload; payload length lies; truncated transform
# Expected: IKE-PROTO-001:22.8 Low; no crash
# ─────────────────────────────────────────────────────────────────────────────
def gen_f15_ikev2_malformed() -> None:
    # Packet 1: IKE header claiming length > actual UDP data
    valid_ike = build_ikev2_header(
        spi_i=b"\xF5\xF5\xF5\xF5\xF5\xF5\xF5\xF5",
        spi_r=b"\x00" * 8,
        next_payload=PL_NONCE,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=b"\x00" * 16,
    )
    # Inflate the length field in the IKE header (bytes 24-27)
    inflated = bytearray(valid_ike)
    struct.pack_into(">I", inflated, 24, len(valid_ike) + 100)
    pkt1 = build_ike_raw_packet("10.15.0.1", "10.15.0.2", 500, 500,
                                 bytes(inflated), 1700150000, 0, 1)

    # Packet 2: payload generic header claims length > remaining data
    short_body = b"\x00" * 4  # payload header only, no body
    pkt2_ike = build_ikev2_header(
        spi_i=b"\xF6\xF6\xF6\xF6\xF6\xF6\xF6\xF6",
        spi_r=b"\x00" * 8,
        next_payload=PL_NONCE,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=short_body,
    )
    pkt2 = build_ike_raw_packet("10.15.0.1", "10.15.0.2", 500, 500,
                                 pkt2_ike, 1700150001, 0, 2)

    packets = [pkt1, pkt2]
    _save("ikev2_malformed.pcap", write_pcap(packets), {
        "fixture": "F15",
        "expected_findings": [{"rule_id": "IKE-PROTO-001", "risk_score": 22.8, "severity": "Low"}],
        "malformed_count": 2,
        "no_crash": True,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F16 — ikev2_ip_fragmented.pcap
# Large SA_INIT split into 3 IPv4 fragments (one out of order)
# Expected: Same facts as unfragmented; reassembled=true
# ─────────────────────────────────────────────────────────────────────────────
def gen_f16_ikev2_ip_fragmented() -> None:
    # Build a large IKEv2 packet then split into 3 fragments
    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_GCM_16, key_length=256)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t_dh   = build_ikev2_transform(T_DH,   DH_MODP2048)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body = build_ikev2_ke(DH_MODP2048, b"\x16" * 256)
    nonce_body = build_ikev2_nonce(b"\x16" * 16)
    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    ft, body = _chain_payloads(payloads)

    ike_pkt = build_ikev2_header(
        spi_i=b"\x16\x16\x16\x16\x16\x16\x16\x16",
        spi_r=b"\x00" * 8,
        next_payload=ft,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body,
    )
    # UDP wrapper (without IP)
    udp_pkt = build_udp(500, 500, ike_pkt)

    # IPv4 fragmentation: split UDP into 3 pieces (offset in 8-byte units)
    frag_size = 64  # bytes per fragment (must be multiple of 8)
    total_len = len(udp_pkt)
    fragments = []
    for _i, offset in enumerate(range(0, total_len, frag_size)):
        chunk = udp_pkt[offset:offset + frag_size]
        more = 1 if offset + frag_size < total_len else 0
        frag_offset = offset // 8
        flags_frag = (more << 13) | frag_offset
        ip_id = 0x1616
        ip_hdr = struct.pack(">BBHHHBBHII",
            0x45, 0,
            20 + len(chunk),
            ip_id,
            flags_frag,
            64, 17, 0,
            0x0A0F0001,  # 10.15.0.1
            0x0A0F0002,  # 10.15.0.2
        )
        fragments.append(ip_hdr + chunk)

    # Reorder: swap fragment 0 and 1 to simulate out-of-order delivery
    if len(fragments) >= 2:
        fragments[0], fragments[1] = fragments[1], fragments[0]
    packets = [
        PcapPacket(ts_sec=1700160000 + i, ts_usec=0, data=fragments[i])
        for i in range(len(fragments))
    ]
    _save("ikev2_ip_fragmented.pcap", write_pcap(packets), {
        "fixture": "F16",
        "reassembled": True,
        "fragment_count": len(fragments),
        "expected_max_severity": "Info",
    })


# ─────────────────────────────────────────────────────────────────────────────
# F17 — ikev2_des_md5_group1.pcap
# Selected: DES, PRF HMAC_MD5, INTEG HMAC_MD5_96, DH 1
# Expected: CRY-ENC-001:100.0 Critical; CRY-DH-001:100.0 Critical; CRY-INT-001×2:40.0 Medium
# ─────────────────────────────────────────────────────────────────────────────
def gen_f17_ikev2_des_md5_group1() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_DES)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_MD5)
    t_intg = build_ikev2_transform(T_INTG, INTG_HMAC_MD5_96)
    t_dh   = build_ikev2_transform(T_DH,   DH_768)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_intg, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body = build_ikev2_ke(DH_768, b"\x17" * 96)
    nonce_body = build_ikev2_nonce(b"\x17" * 16)
    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
    ft, body = _chain_payloads(payloads)

    init_i = build_ikev2_header(
        spi_i=b"\x17\x17\x17\x17\x17\x17\x17\x17",
        spi_r=b"\x00" * 8,
        next_payload=ft, flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    init_r = build_ikev2_header(
        spi_i=b"\x17\x17\x17\x17\x17\x17\x17\x17",
        spi_r=b"\x18\x18\x18\x18\x18\x18\x18\x18",
        next_payload=ft, flags=FLAG_RESPONSE,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    packets = [
        build_ike_raw_packet("10.17.0.1", "10.17.0.2", 500, 500, init_i, 1700170000, 0, 1),
        build_ike_raw_packet("10.17.0.2", "10.17.0.1", 500, 500, init_r, 1700170000, 100000, 2),
    ]
    _save("ikev2_des_md5_group1.pcap", write_pcap(packets), {
        "fixture": "F17",
        "expected_findings": [
            {"rule_id": "CRY-ENC-001", "risk_score": 100.0, "severity": "Critical"},
            {"rule_id": "CRY-DH-001",  "risk_score": 100.0, "severity": "Critical"},
            {"rule_id": "CRY-INT-001", "risk_score": 40.0,  "severity": "Medium"},
            {"rule_id": "CRY-INT-001", "risk_score": 40.0,  "severity": "Medium"},
        ],
        "expected_posture": {"grade": "F"},
        "encryption": "DES",
        "dh_group": 1,
    })


# ─────────────────────────────────────────────────────────────────────────────
# F18 — ikev2_unanswered.pcap
# SA_INIT + 3 retransmits, no reply
# Expected: IKE-NEG-003:20.4 Low
# ─────────────────────────────────────────────────────────────────────────────
def gen_f18_ikev2_unanswered() -> None:
    nonce_body = build_ikev2_nonce(b"\x18" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])
    spi = b"\x18\x18\x18\x18\x18\x18\x18\x18"

    packets = []
    for i in range(4):  # original + 3 retransmits
        init = build_ikev2_header(
            spi_i=spi, spi_r=b"\x00" * 8,
            next_payload=PL_NONCE, flags=FLAG_INITIATOR,
            exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
        )
        packets.append(build_ike_raw_packet(
            "10.18.0.1", "10.18.0.2", 500, 500, init,
            1700180000 + i * 30, 0, 1800 + i
        ))
    _save("ikev2_unanswered.pcap", write_pcap(packets), {
        "fixture": "F18",
        "expected_findings": [{"rule_id": "IKE-NEG-003", "risk_score": 20.4, "severity": "Low"}],
        "retransmits": 3,
        "protocol_counts": {"ikev2": 4},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F19 — truncated.pcap
# Valid pcap cut mid-packet
# Expected: completes with warning; frames before cut analysed
# ─────────────────────────────────────────────────────────────────────────────
def gen_f19_truncated() -> None:
    nonce_body = build_ikev2_nonce(b"\x19" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])
    ike = build_ikev2_header(
        spi_i=b"\x19\x19\x19\x19\x19\x19\x19\x19", spi_r=b"\x00" * 8,
        next_payload=PL_NONCE, flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    pkt1 = build_ike_raw_packet("10.19.0.1", "10.19.0.2", 500, 500, ike, 1700190000, 0, 1)
    pkt2 = build_ike_raw_packet("10.19.0.2", "10.19.0.1", 500, 500, ike, 1700190001, 0, 2)
    full_pcap = write_pcap([pkt1, pkt2])
    # Cut the pcap mid-way through the second packet record
    truncated = full_pcap[:len(full_pcap) - 10]
    (PCAP_DIR / "truncated.pcap").write_bytes(truncated)
    (EXPECTED_DIR / "truncated.json").write_text(json.dumps({
        "fixture": "F19",
        "file": "truncated.pcap",
        "expected_status": "completed",
        "expected_warning": "truncated",
        "parseable_before_cut": True,
    }, indent=2))
    print(f"  [OK] truncated.pcap  ({len(truncated)} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# F20 — not_a_pcap.txt  (for 415 test)
# Random text file renamed .pcap
# ─────────────────────────────────────────────────────────────────────────────
def gen_f20_not_a_pcap() -> None:
    content = b"This is not a PCAP file.\nIt should be rejected with HTTP 415.\n"
    (PCAP_DIR / "not_a_pcap.txt").write_bytes(content)
    (EXPECTED_DIR / "not_a_pcap.json").write_text(json.dumps({
        "fixture": "F20",
        "file": "not_a_pcap.txt",
        "expected_http_status": 415,
        "expected_error_code": "UNSUPPORTED_FILE_TYPE",
    }, indent=2))
    print(f"  [OK] not_a_pcap.txt  ({len(content)} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# F21 — ikev2_vendor_xss.pcap
# Vendor ID payload bytes containing <script>alert(1)</script>
# Expected: IKE-INFO-001; rendered escaped
# ─────────────────────────────────────────────────────────────────────────────
def gen_f21_vendor_xss() -> None:
    xss_bytes = b"<script>alert(1)</script>"
    vid_body = build_vendor_id(xss_bytes)
    nonce_body = build_ikev2_nonce(b"\x21" * 16)
    payloads = [(PL_NONCE, nonce_body), (PL_VENDOR, vid_body)]
    ft, body = _chain_payloads(payloads)

    ike = build_ikev2_header(
        spi_i=b"\x21\x21\x21\x21\x21\x21\x21\x21", spi_r=b"\x00" * 8,
        next_payload=ft, flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    packets = [build_ike_raw_packet("10.21.0.1", "10.21.0.2", 500, 500,
                                     ike, 1700210000, 0, 1)]
    _save("ikev2_vendor_xss.pcap", write_pcap(packets), {
        "fixture": "F21",
        "expected_findings": ["IKE-INFO-001"],
        "xss_in_vendor_id": True,
        "expected_rendering": "escaped",
    })


# ─────────────────────────────────────────────────────────────────────────────
# F22 — benign_multiclient.pcap
# 5 clients, strong crypto, rekeys
# Expected: no finding above Info; no ML flag; posture A
# ─────────────────────────────────────────────────────────────────────────────
def gen_f22_benign_multiclient() -> None:
    t_encr = build_ikev2_transform(T_ENCR, ENCR_AES_GCM_16, key_length=256)
    t_prf  = build_ikev2_transform(T_PRF,  PRF_HMAC_SHA256)
    t_dh   = build_ikev2_transform(T_DH,   DH_X25519)
    t_esn  = build_ikev2_transform(T_ESN,  0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])

    packets = []
    for client in range(5):
        spi_i = bytes([0x22, client + 1] + [0] * 6)
        spi_r = bytes([0x22, 0xA0 + client + 1] + [0] * 6)
        ke_body = build_ikev2_ke(DH_X25519, bytes([client + 1] * 32))
        nonce_body = build_ikev2_nonce(bytes([client + 1] * 16))
        payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body)]
        ft, body = _chain_payloads(payloads)

        src = f"10.22.{client}.1"
        dst = "10.22.100.1"
        ts_base = 1700220000 + client * 100

        init_i = build_ikev2_header(spi_i=spi_i, spi_r=b"\x00"*8,
                                    next_payload=ft, flags=FLAG_INITIATOR,
                                    exchange_type=IKEv2_SA_INIT, message_id=0, body=body)
        init_r = build_ikev2_header(spi_i=spi_i, spi_r=spi_r,
                                    next_payload=ft, flags=FLAG_RESPONSE,
                                    exchange_type=IKEv2_SA_INIT, message_id=0, body=body)
        packets.append(build_ike_raw_packet(src, dst, 500, 500, init_i, ts_base, 0, 2200 + client * 10))
        packets.append(build_ike_raw_packet(dst, src, 500, 500, init_r, ts_base, 100000, 2201 + client * 10))

        # CREATE_CHILD_SA for rekey
        sk_body = build_ikev2_sk_stub(PL_NONE, 64)
        _, body_sk = _chain_payloads([(PL_SK, sk_body)])
        rekey = build_ikev2_header(spi_i=spi_i, spi_r=spi_r,
                                   next_payload=PL_SK, flags=FLAG_INITIATOR,
                                   exchange_type=IKEv2_CREATE_CHILD_SA, message_id=2, body=body_sk)
        packets.append(build_ike_raw_packet(src, dst, 500, 500, rekey, ts_base + 30, 0, 2205 + client * 10))

    _save("benign_multiclient.pcap", write_pcap(packets), {
        "fixture": "F22",
        "expected_max_severity": "Info",
        "client_count": 5,
        "expected_posture": {"grade": "A"},
    })


# ─────────────────────────────────────────────────────────────────────────────
# F23 — pcapng_two_interfaces.pcapng
# pcapng with two Section Block / Interface Descriptor blocks
# ─────────────────────────────────────────────────────────────────────────────
def gen_f23_pcapng_two_interfaces() -> None:
    """Build a minimal pcapng with two interface blocks and one IKEv2 packet each."""

    def _u32le(v: int) -> bytes:
        return struct.pack("<I", v)

    def _u16le(v: int) -> bytes:
        return struct.pack("<H", v)

    def _pad4(b: bytes) -> bytes:
        pad = (4 - len(b) % 4) % 4
        return b + b"\x00" * pad

    def _option(code: int, val: bytes) -> bytes:
        b = struct.pack("<HH", code, len(val)) + _pad4(val)
        return b

    def _block(block_type: int, body: bytes) -> bytes:
        total = 12 + len(body)
        return _u32le(block_type) + _u32le(total) + body + _u32le(total)

    # Section Header Block (SHB): magic(4), major(2), minor(2), section_len(8)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _option(0, b"")
    shb = _block(0x0A0D0D0A, shb_body)

    # Interface Description Block (IDB) × 2 — link type 1=Ethernet, 101=Raw
    idb1_body = _u16le(1) + _u16le(0) + _u32le(65535)   # Ethernet
    idb2_body = _u16le(101) + _u16le(0) + _u32le(65535)  # Raw

    idb1 = _block(1, idb1_body)
    idb2 = _block(1, idb2_body)

    # Build an IKEv2 IKE packet
    nonce_body = build_ikev2_nonce(b"\x23" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])
    ike = build_ikev2_header(
        spi_i=b"\x23\x23\x23\x23\x23\x23\x23\x23", spi_r=b"\x00" * 8,
        next_payload=PL_NONCE, flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    udp = build_udp(500, 500, ike)
    # Ethernet frame wrapping IPv4
    eth_hdr = b"\xFF\xFF\xFF\xFF\xFF\xFF" + b"\x00\x01\x02\x03\x04\x05" + b"\x08\x00"
    ip_pkt = build_ipv4("10.23.0.1", "10.23.0.2", 17, udp, pkt_id=1)
    eth_pkt = eth_hdr + ip_pkt

    # Enhanced Packet Block (EPB)
    def _epb(interface_id: int, data: bytes) -> bytes:
        cap_len = len(data)
        ts_high, ts_low = 0, 1700230000
        body = (struct.pack("<IIIii", interface_id, ts_high, ts_low,
                            cap_len, cap_len) + _pad4(data))
        return _block(6, body)

    # One packet on each interface
    epb1 = _epb(0, eth_pkt)   # Ethernet interface
    epb2 = _epb(1, ip_pkt)    # Raw interface

    pcapng_bytes = shb + idb1 + idb2 + epb1 + epb2
    (PCAP_DIR / "pcapng_two_interfaces.pcapng").write_bytes(pcapng_bytes)
    (EXPECTED_DIR / "pcapng_two_interfaces.json").write_text(json.dumps({
        "fixture": "F23",
        "file": "pcapng_two_interfaces.pcapng",
        "interface_count": 2,
        "expected_protocols": ["ikev2"],
        "expected_packet_count": 2,
    }, indent=2))
    print(f"  [OK] pcapng_two_interfaces.pcapng  ({len(pcapng_bytes)} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# F24 — sll_linktype.pcap
# Linux cooked capture (link type 113)
# ─────────────────────────────────────────────────────────────────────────────
def gen_f24_sll_linktype() -> None:
    """Build a pcap with link_type=113 (SLL) containing one IKEv2 packet."""

    # SLL (Linux Cooked Capture) header: 16 bytes
    # packet_type(2) + arphrd(2) + addr_len(2) + addr(8) + protocol(2)
    sll_hdr = struct.pack(">HHHQH",
        0,      # packet_type: PACKET_HOST
        1,      # arphrd: ARPHRD_ETHER
        6,      # addr_len
        0x001122334455,  # addr (MAC)
        0x0800, # protocol: IPv4
    )
    nonce_body = build_ikev2_nonce(b"\x24" * 16)
    _, body = _chain_payloads([(PL_NONCE, nonce_body)])
    ike = build_ikev2_header(
        spi_i=b"\x24\x24\x24\x24\x24\x24\x24\x24", spi_r=b"\x00" * 8,
        next_payload=PL_NONCE, flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT, message_id=0, body=body,
    )
    udp = build_udp(500, 500, ike)
    ip_pkt = build_ipv4("10.24.0.1", "10.24.0.2", 17, udp, pkt_id=1)
    sll_pkt = sll_hdr + ip_pkt

    LINK_SLL = 113
    pcap_bytes = write_pcap(
        [PcapPacket(ts_sec=1700240000, ts_usec=0, data=sll_pkt)],
        link_type=LINK_SLL,
    )
    (PCAP_DIR / "sll_linktype.pcap").write_bytes(pcap_bytes)
    (EXPECTED_DIR / "sll_linktype.json").write_text(json.dumps({
        "fixture": "F24",
        "file": "sll_linktype.pcap",
        "link_type": 113,
        "expected_protocols": ["ikev2"],
    }, indent=2))
    print(f"  [OK] sll_linktype.pcap  ({len(pcap_bytes)} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

GENERATORS = [
    ("F01", gen_f01_ikev2_modern_gcm_x25519),
    ("F02", gen_f02_ikev2_modp1024_3des),
    ("F03", gen_f03_offered_weak_selected_strong),
    ("F04", gen_f04_ikev1_mainmode_psk),
    ("F05", gen_f05_ikev1_aggressive_psk),
    ("F06", gen_f06_natt_ikev2_esp),
    ("F07", gen_f07_ikev2_cookie_retry),
    ("F08", gen_f08_invalid_ke_retry),
    ("F09", gen_f09_no_proposal_chosen),
    ("F10", gen_f10_ike_init_flood),
    ("F11", gen_f11_ikev1_scan_multihost),
    ("F12", gen_f12_esp_seq_gaps),
    ("F13", gen_f13_esp_null),
    ("F14", gen_f14_ah_flow),
    ("F15", gen_f15_ikev2_malformed),
    ("F16", gen_f16_ikev2_ip_fragmented),
    ("F17", gen_f17_ikev2_des_md5_group1),
    ("F18", gen_f18_ikev2_unanswered),
    ("F19", gen_f19_truncated),
    ("F20", gen_f20_not_a_pcap),
    ("F21", gen_f21_vendor_xss),
    ("F22", gen_f22_benign_multiclient),
    ("F23", gen_f23_pcapng_two_interfaces),
    ("F24", gen_f24_sll_linktype),
]


def main() -> None:
    print("Generating fixture corpus F01–F24...")
    _mkdir()

    failed = []
    for fid, fn in GENERATORS:
        try:
            fn()
        except Exception as exc:
            print(f"  [FAIL] {fid}: {exc}")
            failed.append((fid, str(exc)))

    # Summary
    print(f"\nDone. Fixtures written to {PCAP_DIR}")
    print(f"Expected JSON written to {EXPECTED_DIR}")
    total = len(GENERATORS)
    passed = total - len(failed)
    print(f"\nResult: {passed}/{total} generated successfully.")

    if failed:
        print("\nFailed fixtures:")
        for fid, err in failed:
            print(f"  {fid}: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
