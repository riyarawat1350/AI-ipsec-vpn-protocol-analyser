"""Tests for IKEv1 parser — TASK-015."""

from __future__ import annotations

import struct

import pytest

from analyzer.ike.parser_v1 import parse_ikev1, parse_ikev1_header, redact_identity
from analyzer.ike.common import ParseError
from tests.fixtures.builders import (
    IKEv1_MAIN, IKEv1_AGGRESSIVE,
    PL_V1_SA, PL_V1_KE, PL_V1_ID, PL_V1_HASH, PL_V1_NONCE, PL_V1_NONE,
    FLAG_V1_ENCRYPTION,
    build_ikev1_header, build_ikev1_sa_payload,
    _wrap_payload,
)


def _main_mode_sa() -> bytes:
    sa_body = build_ikev1_sa_payload()
    sa_wrapped = _wrap_payload(PL_V1_NONE, sa_body)
    return build_ikev1_header(
        cookie_i=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        cookie_r=b"\x00" * 8,
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_MAIN,
        flags=0,
        message_id=b"\x00" * 4,
        body=sa_wrapped,
    )


def _build_v1_transform_with_attrs() -> bytes:
    """Build a single IKEv1 transform with TV attributes (encr/hash/auth/group/keylen)."""
    # Attributes: encryption=AES-CBC(7), hash=SHA2-256(4), auth=PSK(1), group=14, keylen=256
    attrs = (
        struct.pack(">HH", 0x8001, 7)   # TV encryption AES-CBC
        + struct.pack(">HH", 0x8002, 4)  # TV hash SHA2-256
        + struct.pack(">HH", 0x8003, 1)  # TV auth PSK
        + struct.pack(">HH", 0x8004, 14) # TV group 14
        + struct.pack(">HH", 0x800E, 256)  # TV key length
    )
    # Transform header: next=0, res=0, len, num=1, id=1 (KEY_IKE), res=0
    total = 8 + len(attrs)
    return struct.pack(">BBHBBH", 0, 0, total, 1, 1, 0) + attrs


def _build_v1_proposal(transforms: list[bytes]) -> bytes:
    tdata = b"".join(transforms)
    # Fix last/more on transforms: only last has next=0
    if len(transforms) > 1:
        fixed = []
        for i, t in enumerate(transforms):
            more = 3 if i < len(transforms) - 1 else 0
            fixed.append(bytes([more]) + t[1:])
        tdata = b"".join(fixed)
    total = 8 + len(tdata)
    return struct.pack(">BBHBBBB", 0, 0, total, 1, 1, 0, len(transforms)) + tdata


def test_parse_main_mode_header():
    pkt = _main_mode_sa()
    msg = parse_ikev1(pkt)
    assert msg.version == 1
    assert msg.exchange_type == IKEv1_MAIN
    assert "Main" in msg.exchange_name or "Identity" in msg.exchange_name
    assert msg.spi_i == "1122334455667788"
    assert msg.spi_r == "0000000000000000"
    assert msg.is_initiator is True
    assert msg.encrypted is False
    assert any(p.payload_type == PL_V1_SA for p in msg.payloads)


def test_parse_sa_with_transforms():
    transform = _build_v1_transform_with_attrs()
    proposal = _build_v1_proposal([transform])
    sa_body = build_ikev1_sa_payload(proposal_data=proposal)
    body = _wrap_payload(PL_V1_NONE, sa_body)
    pkt = build_ikev1_header(next_payload=PL_V1_SA, body=body)
    msg = parse_ikev1(pkt)
    assert len(msg.proposals) == 1
    assert len(msg.proposals[0].transforms) == 1
    t = msg.proposals[0].transforms[0]
    assert t.key_length == 256
    assert "AES" in (t.name or "")
    # Check raw attrs include encryption type 1
    attr_types = [a[0] for a in t.raw_attrs]
    assert 1 in attr_types  # encryption
    assert 14 in attr_types  # key length


def test_encrypted_flag_opaque():
    """E-flag messages must not decode payloads (FR-34)."""
    pkt = _main_mode_sa()
    bad = bytearray(pkt)
    bad[19] = FLAG_V1_ENCRYPTION  # flags byte
    msg = parse_ikev1(bytes(bad))
    assert msg.encrypted is True
    assert msg.payloads == []
    assert any("encrypted" in a.lower() or "not_observable" in a for a in msg.anomalies)


def test_aggressive_mode_id_and_hash():
    """AM cleartext ID + HASH extracted; identity redacted by default."""
    id_body = bytes([1, 0, 0, 0]) + b"alice@example.com"  # type=1 (FQDN-ish)
    hash_body = b"\xAB" * 20
    nonce_body = b"\x11" * 16
    ke_body = b"\x22" * 128

    # Chain: SA → KE → Nonce → ID → HASH
    sa_body = build_ikev1_sa_payload()
    payloads = [
        (PL_V1_SA, sa_body),
        (PL_V1_KE, ke_body),
        (PL_V1_NONCE, nonce_body),
        (PL_V1_ID, id_body),
        (PL_V1_HASH, hash_body),
    ]
    # Manual chain
    result = b""
    for i, (ptype, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else PL_V1_NONE
        result += _wrap_payload(nxt, body)

    pkt = build_ikev1_header(
        next_payload=PL_V1_SA,
        exchange_type=IKEv1_AGGRESSIVE,
        body=result,
    )
    msg = parse_ikev1(pkt)
    assert "Aggressive" in msg.exchange_name
    assert getattr(msg, "v1_hash_len") == 20
    v1_id = getattr(msg, "v1_id")
    assert v1_id is not None
    assert v1_id["redacted"] is True
    assert "al***" in v1_id["value_preview"] or v1_id["value_preview"].startswith("al")


def test_redact_identity_function():
    result = redact_identity(1, b"bob@corp.local", redact=True)
    assert result["redacted"] is True
    assert result["value_preview"].startswith("bo")
    assert "***" in result["value_preview"]
    assert "value_hex" not in result

    clear = redact_identity(1, b"bob@corp.local", redact=False)
    assert clear["redacted"] is False
    assert "bob" in clear["value_hex"] or clear["value_hex"]


def test_truncated_header_graceful():
    msg = parse_ikev1(b"\x00" * 8)
    assert msg.exchange_name == "PARSE_FAILED"


def test_parse_ikev1_header_ok():
    pkt = _main_mode_sa()
    hdr, offset = parse_ikev1_header(pkt)
    assert offset == 28
    assert hdr["exchange_type"] == IKEv1_MAIN


def test_parse_ikev1_header_wrong_version():
    data = b"\x01" * 8 + b"\x00" * 8 + bytes([0, 0x20, 34, 0]) + struct.pack(">II", 0, 28)
    with pytest.raises(ParseError):
        parse_ikev1_header(data)


def test_tlv_life_duration_attribute():
    """TLV attribute (life duration with 4-byte value) must parse."""
    # life type TV=seconds(1), life duration TLV=86400
    attrs = (
        struct.pack(">HH", 0x800B, 1)  # TV life type = seconds
        + struct.pack(">HH", 12, 4) + struct.pack(">I", 86400)  # TLV life duration
    )
    total = 8 + len(attrs)
    transform = struct.pack(">BBHBBH", 0, 0, total, 1, 1, 0) + attrs
    proposal = _build_v1_proposal([transform])
    sa_body = build_ikev1_sa_payload(proposal_data=proposal)
    body = _wrap_payload(PL_V1_NONE, sa_body)
    pkt = build_ikev1_header(next_payload=PL_V1_SA, body=body)
    msg = parse_ikev1(pkt)
    t = msg.proposals[0].transforms[0]
    life_attrs = [a for a in t.raw_attrs if a[0] == 12]
    assert life_attrs
    assert life_attrs[0][1] == 86400
