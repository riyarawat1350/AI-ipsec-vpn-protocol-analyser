"""Tests for IKEv2 parser — TASK-014."""

from __future__ import annotations

import struct

import pytest

from analyzer.ike.parser_v2 import parse_ikev2, parse_ikev2_header
from analyzer.ike.common import ParseError
from tests.fixtures.builders import (
    FLAG_INITIATOR, FLAG_RESPONSE,
    IKEv2_SA_INIT, IKEv2_AUTH,
    PL_SA, PL_KE, PL_NONCE, PL_NOTIFY, PL_SK, PL_VENDOR, PL_NONE,
    build_ikev2_header, build_ikev2_sa_payload, build_ikev2_proposal,
    build_ikev2_transform, build_ikev2_ke, build_ikev2_nonce,
    build_ikev2_notify, build_vendor_id, build_ikev2_sk_stub,
    _chain_payloads,
)


def _sa_init_packet(*, weak_dh: bool = False) -> bytes:
    dh_id = 2 if weak_dh else 14
    ke_len = 128 if weak_dh else 256
    t_encr = build_ikev2_transform(1, 12, key_length=256)
    t_prf = build_ikev2_transform(2, 5)
    t_integ = build_ikev2_transform(3, 12)
    t_dh = build_ikev2_transform(4, dh_id)
    t_esn = build_ikev2_transform(5, 0)
    proposal = build_ikev2_proposal(1, 1, [t_encr, t_prf, t_integ, t_dh, t_esn])
    sa_body = build_ikev2_sa_payload([proposal])
    ke_body = build_ikev2_ke(dh_id, b"\x02" * ke_len)
    nonce_body = build_ikev2_nonce(b"\x11" * 16)
    nat_d = build_ikev2_notify(16388, 0, b"", b"\xaa" * 20)
    payloads = [(PL_SA, sa_body), (PL_KE, ke_body), (PL_NONCE, nonce_body), (PL_NOTIFY, nat_d)]
    first, body = _chain_payloads(payloads)
    return build_ikev2_header(
        spi_i=b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
        spi_r=b"\x00" * 8,
        next_payload=first,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_SA_INIT,
        message_id=0,
        body=body,
    )


def test_parse_sa_init_header_and_proposals():
    pkt = _sa_init_packet()
    msg = parse_ikev2(pkt, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    assert msg.version == 2
    assert msg.exchange_type == IKEv2_SA_INIT
    assert msg.exchange_name == "IKE_SA_INIT"
    assert msg.spi_i == "0123456789abcdef"
    assert msg.spi_r == "0000000000000000"
    assert msg.is_initiator is True
    assert msg.is_response is False
    assert msg.encrypted is False
    assert len(msg.proposals) == 1
    prop = msg.proposals[0]
    assert prop.num == 1
    assert prop.protocol_name == "IKE"
    assert len(prop.transforms) == 5
    # ENCR AES-CBC key length
    encr = prop.transforms[0]
    assert encr.transform_type == 1
    assert encr.transform_id == 12
    assert encr.key_length == 256
    assert "AES" in encr.name
    # DH group 14
    dh = prop.transforms[3]
    assert dh.transform_id == 14
    assert "2048" in dh.name
    # Notify present
    assert len(msg.notifies) == 1
    assert msg.notifies[0]["notify_type"] == 16388
    assert "NAT_DETECTION" in msg.notifies[0]["notify_name"]


def test_parse_sk_marked_encrypted():
    sk_body = build_ikev2_sk_stub(PL_NONE, 64)
    _, body = _chain_payloads([(PL_SK, sk_body)])
    pkt = build_ikev2_header(
        next_payload=PL_SK,
        flags=FLAG_INITIATOR,
        exchange_type=IKEv2_AUTH,
        message_id=1,
        body=body,
    )
    msg = parse_ikev2(pkt)
    assert msg.encrypted is True
    assert msg.exchange_name == "IKE_AUTH"
    assert any(p.payload_type == PL_SK for p in msg.payloads)
    sk = next(p for p in msg.payloads if p.payload_type == PL_SK)
    assert sk.parsed["encrypted"] is True


def test_parse_vendor_id():
    vid = build_vendor_id(b"strongSwan 5.9.0")
    first, body = _chain_payloads([(PL_VENDOR, vid)])
    pkt = build_ikev2_header(next_payload=first, body=body)
    msg = parse_ikev2(pkt)
    assert len(msg.vendor_ids) == 1
    assert msg.vendor_ids[0] == b"strongSwan 5.9.0"


def test_payload_length_lie_produces_anomaly_not_exception():
    """Stated length != actual size → anomaly, never raise."""
    pkt = _sa_init_packet()
    # Corrupt the length field (bytes 24-27)
    bad = bytearray(pkt)
    struct.pack_into(">I", bad, 24, len(pkt) + 100)
    msg = parse_ikev2(bytes(bad))
    assert msg.exchange_name == "IKE_SA_INIT"
    assert any("Length field" in a for a in msg.anomalies)


def test_truncated_header_graceful():
    msg = parse_ikev2(b"\x00" * 10)
    assert msg.exchange_name == "PARSE_FAILED"
    assert msg.anomalies


def test_wrong_version_graceful():
    # Build a v1-looking header (version nibble 0x10)
    data = b"\x01" * 8 + b"\x00" * 8 + bytes([0, 0x10, 2, 0]) + struct.pack(">II", 0, 28)
    msg = parse_ikev2(data)
    assert msg.exchange_name == "PARSE_FAILED"


def test_parse_ikev2_header_ok():
    pkt = _sa_init_packet()
    hdr, offset = parse_ikev2_header(pkt)
    assert offset == 28
    assert hdr["exchange_type"] == IKEv2_SA_INIT
    assert hdr["is_initiator"] is True


def test_parse_ikev2_header_too_short():
    with pytest.raises(ParseError):
        parse_ikev2_header(b"\x00" * 10)


def test_weak_dh_proposal_parsed():
    pkt = _sa_init_packet(weak_dh=True)
    msg = parse_ikev2(pkt)
    dh = msg.proposals[0].transforms[3]
    assert dh.transform_id == 2
    assert "1024" in dh.name


def test_response_flag():
    pkt = _sa_init_packet()
    # Flip to response: clear initiator, set response
    bad = bytearray(pkt)
    bad[19] = FLAG_RESPONSE
    msg = parse_ikev2(bytes(bad))
    assert msg.is_response is True
    assert msg.is_initiator is False
