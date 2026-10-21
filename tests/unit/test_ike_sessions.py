"""Tests for IKE session reconstruction — TASK-017."""

from __future__ import annotations

from pathlib import Path

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.reader import CaptureReader
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.sessions import (
    IkeSessionReconstructor,
    ikemessage_to_model,
    reconstruct_ike_sessions,
)
from analyzer.models import Endpoint, IkeMessage, IkeNotify, IkeProposal, IkeTransform

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def _make_msg(
    *,
    pkt_no: int = 1,
    ts: float = 1000.0,
    version: int = 2,
    spi_i: str = "1122334455667788",
    spi_r: str = "0000000000000000",
    direction: str = "i2r",
    exchange_type: int = 34,
    message_id: int = 0,
    notifies: list[IkeNotify] | None = None,
    proposals: list[IkeProposal] | None = None,
    encrypted: bool = False,
    src_ip: str = "192.168.1.1",
    dst_ip: str = "192.168.1.2",
) -> IkeMessage:
    return IkeMessage(
        pkt_no=pkt_no,
        ts=ts,
        src=Endpoint(ip=src_ip, port=500),
        dst=Endpoint(ip=dst_ip, port=500),
        natt=False,
        version=version,
        exchange_type=exchange_type,
        exchange_name="IKE_SA_INIT" if exchange_type == 34 else "IKE_AUTH",
        flags=0x08 if direction == "i2r" else 0x20,
        message_id=message_id,
        length=100,
        spi_i=spi_i,
        spi_r=spi_r,
        direction=direction,  # type: ignore[arg-type]
        payload_types=[33, 34, 40],
        encrypted=encrypted,
        proposals=proposals or [],
        notifies=notifies or [],
    )


def test_ikev2_basic_session() -> None:
    rec = IkeSessionReconstructor()
    t = IkeTransform(kind="ENCR", id=14, name="AES-GCM-256")
    prop = IkeProposal(num=1, protocol="IKE", transforms=[t])

    # Message 1: Initiator SA_INIT
    m1 = _make_msg(pkt_no=1, ts=100.0, spi_r="0000000000000000", direction="i2r", proposals=[prop])
    rec.process_message(m1)

    # Message 2: Responder SA_INIT
    m2 = _make_msg(pkt_no=2, ts=100.1, spi_r="aabbccddeeff0011", direction="r2i", proposals=[prop], src_ip="192.168.1.2", dst_ip="192.168.1.1")
    rec.process_message(m2)

    sessions = rec.get_sessions()
    assert len(sessions) == 1
    s = sessions[0]
    assert s.spi_i == "1122334455667788"
    assert s.spi_r == "aabbccddeeff0011"
    assert len(s.offered) == 1
    assert s.selected is not None
    assert s.selected.transforms[0].name == "AES-GCM-256"
    assert s.retransmissions == 0
    assert len(s.encrypted_not_observable) > 0


def test_ikev2_cookie_retry_stays_one_session() -> None:
    rec = IkeSessionReconstructor()
    spi_i = "aaaaaaaaaaaaaaaa"

    # SA_INIT 1
    m1 = _make_msg(pkt_no=1, ts=1.0, spi_i=spi_i, direction="i2r")
    rec.process_message(m1)

    # Responder sends COOKIE notify (16390)
    cookie_notify = IkeNotify(type=16390, name="COOKIE", data_len=16, data_hex="1234")
    m2 = _make_msg(pkt_no=2, ts=1.1, spi_i=spi_i, spi_r="bbbbbbbbbbbbbbbb", direction="r2i", notifies=[cookie_notify], src_ip="192.168.1.2", dst_ip="192.168.1.1")
    rec.process_message(m2)

    # Initiator retries with cookie
    m3 = _make_msg(pkt_no=3, ts=1.2, spi_i=spi_i, spi_r="0000000000000000", direction="i2r", notifies=[cookie_notify])
    rec.process_message(m3)

    sessions = rec.get_sessions()
    assert len(sessions) == 1
    assert len(sessions[0].messages) == 3


def test_ikev2_invalid_ke_retry_stays_one_session() -> None:
    rec = IkeSessionReconstructor()
    spi_i = "cccccccccccccccc"

    # Initial SA_INIT
    m1 = _make_msg(pkt_no=1, ts=1.0, spi_i=spi_i, direction="i2r")
    rec.process_message(m1)

    # Responder returns INVALID_KE_PAYLOAD (17)
    inv_ke = IkeNotify(type=17, name="INVALID_KE_PAYLOAD", data_len=2, data_hex="000e")
    m2 = _make_msg(pkt_no=2, ts=1.1, spi_i=spi_i, spi_r="dddddddddddddddd", direction="r2i", notifies=[inv_ke], src_ip="192.168.1.2", dst_ip="192.168.1.1")
    rec.process_message(m2)

    # Initiator retries
    m3 = _make_msg(pkt_no=3, ts=1.2, spi_i=spi_i, direction="i2r")
    rec.process_message(m3)

    sessions = rec.get_sessions()
    assert len(sessions) == 1
    assert sessions[0].ke_retries == 1
    assert len(sessions[0].messages) == 3


def test_retransmission_detection() -> None:
    rec = IkeSessionReconstructor()
    m1 = _make_msg(pkt_no=1, ts=1.0, direction="i2r")
    rec.process_message(m1)

    # Duplicate packet with same headers
    m1_dup = _make_msg(pkt_no=2, ts=2.0, direction="i2r")
    rec.process_message(m1_dup)

    sessions = rec.get_sessions()
    assert len(sessions) == 1
    assert sessions[0].retransmissions == 1


def test_outcome_classification() -> None:
    # 1. Unanswered
    rec = IkeSessionReconstructor()
    rec.process_message(_make_msg(pkt_no=1, ts=1.0, direction="i2r"))
    assert rec.get_sessions()[0].outcome == "unanswered"

    # 2. Failed notify
    rec2 = IkeSessionReconstructor()
    rec2.process_message(_make_msg(pkt_no=1, ts=1.0, direction="i2r"))
    err_notify = IkeNotify(type=14, name="NO_PROPOSAL_CHOSEN")
    rec2.process_message(_make_msg(pkt_no=2, ts=1.1, direction="r2i", notifies=[err_notify], src_ip="192.168.1.2", dst_ip="192.168.1.1"))
    assert rec2.get_sessions()[0].outcome == "failed_notify"

    # 3. Established observed
    rec3 = IkeSessionReconstructor()
    rec3.process_message(_make_msg(pkt_no=1, ts=1.0, direction="i2r", exchange_type=34))
    rec3.process_message(_make_msg(pkt_no=2, ts=1.1, direction="r2i", exchange_type=34, spi_r="1111111111111111", src_ip="192.168.1.2", dst_ip="192.168.1.1"))
    # AUTH response
    rec3.process_message(_make_msg(pkt_no=4, ts=1.3, direction="r2i", exchange_type=35, message_id=1, spi_r="1111111111111111", encrypted=True, src_ip="192.168.1.2", dst_ip="192.168.1.1"))
    assert rec3.get_sessions()[0].outcome == "established_observed"


def test_fixture_ikev2_sa_init_session() -> None:
    pcap_path = FIXTURES_DIR / "ikev2_sa_init.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    messages = []
    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.payload and (parsed.sport == 500 or parsed.dport == 500):
            ike_msg = parse_ikev2(parsed.payload)
            if ike_msg:
                model_msg = ikemessage_to_model(
                    ike_msg,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    src_ip=parsed.src,
                    src_port=parsed.sport or 500,
                    dst_ip=parsed.dst,
                    dst_port=parsed.dport or 500,
                    natt=False,
                    raw_bytes=parsed.payload,
                )
                messages.append(model_msg)

    assert len(messages) == 2
    sessions = reconstruct_ike_sessions(messages)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.version == 2
    assert len(s.offered) == 1
    assert s.selected is not None
    assert s.selected.transforms[0].id == 12  # AES-CBC-256
    assert s.retransmissions == 0
