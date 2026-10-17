"""Tests for Facts and Observations builder — TASK-022."""

from __future__ import annotations

from pathlib import Path
import pytest

from analyzer.capture.reader import CaptureReader
from analyzer.capture.decode import PacketDecoder
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.sessions import reconstruct_ike_sessions, ikemessage_to_model
from analyzer.features.facts import (
    build_facts,
    build_observations_from_sessions,
)
from analyzer.models import Endpoint, IkeProposal, IkeSession, IkeTransform

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def test_build_observations_from_sessions() -> None:
    t_encr = IkeTransform(kind="ENCR", id=12, name="AES-CBC", key_length=256)
    t_dh = IkeTransform(kind="DH", id=14, name="MODP-2048")
    prop = IkeProposal(num=1, protocol="IKE", transforms=[t_encr, t_dh])

    session = IkeSession(
        id="s1",
        version=2,
        spi_i="0123456789abcdef",
        spi_r="fedcba9876543210",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=False,
        first_ts=100.0,
        last_ts=101.0,
        offered=[prop],
        selected=prop,
        outcome="established_observed",
    )

    observations = build_observations_from_sessions([session])
    assert len(observations) == 4  # 2 offered + 2 selected

    offered_obs = [o for o in observations if o.role == "offered"]
    selected_obs = [o for o in observations if o.role == "selected"]

    assert len(offered_obs) == 2
    assert len(selected_obs) == 2

    # Check DH transform observation
    dh_obs = next(o for o in offered_obs if o.kind == "dh")
    assert dh_obs.id == 14
    assert dh_obs.name == "MODP-2048"
    assert dh_obs.ike_version == 2


def test_build_facts_structure() -> None:
    facts = build_facts(
        capture_meta={"total_packets": 10},
        protocol_stats={"counts": {"ikev2": 2}},
        sessions=[],
        flows=[],
        warnings=["test warning"],
    )

    assert facts.capture["total_packets"] == 10
    assert facts.protocol_stats["counts"]["ikev2"] == 2
    assert len(facts.warnings) == 1
    assert len(facts.unsupported) >= 1
    # Truthful statements
    assert any("passive analysis" in u for u in facts.unsupported)


def test_fixture_ikev2_sa_init_facts() -> None:
    pcap_path = FIXTURES_DIR / "ikev2_sa_init.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    messages = []
    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.payload and (parsed.sport == 500 or parsed.dport == 500):
            ike = parse_ikev2(parsed.payload)
            if ike:
                model = ikemessage_to_model(
                    ike,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    src_ip=parsed.src,
                    src_port=parsed.sport or 500,
                    dst_ip=parsed.dst,
                    dst_port=parsed.dport or 500,
                )
                messages.append(model)

    sessions = reconstruct_ike_sessions(messages)
    assert len(sessions) == 1

    facts = build_facts(sessions=sessions)
    assert len(facts.sessions) == 1
    assert len(facts.observations) > 0

    # Ensure transforms are captured in observations
    encr_obs = [o for o in facts.observations if o.kind == "encr"]
    dh_obs = [o for o in facts.observations if o.kind == "dh"]
    assert len(encr_obs) >= 1
    assert len(dh_obs) >= 1
    assert any(o.role == "selected" and o.id == 14 for o in dh_obs)
