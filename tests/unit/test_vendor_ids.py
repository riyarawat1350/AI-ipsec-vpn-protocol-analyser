"""Tests for Vendor ID fingerprinting — TASK-018."""

from __future__ import annotations

from pathlib import Path
import pytest

from analyzer.capture.reader import CaptureReader
from analyzer.capture.decode import PacketDecoder
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.vendor_ids import lookup_vendor_id
from analyzer.enrich.fingerprint import fingerprint_vendor_id, fingerprint_vendor_ids

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def test_strongswan_vid_matched() -> None:
    vid_hex = "882fe56d6fd20dbc2251613b2ebe5beb"
    res = fingerprint_vendor_id(vid_hex)
    assert res["is_known"] is True
    assert "strongSwan" in res["matched_name"]
    assert res["label"] == "self-reported"
    assert res["raw_hex"] == vid_hex


def test_unknown_vid_displayed_as_hex() -> None:
    unknown_hex = "1234567890abcdefdeadbeef"
    res = fingerprint_vendor_id(unknown_hex)
    assert res["is_known"] is False
    assert res["matched_name"] == unknown_hex
    assert res["label"] == "self-reported"
    assert res["raw_hex"] == unknown_hex


def test_ascii_prefix_vendor_id() -> None:
    res = fingerprint_vendor_id(b"strongSwan 5.9.8")
    assert res["is_known"] is True
    assert "strongSwan" in res["matched_name"]
    assert res["label"] == "self-reported"


def test_standard_nat_t_vid() -> None:
    # RFC 3947 hash
    import hashlib
    vid = hashlib.md5(b"RFC 3947").digest()
    res = fingerprint_vendor_id(vid)
    assert res["is_known"] is True
    assert "RFC 3947" in res["matched_name"]
    assert res["label"] == "self-reported"


def test_fixture_ikev2_strongswan_vid() -> None:
    pcap_path = FIXTURES_DIR / "ikev2_strongswan_vid.pcap"
    assert pcap_path.exists()

    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    vids_found = []
    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.payload:
            msg = parse_ikev2(parsed.payload)
            if msg and msg.vendor_ids:
                vids_found.extend(msg.vendor_ids)

    assert len(vids_found) >= 1
    fp = fingerprint_vendor_ids(vids_found)
    assert any("strongSwan" in f["matched_name"] for f in fp)
    for item in fp:
        assert item["label"] == "self-reported"
