"""TASK-016: tshark cross-validation.

Validates that IKE parser fields match tshark's dissection on fixture pcaps.
Skipped cleanly when tshark is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.reader import CaptureReader
from analyzer.ike.parser_v2 import parse_ikev2

TSHARK_BIN = shutil.which("tshark")
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


@pytest.mark.skipif(TSHARK_BIN is None, reason="tshark not installed on this system")
def test_tshark_crossval_ikev2_sa_init() -> None:
    pcap_path = FIXTURES_DIR / "ikev2_sa_init.pcap"
    if not pcap_path.exists():
        pytest.skip(f"Fixture {pcap_path} not found")

    cmd = [
        str(TSHARK_BIN),
        "-r", str(pcap_path),
        "-T", "json",
        "-e", "isakmp.ispi",
        "-e", "isakmp.rspi",
        "-e", "isakmp.version",
        "-e", "isakmp.exchange_type",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"tshark failed: {res.stderr}"
    tshark_data = json.loads(res.stdout)
    assert len(tshark_data) > 0

    decoder = PacketDecoder()
    reader = CaptureReader(pcap_path)
    our_messages = []
    for frame in reader.iter_frames():
        parsed_pkt = decoder.decode(frame.data, frame.link_type)
        if parsed_pkt and parsed_pkt.payload:
            if parsed_pkt.src_port in (500, 4500) or parsed_pkt.dst_port in (500, 4500):
                payload = parsed_pkt.payload
                if parsed_pkt.dst_port == 4500 or parsed_pkt.src_port == 4500:
                    if payload.startswith(b"\x00\x00\x00\x00"):
                        payload = payload[4:]
                msg = parse_ikev2(payload)
                if msg:
                    our_messages.append(msg)

    assert len(our_messages) >= 1
    for idx, our_msg in enumerate(our_messages):
        tshark_layers = tshark_data[idx].get("_source", {}).get("layers", {})
        if "isakmp.ispi" in tshark_layers:
            tshark_ispi = tshark_layers["isakmp.ispi"][0].replace(":", "").lower()
            assert our_msg.spi_i.hex().lower() == tshark_ispi
        if "isakmp.version" in tshark_layers:
            ver_str = tshark_layers["isakmp.version"][0]
            assert "2" in ver_str
