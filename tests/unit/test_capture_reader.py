"""Unit tests for capture reader (TASK-007)."""

import struct

import pytest

from analyzer.capture.linktypes import LINKTYPE_ETHERNET
from analyzer.capture.reader import CaptureReader


def create_sample_pcap(filepath, magic_bytes=b"\xa1\xb2\xc3\xd4", is_nano=False, endian=">", linktype=LINKTYPE_ETHERNET, packets=5):
    """Helper to synthesize a test PCAP file."""
    with open(filepath, "wb") as f:
        # Write magic bytes directly
        f.write(magic_bytes)
        # Remaining global header: v_maj(2), v_min(2), tz(4), sig(4), snaplen(4), network(4)
        ghdr = struct.pack(f"{endian}HHiIII", 2, 4, 0, 0, 65535, linktype)
        f.write(ghdr)

        for i in range(packets):
            ts_sec = 1700000000 + i
            ts_subsec = 500000 if not is_nano else 500000000
            payload = b"TEST_PAYLOAD_" + bytes([i]) * 10
            cap_len = len(payload)
            orig_len = cap_len
            pkt_hdr = struct.pack(f"{endian}IIII", ts_sec, ts_subsec, cap_len, orig_len)
            f.write(pkt_hdr)
            f.write(payload)


def create_sample_pcapng(filepath, packets=3):
    """Helper to synthesize a test PCAPNG file with SHB, IDB, and EPB blocks."""
    with open(filepath, "wb") as f:
        # 1. SHB (Section Header Block)
        # block_type(4)=0x0A0D0D0A, total_len(4)=28, bom(4)=0x1A2B3C4D, maj(2)=1, min(2)=0, sec_len(8)=-1, total_len(4)=28
        shb = struct.pack(">IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        f.write(shb)

        # 2. IDB (Interface Description Block)
        # block_type(4)=0x00000001, total_len(4)=20, linktype(2)=1(Ethernet), reserved(2)=0, snaplen(4)=65535, total_len(4)=20
        idb = struct.pack(">IIHHII", 0x00000001, 20, LINKTYPE_ETHERNET, 0, 65535, 20)
        f.write(idb)

        # 3. EPBs (Enhanced Packet Blocks)
        for i in range(packets):
            payload = b"PCAPNG_DATA_" + bytes([i]) * 8
            # Pad payload to 32-bit boundary
            padded_len = (len(payload) + 3) & ~3
            padding = b"\x00" * (padded_len - len(payload))
            block_total_len = 32 + padded_len

            # EPB: type(4)=6, total_len(4), if_id(4)=0, ts_hi(4)=0, ts_lo(4)=1000000*i, cap_len(4), orig_len(4), data, padding, total_len(4)
            epb_hdr = struct.pack(
                ">IIIIIII",
                0x00000006,
                block_total_len,
                0,
                0,
                1000000 * (i + 1),
                len(payload),
                len(payload),
            )
            f.write(epb_hdr)
            f.write(payload)
            f.write(padding)
            f.write(struct.pack(">I", block_total_len))


@pytest.mark.unit
def test_read_pcap_microsecond_big_endian(tmp_path):
    """Verify parsing of big-endian microsecond PCAP."""
    pcap_file = tmp_path / "test_be_us.pcap"
    create_sample_pcap(pcap_file, magic_bytes=b"\xa1\xb2\xc3\xd4", is_nano=False, endian=">", packets=4)

    reader = CaptureReader(pcap_file)
    frames = list(reader.iter_frames())

    assert len(frames) == 4
    assert reader.metadata.format == "pcap"
    assert reader.metadata.packet_count == 4
    assert reader.metadata.linktypes == [LINKTYPE_ETHERNET]
    assert frames[0].pkt_no == 1
    assert frames[0].ts == 1700000000.5
    assert b"TEST_PAYLOAD" in frames[0].raw_bytes
    assert not reader.metadata.truncated


@pytest.mark.unit
def test_read_pcap_nanosecond_little_endian(tmp_path):
    """Verify parsing of little-endian nanosecond PCAP."""
    pcap_file = tmp_path / "test_le_ns.pcap"
    create_sample_pcap(pcap_file, magic_bytes=b"\x4d\x3c\xb2\xa1", is_nano=True, endian="<", packets=3)

    reader = CaptureReader(pcap_file)
    frames = list(reader.iter_frames())

    assert len(frames) == 3
    assert reader.metadata.format == "pcap"
    assert reader.metadata.packet_count == 3
    assert frames[0].ts == 1700000000.5
    assert not reader.metadata.truncated


@pytest.mark.unit
def test_read_pcapng_stream(tmp_path):
    """Verify parsing of PCAPNG stream with SHB, IDB, and EPBs."""
    pcapng_file = tmp_path / "test.pcapng"
    create_sample_pcapng(pcapng_file, packets=3)

    reader = CaptureReader(pcapng_file)
    frames = list(reader.iter_frames())

    assert len(frames) == 3
    assert reader.metadata.format == "pcapng"
    assert reader.metadata.packet_count == 3
    assert frames[0].linktype == LINKTYPE_ETHERNET
    assert b"PCAPNG_DATA" in frames[0].raw_bytes
    assert not reader.metadata.truncated


@pytest.mark.unit
def test_truncated_pcap_tolerance(tmp_path):
    """Verify truncation tolerance: frames before the cut are yielded and a warning is logged (FR-12)."""
    pcap_file = tmp_path / "cut.pcap"
    create_sample_pcap(pcap_file, packets=5)

    # Cut file in the middle of packet #4
    data = pcap_file.read_bytes()
    truncated_data = data[:-15]
    pcap_file.write_bytes(truncated_data)

    reader = CaptureReader(pcap_file)
    frames = list(reader.iter_frames())

    # Must yield the complete packets before the cut without crashing
    assert len(frames) >= 3
    assert reader.metadata.truncated is True
    assert len(reader.metadata.warnings) > 0
    assert any("Truncated" in w for w in reader.metadata.warnings)
