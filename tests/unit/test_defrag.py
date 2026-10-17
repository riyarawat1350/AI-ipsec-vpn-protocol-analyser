"""Tests for IPv4 defragmenter (TASK-009 / FR-11)."""

import struct

import pytest

from analyzer.capture.defrag import IPv4Defragmenter
from analyzer.models import DecodedPacket


def _make_frag(
    pkt_no: int,
    ts: float,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    ip_proto: int = 17,
    frag_id: int = 100,
    frag_offset: int = 0,
    more_fragments: bool = True,
    payload: bytes = b"\x00" * 8,
) -> DecodedPacket:
    """Helper to create a fragment DecodedPacket."""
    return DecodedPacket(
        pkt_no=pkt_no,
        ts=ts,
        src=src,
        dst=dst,
        ip_proto=ip_proto,
        payload=payload,
        is_fragment=True,
        frag_offset=frag_offset,
        more_fragments=more_fragments,
        frag_id=frag_id,
    )


def _make_unfragmented(pkt_no: int = 1) -> DecodedPacket:
    """Helper for a non-fragment packet."""
    return DecodedPacket(
        pkt_no=pkt_no,
        ts=1.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        ip_proto=17,
        payload=b"\xaa" * 20,
        is_fragment=False,
    )


class TestBasicReassembly:
    """Test basic fragmented UDP reassembly."""

    def test_unfragmented_passes_through(self):
        defrag = IPv4Defragmenter()
        pkt = _make_unfragmented()
        result = defrag.process(pkt)
        assert result is not None
        assert result.payload == pkt.payload
        assert result.reassembled is False

    def test_two_fragment_reassembly(self):
        """Two contiguous fragments reassemble into UDP payload."""
        defrag = IPv4Defragmenter()

        # Build a valid UDP header + payload as fragmented data
        # Fragment 0: UDP header (8 bytes) + first 8 bytes of data
        udp_hdr = struct.pack(">HHH", 500, 4500, 24)  # sport, dport, length
        udp_hdr += b"\x00\x00"  # checksum
        frag0_payload = udp_hdr + b"\xaa" * 8

        # Fragment 1: 8 more bytes of data (last fragment)
        frag1_payload = b"\xbb" * 8

        frag0 = _make_frag(
            pkt_no=1,
            ts=1.0,
            frag_offset=0,
            more_fragments=True,
            payload=frag0_payload,
        )
        frag1 = _make_frag(
            pkt_no=2,
            ts=1.1,
            frag_offset=len(frag0_payload),
            more_fragments=False,
            payload=frag1_payload,
        )

        r0 = defrag.process(frag0)
        assert r0 is None  # Not complete yet

        r1 = defrag.process(frag1)
        assert r1 is not None
        assert r1.reassembled is True
        assert r1.is_fragment is False
        assert r1.sport == 500
        assert r1.dport == 4500
        # Payload should be the UDP body (after 8-byte UDP header) up to udp_len
        assert r1.payload == b"\xaa" * 8 + b"\xbb" * 8

    def test_three_fragment_reassembly(self):
        """Three fragments reassemble correctly in order."""
        defrag = IPv4Defragmenter()

        frag_data = [b"\x01" * 100, b"\x02" * 100, b"\x03" * 100]
        frags = [
            _make_frag(
                pkt_no=i + 1,
                ts=1.0 + i * 0.01,
                ip_proto=50,  # ESP, not UDP, so no UDP header stripping
                frag_offset=i * 100,
                more_fragments=(i < 2),
                payload=frag_data[i],
            )
            for i in range(3)
        ]

        assert defrag.process(frags[0]) is None
        assert defrag.process(frags[1]) is None

        result = defrag.process(frags[2])
        assert result is not None
        assert result.reassembled is True
        assert result.payload == b"\x01" * 100 + b"\x02" * 100 + b"\x03" * 100

    def test_out_of_order_fragments(self):
        """Fragments arriving out of order still reassemble."""
        defrag = IPv4Defragmenter()

        frag_data = [b"\xaa" * 64, b"\xbb" * 64]
        frag0 = _make_frag(pkt_no=1, ts=1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=frag_data[0])
        frag1 = _make_frag(pkt_no=2, ts=1.1, ip_proto=50, frag_offset=64, more_fragments=False, payload=frag_data[1])

        # Send last fragment first
        assert defrag.process(frag1) is None
        result = defrag.process(frag0)
        assert result is not None
        assert result.payload == b"\xaa" * 64 + b"\xbb" * 64


class TestOverlappingFragments:
    """Overlapping fragments must be discarded (security measure)."""

    def test_overlapping_discards_flow(self):
        defrag = IPv4Defragmenter()

        frag0 = _make_frag(pkt_no=1, ts=1.0, frag_offset=0, more_fragments=True, payload=b"\xaa" * 16)
        # Overlapping: offset 8 overlaps with bytes 8-15 of frag0
        frag_overlap = _make_frag(pkt_no=2, ts=1.1, frag_offset=8, more_fragments=False, payload=b"\xbb" * 16)

        assert defrag.process(frag0) is None
        result = defrag.process(frag_overlap)
        assert result is None
        assert any("Overlapping" in w for w in defrag.warnings)


class TestMemoryBounds:
    """Memory caps must be enforced."""

    def test_max_cache_bytes_enforced(self):
        defrag = IPv4Defragmenter(max_cache_bytes=100)

        # First fragment is 80 bytes — fits
        frag0 = _make_frag(pkt_no=1, ts=1.0, frag_offset=0, more_fragments=True, payload=b"\x00" * 80)
        assert defrag.process(frag0) is None

        # Second fragment is 30 bytes — exceeds 100-byte cap
        frag1 = _make_frag(pkt_no=2, ts=1.1, frag_offset=80, more_fragments=False, payload=b"\x00" * 30)
        result = defrag.process(frag1)
        assert result is None
        assert any("memory limit" in w.lower() for w in defrag.warnings)

    def test_max_cache_entries_enforced(self):
        defrag = IPv4Defragmenter(max_cache_entries=2)

        # Fill 2 separate flows
        for i in range(2):
            frag = _make_frag(
                pkt_no=i + 1,
                ts=1.0 + i,
                frag_id=i + 200,
                frag_offset=0,
                more_fragments=True,
                payload=b"\x00" * 8,
            )
            defrag.process(frag)

        # Third flow should be rejected
        frag_extra = _make_frag(
            pkt_no=100,
            ts=2.0,
            frag_id=300,
            frag_offset=0,
            more_fragments=True,
            payload=b"\x00" * 8,
        )
        result = defrag.process(frag_extra)
        assert result is None
        assert any("cache entries limit" in w.lower() for w in defrag.warnings)

    def test_max_fragments_per_packet_enforced(self):
        defrag = IPv4Defragmenter(max_fragments_per_packet=3)

        for i in range(3):
            frag = _make_frag(
                pkt_no=i + 1,
                ts=1.0 + i * 0.01,
                frag_offset=i * 8,
                more_fragments=True,
                payload=b"\x00" * 8,
            )
            defrag.process(frag)

        # 4th fragment should exceed limit
        frag_over = _make_frag(
            pkt_no=4,
            ts=1.04,
            frag_offset=24,
            more_fragments=False,
            payload=b"\x00" * 8,
        )
        result = defrag.process(frag_over)
        assert result is None
        assert any("maximum fragment count" in w.lower() for w in defrag.warnings)


class TestTimeout:
    """Expired flows must be purged."""

    def test_timeout_evicts_flow(self):
        defrag = IPv4Defragmenter(timeout_seconds=5.0)

        frag0 = _make_frag(pkt_no=1, ts=1.0, frag_offset=0, more_fragments=True, payload=b"\x00" * 8)
        defrag.process(frag0)

        # Process a packet much later from a different flow to trigger purge
        late_pkt = _make_unfragmented(pkt_no=99)
        late_pkt.ts = 100.0  # Way past timeout
        # Unfragmented just passes through
        defrag._purge_expired(100.0)

        assert any("timed out" in w.lower() for w in defrag.warnings)
        # Original flow should be evicted
        assert len(defrag._flows) == 0


class TestCacheCleanup:
    """After reassembly, internal cache bytes must be decremented."""

    def test_cache_bytes_decremented_after_reassembly(self):
        defrag = IPv4Defragmenter()

        frag0 = _make_frag(pkt_no=1, ts=1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=b"\x00" * 64)
        frag1 = _make_frag(pkt_no=2, ts=1.1, ip_proto=50, frag_offset=64, more_fragments=False, payload=b"\x00" * 64)

        defrag.process(frag0)
        assert defrag._current_cache_bytes == 64

        defrag.process(frag1)
        # After successful reassembly, cache should be cleaned
        assert defrag._current_cache_bytes == 0
        assert len(defrag._flows) == 0
