"""Unit tests for IPv4 defragmenter (TASK-009)."""

import pytest

from analyzer.capture.defrag import IPv4Defragmenter
from analyzer.models import DecodedPacket


def make_fragment(
    pkt_no: int,
    ts: float,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    ip_proto: int = 17,
    frag_id: int = 1234,
    frag_offset: int = 0,
    more_fragments: bool = True,
    payload: bytes = b"\x00" * 10,
) -> DecodedPacket:
    return DecodedPacket(
        pkt_no=pkt_no,
        ts=ts,
        src=src,
        dst=dst,
        ip_proto=ip_proto,
        sport=None,
        dport=None,
        payload=payload,
        reassembled=False,
        is_fragment=True,
        frag_offset=frag_offset,
        more_fragments=more_fragments,
        frag_id=frag_id,
    )


@pytest.mark.unit
def test_unfragmented_packet_passthrough():
    """Unfragmented packets must pass straight through."""
    defrag = IPv4Defragmenter()
    pkt = DecodedPacket(
        pkt_no=1, ts=1.0, src="1.2.3.4", dst="5.6.7.8",
        ip_proto=50, sport=None, dport=None,
        payload=b"ESP_DATA", reassembled=False, is_fragment=False,
    )
    result = defrag.process(pkt)
    assert result is pkt


@pytest.mark.unit
def test_two_fragment_reassembly():
    """Two non-overlapping fragments should reassemble correctly."""
    defrag = IPv4Defragmenter()

    data_a = b"FIRST_CHUNK_DATA"
    data_b = b"SECOND_CHUNK"

    f1 = make_fragment(1, 1.0, frag_offset=0, more_fragments=True, payload=data_a)
    f2 = make_fragment(2, 1.1, frag_offset=len(data_a), more_fragments=False, payload=data_b)

    r1 = defrag.process(f1)
    assert r1 is None  # Still waiting

    r2 = defrag.process(f2)
    assert r2 is not None
    assert r2.reassembled is True
    # For proto 17 (UDP) the payload bytes are stripped of UDP header
    # but our test data is not a valid UDP header so just check the concatenation
    # The defragmenter returns reassembled payload as-is for non-UDP (proto 50/51)
    # Let's use proto 50 (ESP) to avoid UDP stripping in this test

    defrag2 = IPv4Defragmenter()
    f1_esp = make_fragment(1, 1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=data_a)
    f2_esp = make_fragment(2, 1.1, ip_proto=50, frag_offset=len(data_a), more_fragments=False, payload=data_b)
    defrag2.process(f1_esp)
    r_esp = defrag2.process(f2_esp)
    assert r_esp is not None
    assert r_esp.reassembled is True
    assert r_esp.payload == data_a + data_b


@pytest.mark.unit
def test_out_of_order_fragments():
    """Fragments arriving out of order should still reassemble correctly."""
    defrag = IPv4Defragmenter()
    data_a = b"FIRST_PART_DATA_"
    data_b = b"SECOND_PART_DATA"

    # Send second fragment first
    f2 = make_fragment(2, 1.1, ip_proto=50, frag_offset=len(data_a), more_fragments=False, payload=data_b)
    f1 = make_fragment(1, 1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=data_a)

    r2 = defrag.process(f2)
    assert r2 is None  # Cannot reassemble without offset 0

    r1 = defrag.process(f1)
    assert r1 is not None
    assert r1.reassembled is True
    assert r1.payload == data_a + data_b


@pytest.mark.unit
def test_overlapping_fragments_discarded():
    """Overlapping fragments must be discarded with a warning (security, no crash)."""
    defrag = IPv4Defragmenter()
    data_a = b"A" * 16
    data_b = b"B" * 16  # Overlaps with data_a

    f1 = make_fragment(1, 1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=data_a)
    f2 = make_fragment(2, 1.1, ip_proto=50, frag_offset=8, more_fragments=False, payload=data_b)  # overlaps

    defrag.process(f1)
    result = defrag.process(f2)

    assert result is None
    assert len(defrag.warnings) > 0
    assert any("Overlapping" in w for w in defrag.warnings)


@pytest.mark.unit
def test_memory_cap_enforced():
    """Defragmenter must discard fragments exceeding the memory cap."""
    small_limit = IPv4Defragmenter(max_cache_bytes=100)
    payload = b"X" * 101  # Exceeds limit

    frag = make_fragment(1, 1.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=payload)
    result = small_limit.process(frag)

    assert result is None
    assert len(small_limit.warnings) > 0
    assert any("memory limit" in w for w in small_limit.warnings)


@pytest.mark.unit
def test_fragment_timeout_eviction():
    """Flows that exceed the timeout must be evicted with a warning."""
    defrag = IPv4Defragmenter(timeout_seconds=5.0)

    f1 = make_fragment(1, 0.0, ip_proto=50, frag_offset=0, more_fragments=True, payload=b"DATA")
    defrag.process(f1)

    # Process a second fragment from a different flow, but with timestamp >> timeout
    f2 = make_fragment(2, 100.0, ip_proto=50, frag_id=9999, frag_offset=0, more_fragments=False, payload=b"NEW")
    defrag.process(f2)

    assert any("timed out" in w for w in defrag.warnings)
