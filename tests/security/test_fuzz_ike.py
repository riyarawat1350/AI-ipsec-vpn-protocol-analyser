"""TASK-016: Parser fuzzing test using Hypothesis.

Ensures that random, mutated, or truncated bytes fed to IKEv1 and IKEv2
parsers never trigger unhandled exceptions (e.g. IndexError, struct.error,
ValueError).
"""

from __future__ import annotations

import struct
from hypothesis import given, settings, strategies as st
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.parser_v1 import parse_ikev1
from analyzer.ike.common import ParseError


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=0, max_size=4096))
def test_fuzz_ikev2_arbitrary_bytes(data: bytes) -> None:
    """IKEv2 parser must never crash on arbitrary byte payloads."""
    try:
        msg = parse_ikev2(data)
        if msg is not None:
            assert isinstance(msg.anomalies, list)
    except ParseError:
        # Expected for headers shorter than 28 bytes or wrong versions
        pass
    except Exception as exc:
        raise AssertionError(f"Unhandled exception in parse_ikev2: {exc}") from exc


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=0, max_size=4096))
def test_fuzz_ikev1_arbitrary_bytes(data: bytes) -> None:
    """IKEv1 parser must never crash on arbitrary byte payloads."""
    try:
        msg = parse_ikev1(data)
        if msg is not None:
            assert isinstance(msg.anomalies, list)
    except ParseError:
        # Expected for headers shorter than 28 bytes or wrong versions
        pass
    except Exception as exc:
        raise AssertionError(f"Unhandled exception in parse_ikev1: {exc}") from exc


@settings(max_examples=200, deadline=None)
@given(
    st.binary(min_size=28, max_size=28),
    st.integers(min_value=0, max_value=65535),
    st.integers(min_value=0, max_value=255),
    st.binary(min_size=0, max_size=500),
)
def test_fuzz_ikev2_corrupted_header(
    hdr_prefix: bytes, stated_len: int, next_payload: int, body: bytes
) -> None:
    """Corrupted lengths, bad next_payload values must record anomalies, not crash."""
    spii = hdr_prefix[:8]
    spir = hdr_prefix[8:16]
    ver = 0x20
    exchange = 34  # IKE_SA_INIT
    flags = 0x08  # Initiator
    msg_id = 0
    raw_hdr = spii + spir + bytes([next_payload, ver, exchange, flags]) + struct.pack("!II", msg_id, stated_len)
    raw_packet = raw_hdr + body

    try:
        msg = parse_ikev2(raw_packet)
        if msg is not None:
            assert msg.version == 2
    except ParseError:
        pass
    except Exception as exc:
        raise AssertionError(f"Unhandled exception on corrupted IKEv2 header: {exc}") from exc


@settings(max_examples=200, deadline=None)
@given(
    st.binary(min_size=28, max_size=28),
    st.integers(min_value=0, max_value=65535),
    st.integers(min_value=0, max_value=255),
    st.binary(min_size=0, max_size=500),
)
def test_fuzz_ikev1_corrupted_header(
    hdr_prefix: bytes, stated_len: int, next_payload: int, body: bytes
) -> None:
    """Corrupted lengths and bad payloads in IKEv1 must record anomalies, not crash."""
    spii = hdr_prefix[:8]
    spir = hdr_prefix[8:16]
    ver = 0x10  # IKEv1
    exchange = 2   # Identity Protection (Main Mode)
    flags = 0
    msg_id = 0
    raw_hdr = spii + spir + bytes([next_payload, ver, exchange, flags]) + struct.pack("!II", msg_id, stated_len)
    raw_packet = raw_hdr + body

    try:
        msg = parse_ikev1(raw_packet)
        if msg is not None:
            assert msg.version == 1
    except ParseError:
        pass
    except Exception as exc:
        raise AssertionError(f"Unhandled exception on corrupted IKEv1 header: {exc}") from exc
