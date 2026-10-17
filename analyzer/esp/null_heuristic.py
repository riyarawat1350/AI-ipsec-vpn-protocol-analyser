"""ESP-NULL heuristic detection — TASK-020.

SPEC §5.7:
Detects unencrypted (NULL cipher) ESP payloads without keys by analyzing:
1. Inner IPv4 tunnel packet headers with valid checksums
2. Plaintext / structured transport payload patterns
Random AES-encrypted bytes have random entropy and fail the checksum test
with probability ~2^-16 per packet, yielding 0 false positives.
"""

from __future__ import annotations

import struct
from typing import NamedTuple


class NullHeuristicResult(NamedTuple):
    null_suspected: bool
    confidence: float | None
    inferred_mode: str | None
    sampled_packets: int
    matching_packets: int


def verify_ipv4_checksum(hdr_bytes: bytes) -> bool:
    """Validate 16-bit one's-complement checksum of IPv4 header."""
    if len(hdr_bytes) < 20 or len(hdr_bytes) % 2 != 0:
        return False
    words = struct.unpack(f">{len(hdr_bytes) // 2}H", hdr_bytes)
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def is_candidate_null_packet(payload: bytes) -> tuple[bool, str]:
    """Test if a single ESP payload prefix looks like plaintext / unencrypted.

    Returns (is_candidate, mode).
    """
    if len(payload) < 16:
        return False, "unknown"

    # 1. Inner IPv4 tunnel check (SPEC §5.7)
    if (payload[0] >> 4) == 4 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        if 20 <= ihl <= len(payload):
            total_len = struct.unpack_from(">H", payload, 2)[0]
            if ihl <= total_len:
                if verify_ipv4_checksum(payload[:ihl]):
                    return True, "tunnel (inferred)"

    # 2. Plaintext / ASCII / HTTP structure check
    if payload.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"HEAD ", b"SSH-")):
        return True, "transport (inferred)"

    printable = sum(1 for b in payload if 32 <= b <= 126 or b in (9, 10, 13, 0))
    # High ratio of printable ASCII + null padding
    if len(payload) >= 20 and (printable / len(payload)) >= 0.85:
        return True, "transport (inferred)"

    return False, "unknown"


def check_esp_null(sample_prefixes: list[bytes]) -> NullHeuristicResult:
    """Evaluate up to 50 sampled packet prefixes of an ESP flow.

    Requires >= 10 samples and >= 90% matching candidates to flag.
    """
    if len(sample_prefixes) < 10:
        return NullHeuristicResult(
            null_suspected=False,
            confidence=None,
            inferred_mode=None,
            sampled_packets=len(sample_prefixes),
            matching_packets=0,
        )

    matched = 0
    inferred_modes: list[str] = []

    for prefix in sample_prefixes[:50]:
        is_candidate, mode = is_candidate_null_packet(prefix)
        if is_candidate:
            matched += 1
            inferred_modes.append(mode)

    ratio = matched / len(sample_prefixes)
    if ratio >= 0.90:
        # Determine dominant mode
        tunnel_count = inferred_modes.count("tunnel (inferred)")
        transport_count = inferred_modes.count("transport (inferred)")
        dominant_mode = "tunnel (inferred)" if tunnel_count >= transport_count else "transport (inferred)"

        return NullHeuristicResult(
            null_suspected=True,
            confidence=0.85,
            inferred_mode=dominant_mode,
            sampled_packets=len(sample_prefixes),
            matching_packets=matched,
        )

    return NullHeuristicResult(
        null_suspected=False,
        confidence=None,
        inferred_mode=None,
        sampled_packets=len(sample_prefixes),
        matching_packets=matched,
    )
