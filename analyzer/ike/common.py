"""Common IKE parsing helpers and data structures — TASK-013."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# IKE message data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IKETransform:
    """A single IKEv2 or IKEv1 transform/attribute."""
    transform_type: int      # 1=ENCR, 2=PRF, 3=INTEG, 4=DH, 5=ESN
    transform_id: int
    key_length: int | None = None  # from TV attribute type 14
    name: str = ""
    raw_attrs: list[tuple[int, int | bytes]] = field(default_factory=list)


@dataclass
class IKEProposal:
    """An IKEv2 or IKEv1 proposal/transform-set."""
    num: int
    protocol_id: int   # 1=IKE, 2=AH, 3=ESP
    protocol_name: str = ""
    spi: bytes = b""
    transforms: list[IKETransform] = field(default_factory=list)


@dataclass
class IKEPayload:
    """Parsed IKE payload (generic container)."""
    payload_type: int
    payload_name: str
    critical: bool
    data: bytes           # raw payload body (after 4-byte generic header)
    parsed: Any = None    # type-specific parsed object


@dataclass
class IKEMessage:
    """Fully parsed IKE message (v1 or v2)."""
    version: int           # 1 or 2
    exchange_type: int
    exchange_name: str
    flags: int
    message_id: int
    length: int
    spi_i: str             # hex string
    spi_r: str             # hex string
    is_initiator: bool
    is_response: bool
    encrypted: bool        # SK payload present (v2) or E flag set (v1)
    payloads: list[IKEPayload] = field(default_factory=list)
    proposals: list[IKEProposal] = field(default_factory=list)
    notifies: list[dict[str, Any]] = field(default_factory=list)
    vendor_ids: list[bytes] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    # Source context (populated by caller)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    ts: float = 0.0
    natt: bool = False
    raw_header: bytes = b""


# ─────────────────────────────────────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

class ParseError(Exception):
    """Raised when payload data is structurally invalid."""


def safe_unpack(fmt: str, data: bytes, offset: int = 0) -> tuple:
    """Unpack *fmt* from *data[offset:]*, raising ParseError if data is too short."""
    size = struct.calcsize(fmt)
    end = offset + size
    if len(data) < end:
        raise ParseError(
            f"Buffer too short: need {size} bytes at offset {offset}, "
            f"have {len(data) - offset}"
        )
    return struct.unpack_from(fmt, data, offset)


def hex_spi(raw: bytes) -> str:
    """Return SPI bytes as lowercase hex string."""
    return raw.hex()


PROTOCOL_ID_NAMES: dict[int, str] = {
    0: "RESERVED",
    1: "IKE",
    2: "AH",
    3: "ESP",
    4: "FC_ESP_HEADER",
    5: "FC_CT_AUTHENTICATION",
}


def protocol_name(proto_id: int) -> str:
    return PROTOCOL_ID_NAMES.get(proto_id, f"UNKNOWN({proto_id})")


def iter_payloads(data: bytes, first_payload_type: int) -> list[tuple[int, bool, bytes]]:
    """Iterate over chained IKE generic payload headers.

    Yields (payload_type, critical, body_bytes) for each payload.
    Appends anomaly strings to *anomalies* list when length fields lie.
    Returns a list of (ptype, critical, body).
    """
    results: list[tuple[int, bool, bytes]] = []
    current_type = first_payload_type
    pos = 0
    max_iterations = 64  # guard against infinite loops from malformed packets

    while current_type != 0 and pos < len(data) and max_iterations > 0:
        max_iterations -= 1
        if pos + 4 > len(data):
            break  # truncated header — stop gracefully
        next_type, flags_byte, payload_len = struct.unpack_from(">BBH", data, pos)
        critical = bool(flags_byte & 0x80)
        if payload_len < 4:
            break  # corrupt length — stop
        body_end = pos + payload_len
        if body_end > len(data):
            # Truncated payload — include what we have
            body = data[pos + 4: len(data)]
        else:
            body = data[pos + 4: body_end]
        results.append((current_type, critical, body))
        pos = body_end
        current_type = next_type

    return results
