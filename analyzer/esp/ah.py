"""Authentication Header (AH) decoding and tracking — TASK-019.

RFC 4302:
Header layout:
- Next Header (1 byte)
- Payload Len (1 byte, in 32-bit words minus 2)
- Reserved (2 bytes)
- SPI (4 bytes)
- Sequence Number (4 bytes)
- ICV (variable, padded to 32/64 bits)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class ParsedAhHeader:
    next_header: int
    payload_len: int
    total_len: int
    spi: int
    spi_hex: str
    seq: int
    icv: bytes
    payload: bytes


def parse_ah_header(data: bytes) -> ParsedAhHeader | None:
    """Parse raw AH header starting at byte 0 of IP protocol 51 payload."""
    if len(data) < 12:
        return None

    next_header, payload_len, reserved, spi, seq = struct.unpack_from(">BBHII", data, 0)
    total_len = (payload_len + 2) * 4
    if total_len < 12:
        total_len = 12

    icv = data[12:min(total_len, len(data))]
    payload = data[total_len:] if len(data) >= total_len else b""

    return ParsedAhHeader(
        next_header=next_header,
        payload_len=payload_len,
        total_len=total_len,
        spi=spi,
        spi_hex=f"{spi:08x}",
        seq=seq,
        icv=icv,
        payload=payload,
    )
