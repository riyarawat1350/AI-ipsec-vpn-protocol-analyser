"""Streaming capture reader for PCAP and PCAPNG files (FR-08, FR-12)."""

import struct
from collections.abc import Generator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from analyzer.capture.linktypes import LINKTYPE_ETHERNET

# Raw byte magic identifiers
RAW_MAGIC_BE_US = b"\xa1\xb2\xc3\xd4"
RAW_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"
RAW_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"
RAW_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"
RAW_MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"


@dataclass
class RawFrame:
    """Raw unparsed packet frame yielded from capture reader."""

    pkt_no: int
    ts: float  # epoch seconds (float with micro/nanosecond precision)
    linktype: int
    raw_bytes: bytes
    orig_len: int


@dataclass
class CaptureMetadata:
    """Capture file metadata and streaming statistics."""

    format: str = "unknown"
    packet_count: int = 0
    total_bytes: int = 0
    start_ts: float | None = None
    end_ts: float | None = None
    duration_s: float = 0.0
    linktypes: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False


class CaptureReader:
    """Streaming reader supporting classic PCAP and PCAPNG with truncation tolerance."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        self.metadata = CaptureMetadata()

    def iter_frames(self) -> Iterator[RawFrame]:
        """Stream frames from capture file."""
        if not self.filepath.exists():
            raise FileNotFoundError(f"Capture file not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                self.metadata.warnings.append("File is empty or too short to contain a capture header")
                return

            f.seek(0)

            if magic_bytes in (RAW_MAGIC_BE_US, RAW_MAGIC_LE_US, RAW_MAGIC_BE_NS, RAW_MAGIC_LE_NS):
                self.metadata.format = "pcap"
                yield from self._read_pcap(f)
            elif magic_bytes == RAW_MAGIC_PCAPNG:
                self.metadata.format = "pcapng"
                yield from self._read_pcapng(f)
            else:
                self.metadata.warnings.append(f"Unrecognized capture magic bytes: {magic_bytes.hex()}")
                return

        # Finalize metadata duration
        if self.metadata.start_ts is not None and self.metadata.end_ts is not None:
            self.metadata.duration_s = max(0.0, self.metadata.end_ts - self.metadata.start_ts)

    def _record_frame_meta(self, ts: float, length: int, linktype: int) -> None:
        """Update ongoing capture summary metadata."""
        self.metadata.packet_count += 1
        self.metadata.total_bytes += length

        if self.metadata.start_ts is None or ts < self.metadata.start_ts:
            self.metadata.start_ts = ts
        if self.metadata.end_ts is None or ts > self.metadata.end_ts:
            self.metadata.end_ts = ts

        if linktype not in self.metadata.linktypes:
            self.metadata.linktypes.append(linktype)

    def _read_pcap(self, f: BinaryIO) -> Generator[RawFrame, None, None]:
        """Parse classic PCAP file stream."""
        hdr_bytes = f.read(24)
        if len(hdr_bytes) < 24:
            self.metadata.warnings.append("Truncated global PCAP header")
            self.metadata.truncated = True
            return

        magic_bytes = hdr_bytes[:4]
        if magic_bytes == RAW_MAGIC_BE_US:
            endian = ">"
            is_nanosecond = False
        elif magic_bytes == RAW_MAGIC_LE_US:
            endian = "<"
            is_nanosecond = False
        elif magic_bytes == RAW_MAGIC_BE_NS:
            endian = ">"
            is_nanosecond = True
        elif magic_bytes == RAW_MAGIC_LE_NS:
            endian = "<"
            is_nanosecond = True
        else:
            self.metadata.warnings.append(f"Invalid PCAP magic bytes: {magic_bytes.hex()}")
            return

        # Header fields: magic(4), v_maj(2), v_min(2), tz(4), sig(4), snaplen(4), network(4)
        _, _, _, _, _, _, global_linktype = struct.unpack(f"{endian}IHHiIII", hdr_bytes)

        pkt_no = 0
        while True:
            pkt_hdr_bytes = f.read(16)
            if not pkt_hdr_bytes:
                break  # Normal EOF
            if len(pkt_hdr_bytes) < 16:
                self.metadata.warnings.append("Truncated packet header encountered")
                self.metadata.truncated = True
                break

            ts_sec, ts_subsec, cap_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr_bytes)
            if is_nanosecond:
                ts = float(ts_sec) + (float(ts_subsec) / 1e9)
            else:
                ts = float(ts_sec) + (float(ts_subsec) / 1e6)

            packet_data = f.read(cap_len)
            if len(packet_data) < cap_len:
                self.metadata.warnings.append(
                    f"Truncated packet payload at packet #{pkt_no + 1} (expected {cap_len} bytes, got {len(packet_data)})"
                )
                self.metadata.truncated = True
                break

            pkt_no += 1
            self._record_frame_meta(ts, orig_len, global_linktype)
            yield RawFrame(
                pkt_no=pkt_no,
                ts=ts,
                linktype=global_linktype,
                raw_bytes=packet_data,
                orig_len=orig_len,
            )

    def _read_pcapng(self, f: BinaryIO) -> Generator[RawFrame, None, None]:
        """Parse PCAPNG stream (supports multiple interfaces, IDBs, and EPBs)."""
        endian = "="
        interfaces: list[dict] = []  # list of interface info {linktype, tsresol}
        pkt_no = 0

        while True:
            hdr = f.read(8)
            if not hdr:
                break
            if len(hdr) < 8:
                self.metadata.warnings.append("Truncated block header in PCAPNG")
                self.metadata.truncated = True
                break

            block_type = struct.unpack(f"{endian}I", hdr[:4])[0]
            block_total_len = struct.unpack(f"{endian}I", hdr[4:8])[0]

            if block_type == 0x0A0D0D0A:  # Section Header Block (SHB)
                bom_bytes = f.read(4)
                if len(bom_bytes) < 4:
                    self.metadata.warnings.append("Truncated SHB in PCAPNG")
                    self.metadata.truncated = True
                    break
                bom = struct.unpack(">I", bom_bytes)[0]
                if bom == 0x1A2B3C4D:
                    endian = ">"
                elif bom == 0x4D3C2B1A:
                    endian = "<"
                # Re-read block_total_len with proper endianness
                block_total_len = struct.unpack(f"{endian}I", hdr[4:8])[0]
                remaining = block_total_len - 12
                if remaining > 0:
                    f.seek(remaining, 1)
                interfaces = []
                continue

            body_len = block_total_len - 12
            if body_len < 0:
                self.metadata.warnings.append("Invalid PCAPNG block length")
                self.metadata.truncated = True
                break

            body = f.read(body_len)
            trailer = f.read(4)
            if len(body) < body_len or len(trailer) < 4:
                self.metadata.warnings.append("Truncated PCAPNG block body")
                self.metadata.truncated = True
                break

            if block_type == 0x00000001:  # Interface Description Block (IDB)
                if len(body) >= 8:
                    link_type, _, snaplen = struct.unpack(f"{endian}HHI", body[:8])
                    tsresol = 1e-6
                    opt_offset = 8
                    while opt_offset + 4 <= len(body):
                        opt_code, opt_len = struct.unpack(f"{endian}HH", body[opt_offset : opt_offset + 4])
                        opt_offset += 4
                        if opt_code == 0:
                            break
                        if opt_code == 9 and opt_len >= 1 and opt_offset < len(body):
                            res_val = body[opt_offset]
                            if res_val & 0x80:
                                tsresol = 2 ** -(res_val & 0x7F)
                            else:
                                tsresol = 10 ** -res_val
                        padded_len = (opt_len + 3) & ~3
                        opt_offset += padded_len
                    interfaces.append({"linktype": link_type, "tsresol": tsresol, "snaplen": snaplen})
                else:
                    interfaces.append({"linktype": LINKTYPE_ETHERNET, "tsresol": 1e-6, "snaplen": 65535})

            elif block_type == 0x00000006:  # Enhanced Packet Block (EPB)
                if len(body) >= 20:
                    if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[:20])
                    if if_id < len(interfaces):
                        if_info = interfaces[if_id]
                    else:
                        if_info = {"linktype": LINKTYPE_ETHERNET, "tsresol": 1e-6}

                    linktype = if_info["linktype"]
                    ts_raw = (ts_hi << 32) | ts_lo
                    ts = float(ts_raw) * if_info["tsresol"]

                    packet_data = body[20 : 20 + cap_len]
                    if len(packet_data) < cap_len:
                        self.metadata.warnings.append("Truncated packet payload in EPB")
                        self.metadata.truncated = True
                        break

                    pkt_no += 1
                    self._record_frame_meta(ts, orig_len, linktype)
                    yield RawFrame(
                        pkt_no=pkt_no,
                        ts=ts,
                        linktype=linktype,
                        raw_bytes=packet_data,
                        orig_len=orig_len,
                    )
            elif block_type == 0x00000003:  # Simple Packet Block (SPB)
                if len(body) >= 4 and len(interfaces) > 0:
                    orig_len = struct.unpack(f"{endian}I", body[:4])[0]
                    linktype = interfaces[0]["linktype"]
                    cap_len = min(len(body) - 4, orig_len)
                    packet_data = body[4 : 4 + cap_len]
                    pkt_no += 1
                    ts = 0.0
                    self._record_frame_meta(ts, orig_len, linktype)
                    yield RawFrame(
                        pkt_no=pkt_no,
                        ts=ts,
                        linktype=linktype,
                        raw_bytes=packet_data,
                        orig_len=orig_len,
                    )
