"""ESP and AH flow tracking state machine — TASK-019.

FR-35, FR-36, FR-40, FR-41 per SPEC §5.6:
- Groups directional ESP/AH packets by (src, dst, spi, encap).
- Tracks sequence numbers: gaps, duplicates, reorders, wrap_near.
- Keeps bounded memory: counters, <= 200 gaps, <= 1024 recent window,
  <= 50 sample prefixes (64 bytes), <= 500 downsampled (ts, seq) points.
- Never stores full payloads.
"""

from __future__ import annotations

import collections
import struct
from typing import Any, Literal

from analyzer.models import FlowSeqStats, IpsecFlow


class FlowTrackerState:
    """Internal state for tracking a single directional IPsec flow."""

    def __init__(
        self,
        flow_id: str,
        proto: Literal["esp", "ah"],
        src: str,
        dst: str,
        spi: str,
        encap: Literal["raw", "natt"],
        first_ts: float,
        first_pkt_no: int,
    ) -> None:
        self.flow_id = flow_id
        self.proto = proto
        self.src = src
        self.dst = dst
        self.spi = spi.lower()
        self.encap = encap
        self.first_ts = first_ts
        self.last_ts = first_ts

        self.packet_count: int = 0
        self.byte_count: int = 0

        # Sequence tracking
        self.last_seq: int | None = None
        self.max_seq: int = 0
        self.gaps: list[tuple[int, int, int]] = []  # (start_seq, end_seq, pkt_no)
        self.duplicates: int = 0
        self.reorders: int = 0
        self.wrap_near: bool = False

        # Sliding window for duplicates/reorders (max 1024)
        self._recent_deque: collections.deque[int] = collections.deque(maxlen=1024)
        self._recent_set: set[int] = set()

        # Samples (bounded)
        self.sample_pkt_nos: list[int] = []
        self.sample_payload_prefixes: list[bytes] = []
        self.downsampled_points: list[tuple[float, int]] = []  # (ts, seq)
        self.packet_sizes: list[int] = []

    def process_packet(
        self,
        seq: int,
        pkt_no: int,
        ts: float,
        packet_len: int,
        payload_prefix: bytes,
    ) -> None:
        """Process one ESP/AH packet for this flow."""
        self.packet_count += 1
        self.byte_count += packet_len
        self.last_ts = max(self.last_ts, ts)

        if len(self.sample_pkt_nos) < 50:
            self.sample_pkt_nos.append(pkt_no)
        if len(self.sample_payload_prefixes) < 50:
            self.sample_payload_prefixes.append(payload_prefix[:64])
        if len(self.downsampled_points) < 500:
            self.downsampled_points.append((ts, seq))

        # Update max seq and wrap_near
        if seq > self.max_seq:
            self.max_seq = seq
        if self.max_seq > 0xFFFFFF00:
            self.wrap_near = True

        # Sequence anomaly logic per SPEC §5.6
        if self.last_seq is None:
            # First packet
            self.last_seq = seq
        else:
            if seq == self.last_seq + 1:
                # Normal in-order progression
                self.last_seq = seq
            elif seq > self.last_seq + 1:
                # Gap detected
                gap_start = self.last_seq + 1
                gap_end = seq - 1
                if len(self.gaps) < 200:
                    self.gaps.append((gap_start, gap_end, pkt_no))
                self.last_seq = seq
            else:
                # seq <= self.last_seq
                is_duplicate = (seq == self.last_seq) or (seq in self._recent_set)
                if is_duplicate:
                    self.duplicates += 1
                if seq < self.last_seq:
                    self.reorders += 1

        # Maintain recent window (cap 1024)
        if len(self._recent_deque) == 1024:
            oldest = self._recent_deque.popleft()
            self._recent_set.discard(oldest)
        self._recent_deque.append(seq)
        self._recent_set.add(seq)

    def to_model(self) -> IpsecFlow:
        """Export as Pydantic IpsecFlow model."""
        seq_stats = FlowSeqStats(
            max_seq=self.max_seq,
            gaps=list(self.gaps),
            duplicates=self.duplicates,
            reorders=self.reorders,
            wrap_near=self.wrap_near,
        )
        return IpsecFlow(
            id=self.flow_id,
            proto=self.proto,
            src=self.src,
            dst=self.dst,
            spi=self.spi,
            encap=self.encap,
            first_ts=self.first_ts,
            last_ts=self.last_ts,
            packets=self.packet_count,
            bytes=self.byte_count,
            seq=seq_stats,
            sample_pkt_nos=list(self.sample_pkt_nos),
        )


class FlowTracker:
    """Stateful tracker for all IPsec ESP and AH flows."""

    def __init__(self) -> None:
        self.flows: dict[str, FlowTrackerState] = {}

    def _flow_key(
        self,
        proto: Literal["esp", "ah"],
        src: str,
        dst: str,
        spi_hex: str,
        encap: Literal["raw", "natt"],
    ) -> str:
        return f"{proto}_{src}_{dst}_{spi_hex.lower()}_{encap}"

    def process_esp(
        self,
        src: str,
        dst: str,
        spi: int | str,
        seq: int,
        pkt_no: int,
        ts: float,
        packet_len: int,
        payload_prefix: bytes,
        encap: Literal["raw", "natt"] = "raw",
    ) -> FlowTrackerState:
        """Process an ESP packet."""
        spi_hex = f"{spi:08x}" if isinstance(spi, int) else spi.lower()
        key = self._flow_key("esp", src, dst, spi_hex, encap)
        state = self.flows.get(key)
        if state is None:
            state = FlowTrackerState(
                flow_id=key,
                proto="esp",
                src=src,
                dst=dst,
                spi=spi_hex,
                encap=encap,
                first_ts=ts,
                first_pkt_no=pkt_no,
            )
            self.flows[key] = state

        state.process_packet(
            seq=seq,
            pkt_no=pkt_no,
            ts=ts,
            packet_len=packet_len,
            payload_prefix=payload_prefix,
        )
        return state

    def process_ah(
        self,
        src: str,
        dst: str,
        spi: int | str,
        seq: int,
        pkt_no: int,
        ts: float,
        packet_len: int,
        payload_prefix: bytes,
        encap: Literal["raw", "natt"] = "raw",
    ) -> FlowTrackerState:
        """Process an AH packet."""
        spi_hex = f"{spi:08x}" if isinstance(spi, int) else spi.lower()
        key = self._flow_key("ah", src, dst, spi_hex, encap)
        state = self.flows.get(key)
        if state is None:
            state = FlowTrackerState(
                flow_id=key,
                proto="ah",
                src=src,
                dst=dst,
                spi=spi_hex,
                encap=encap,
                first_ts=ts,
                first_pkt_no=pkt_no,
            )
            self.flows[key] = state

        state.process_packet(
            seq=seq,
            pkt_no=pkt_no,
            ts=ts,
            packet_len=packet_len,
            payload_prefix=payload_prefix,
        )
        return state

    def get_flows(self) -> list[IpsecFlow]:
        """Return all tracked flows as Pydantic models."""
        return [state.to_model() for state in self.flows.values()]


def parse_esp_packet(payload: bytes) -> tuple[int, int, bytes] | None:
    """Extract (spi, seq, payload_after_esp_hdr) from raw ESP or NAT-T ESP payload."""
    if len(payload) < 8:
        return None
    spi, seq = struct.unpack_from(">II", payload, 0)
    return spi, seq, payload[8:]
