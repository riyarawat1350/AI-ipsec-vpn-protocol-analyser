"""IPv4 fragment reassembly with strict memory bounds and timeouts (FR-11)."""

import struct
from dataclasses import dataclass, field

from analyzer.models import DecodedPacket


@dataclass
class FragmentChunk:
    """A single fragment chunk."""

    offset: int
    data: bytes
    pkt_no: int


@dataclass
class DefragFlow:
    """State tracking for a fragmented packet key (src, dst, id, proto)."""

    src: str
    dst: str
    frag_id: int
    ip_proto: int
    first_ts: float
    last_ts: float
    chunks: list[FragmentChunk] = field(default_factory=list)
    has_last: bool = False
    total_len_expected: int | None = None
    bytes_stored: int = 0


class IPv4Defragmenter:
    """Bounded, timeout-aware IPv4 defragmenter."""

    def __init__(
        self,
        max_fragments_per_packet: int = 64,
        max_cache_entries: int = 1000,
        max_cache_bytes: int = 10 * 1024 * 1024,  # 10 MB limit
        timeout_seconds: float = 30.0,
    ) -> None:
        self.max_fragments_per_packet = max_fragments_per_packet
        self.max_cache_entries = max_cache_entries
        self.max_cache_bytes = max_cache_bytes
        self.timeout_seconds = timeout_seconds

        self._flows: dict[tuple[str, str, int, int], DefragFlow] = {}
        self._current_cache_bytes: int = 0
        self.warnings: list[str] = []

    def process(self, pkt: DecodedPacket) -> DecodedPacket | None:
        """Process a packet.

        If packet is unfragmented, returns it immediately.
        If packet is a fragment, buffers it and returns the reassembled packet
        when complete, or None if still awaiting fragments.
        """
        if not pkt.is_fragment:
            return pkt

        frag_id = pkt.frag_id if pkt.frag_id is not None else 0
        key = (pkt.src, pkt.dst, frag_id, pkt.ip_proto)
        now = pkt.ts

        # 1. Clean expired entries
        self._purge_expired(now)

        # 2. Check cache limits before inserting
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self.max_cache_entries:
                self.warnings.append(
                    f"Defrag cache entries limit reached ({self.max_cache_entries}). Discarding fragment."
                )
                return None
            flow = DefragFlow(
                src=pkt.src,
                dst=pkt.dst,
                frag_id=frag_id,
                ip_proto=pkt.ip_proto,
                first_ts=now,
                last_ts=now,
            )
            self._flows[key] = flow

        # Check fragment count per packet
        if len(flow.chunks) >= self.max_fragments_per_packet:
            self.warnings.append(
                f"Packet {pkt.pkt_no}: Exceeded maximum fragment count ({self.max_fragments_per_packet}) for id={frag_id}. Discarding flow."
            )
            self._evict_flow(key)
            return None

        # Check memory bounds
        frag_bytes_len = len(pkt.payload)
        if self._current_cache_bytes + frag_bytes_len > self.max_cache_bytes:
            self.warnings.append(
                f"Packet {pkt.pkt_no}: Defragmenter memory limit ({self.max_cache_bytes} bytes) exceeded. Discarding flow."
            )
            self._evict_flow(key)
            return None

        # Detect overlapping fragments
        chunk_offset = pkt.frag_offset
        chunk_end = chunk_offset + frag_bytes_len

        for existing in flow.chunks:
            existing_end = existing.offset + len(existing.data)
            # Overlap check
            if max(chunk_offset, existing.offset) < min(chunk_end, existing_end):
                self.warnings.append(
                    f"Packet {pkt.pkt_no}: Overlapping fragment detected for id={frag_id} (offset {chunk_offset} vs {existing.offset}). Discarding flow."
                )
                self._evict_flow(key)
                return None

        # Append chunk
        flow.chunks.append(FragmentChunk(offset=chunk_offset, data=pkt.payload, pkt_no=pkt.pkt_no))
        flow.chunks.sort(key=lambda c: c.offset)
        flow.bytes_stored += frag_bytes_len
        self._current_cache_bytes += frag_bytes_len
        flow.last_ts = now

        if not pkt.more_fragments:
            flow.has_last = True
            flow.total_len_expected = chunk_end

        # Check if complete
        if flow.has_last and flow.total_len_expected is not None:
            reassembled_data = self._check_and_reassemble(flow)
            if reassembled_data is not None:
                first_pkt_no = flow.chunks[0].pkt_no
                self._evict_flow(key)

                sport: int | None = None
                dport: int | None = None
                payload = reassembled_data

                # If UDP (proto 17), first 8 bytes of reassembled buffer are the UDP header
                if pkt.ip_proto == 17:
                    if len(reassembled_data) >= 8:
                        sport, dport, udp_len = struct.unpack(">HHH", reassembled_data[:6])
                        p_len = min(len(reassembled_data), udp_len) if udp_len >= 8 else len(reassembled_data)
                        payload = reassembled_data[8:p_len]

                return DecodedPacket(
                    pkt_no=first_pkt_no,
                    ts=now,
                    src=pkt.src,
                    dst=pkt.dst,
                    ip_proto=pkt.ip_proto,
                    sport=sport,
                    dport=dport,
                    payload=payload,
                    reassembled=True,
                    is_fragment=False,
                )

        return None

    def _check_and_reassemble(self, flow: DefragFlow) -> bytes | None:
        """If all contiguous fragments from offset 0 to total_len_expected are present, reassemble."""
        if not flow.chunks or flow.chunks[0].offset != 0:
            return None

        current_offset = 0
        parts: list[bytes] = []

        for chunk in flow.chunks:
            if chunk.offset != current_offset:
                # Gap in sequence
                return None
            parts.append(chunk.data)
            current_offset += len(chunk.data)

        if current_offset == flow.total_len_expected:
            return b"".join(parts)
        return None

    def _evict_flow(self, key: tuple[str, str, int, int]) -> None:
        """Evict flow and deduct its memory from total cache bytes."""
        flow = self._flows.pop(key, None)
        if flow:
            self._current_cache_bytes = max(0, self._current_cache_bytes - flow.bytes_stored)

    def _purge_expired(self, now: float) -> None:
        """Purge flows that have timed out."""
        expired = [
            k for k, flow in self._flows.items() if now - flow.first_ts > self.timeout_seconds
        ]
        for k in expired:
            self.warnings.append(f"Fragment flow {k} timed out after {self.timeout_seconds}s. Evicted.")
            self._evict_flow(k)
