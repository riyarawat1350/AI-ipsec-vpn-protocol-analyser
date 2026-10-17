"""Protocol classifier per SPEC §5.1 (FR-13..FR-17, FR-19).

Classifies each DecodedPacket into a protocol bucket and accumulates
statistics. No fake/hardcoded data — all counts are derived at runtime
from the actual decoded packets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from analyzer.models import DecodedPacket

# ---------------------------------------------------------------------------
# IKE port constants
# ---------------------------------------------------------------------------
IKE_PORT = 500
NATT_PORT = 4500

# IP protocol numbers (IANA)
PROTO_UDP: int = 17
PROTO_TCP: int = 6
PROTO_ESP: int = 50
PROTO_AH: int = 51
PROTO_ICMP: int = 1
PROTO_ICMPv6: int = 58


# ---------------------------------------------------------------------------
# Protocol bucket enum-like constants
# ---------------------------------------------------------------------------
class Protocol:
    IKEv1 = "ikev1"
    IKEv2 = "ikev2"
    IKE_UNKNOWN = "ike_unknown"
    ESP = "esp"
    AH = "ah"
    NAT_T = "natt"
    KEEPALIVE = "keepalive"
    OTHER_UDP = "other_udp"
    OTHER_TCP = "other_tcp"
    OTHER_IP = "other_ip"
    UNKNOWN = "unknown"


# NAT-T keepalive is a single 0xFF byte on port 4500
_KEEPALIVE_PAYLOAD = b"\xff"


@dataclass
class TalkerStats:
    """Per-IP address statistics."""

    ip: str
    packets: int = 0
    bytes: int = 0


@dataclass
class PortStats:
    """Per-port statistics."""

    port: int
    proto: str  # "udp" | "tcp"
    packets: int = 0


@dataclass
class ClassifierResult:
    """Complete protocol distribution and traffic statistics."""

    # Protocol bucket counters (packet count)
    counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Total packets / bytes processed
    total_packets: int = 0
    total_bytes: int = 0

    # Top talker tracking — maintained as dicts keyed by IP
    talkers: dict[str, TalkerStats] = field(default_factory=dict)

    # Port histogram — keyed by (port, proto_str)
    port_stats: dict[tuple[int, str], PortStats] = field(default_factory=dict)

    # First and last timestamps seen
    first_ts: float | None = None
    last_ts: float | None = None

    # Interface → frame count (from reader metadata if available)
    interfaces: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Link-type distribution
    link_types: dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Warnings from classification
    warnings: list[str] = field(default_factory=list)

    def protocol_distribution(self) -> dict[str, float]:
        """Return each protocol bucket as a fraction of total_packets."""
        if self.total_packets == 0:
            return {}
        return {proto: count / self.total_packets for proto, count in self.counts.items()}

    def top_talkers(self, n: int = 10) -> list[TalkerStats]:
        """Return top-n talkers by packet count."""
        return sorted(self.talkers.values(), key=lambda t: t.packets, reverse=True)[:n]

    def top_ports(self, n: int = 10) -> list[PortStats]:
        """Return top-n ports by packet count."""
        return sorted(self.port_stats.values(), key=lambda p: p.packets, reverse=True)[:n]

    def duration_seconds(self) -> float | None:
        """Capture duration in seconds, or None if fewer than 2 packets."""
        if self.first_ts is not None and self.last_ts is not None:
            return max(0.0, self.last_ts - self.first_ts)
        return None


class ProtocolClassifier:
    """Single-pass streaming protocol classifier.

    Call :meth:`process` for each :class:`~analyzer.models.DecodedPacket`
    decoded from the capture. When done, call :meth:`result` to obtain a
    :class:`ClassifierResult` with all statistics.

    No scapy / tshark — purely our own decode layer.
    """

    def __init__(self) -> None:
        self._result: ClassifierResult = ClassifierResult()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, pkt: DecodedPacket) -> str:
        """Classify *pkt* and update statistics.

        Returns the :class:`Protocol` bucket string assigned to this packet.
        """
        r = self._result
        r.total_packets += 1
        payload_len = len(pkt.payload)
        r.total_bytes += payload_len

        # Timestamp tracking
        if r.first_ts is None or pkt.ts < r.first_ts:
            r.first_ts = pkt.ts
        if r.last_ts is None or pkt.ts > r.last_ts:
            r.last_ts = pkt.ts

        # Source talker
        self._update_talker(pkt.src, payload_len)

        # Port stats
        proto_label = self._ip_proto_label(pkt.ip_proto)
        if pkt.sport is not None:
            self._update_port(pkt.sport, proto_label)
        if pkt.dport is not None:
            self._update_port(pkt.dport, proto_label)

        # Protocol bucket
        bucket = self._classify_bucket(pkt)
        r.counts[bucket] += 1

        return bucket

    def result(self) -> ClassifierResult:
        """Return the accumulated statistics."""
        return self._result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_bucket(self, pkt: DecodedPacket) -> str:
        """Determine the protocol bucket for *pkt*."""
        proto = pkt.ip_proto

        # ---------------------------------------------------------------
        # ESP (raw, FR-13)
        # ---------------------------------------------------------------
        if proto == PROTO_ESP:
            return Protocol.ESP

        # ---------------------------------------------------------------
        # AH (FR-14)
        # ---------------------------------------------------------------
        if proto == PROTO_AH:
            return Protocol.AH

        # ---------------------------------------------------------------
        # UDP-based protocols
        # ---------------------------------------------------------------
        if proto == PROTO_UDP:
            sport = pkt.sport
            dport = pkt.dport

            # NAT-T keepalive (single 0xFF byte on port 4500)
            if (
                (sport == NATT_PORT or dport == NATT_PORT)
                and pkt.payload == _KEEPALIVE_PAYLOAD
            ):
                return Protocol.KEEPALIVE

            # NAT-T encapsulated ESP — port 4500, ≥4 bytes, non-IKE header
            # The first 4 bytes of NAT-T ESP are the non-ESP marker (0x00000000 for IKE,
            # or SPI for ESP). SPI=0 means IKE.
            if sport == NATT_PORT or dport == NATT_PORT:
                if len(pkt.payload) >= 4:
                    spi_or_marker = int.from_bytes(pkt.payload[:4], "big")
                    if spi_or_marker == 0:
                        # IKE encapsulated in NAT-T
                        return self._classify_ike(pkt.payload[4:])
                    else:
                        # ESP-in-UDP
                        return Protocol.NAT_T
                return Protocol.NAT_T

            # Plain IKE on port 500
            if sport == IKE_PORT or dport == IKE_PORT:
                return self._classify_ike(pkt.payload)

            return Protocol.OTHER_UDP

        # ---------------------------------------------------------------
        # TCP
        # ---------------------------------------------------------------
        if proto == PROTO_TCP:
            return Protocol.OTHER_TCP

        # ---------------------------------------------------------------
        # Everything else
        # ---------------------------------------------------------------
        return Protocol.OTHER_IP

    def _classify_ike(self, payload: bytes) -> str:
        """Peek at IKE version byte to distinguish v1 vs v2.

        IKE header layout (RFC 7296 / RFC 2409):
            0–7   initiator SPI
            8–15  responder SPI
            16    next payload
            17    MjVer | MnVer  (upper nibble = major, lower = minor)
        """
        if len(payload) < 18:
            return Protocol.IKE_UNKNOWN
        version_byte = payload[17]
        major = (version_byte >> 4) & 0x0F
        if major == 2:
            return Protocol.IKEv2
        if major == 1:
            return Protocol.IKEv1
        self._result.warnings.append(
            f"Unknown IKE major version {major} (version byte 0x{version_byte:02x})"
        )
        return Protocol.IKE_UNKNOWN

    def _update_talker(self, ip: str, pkt_bytes: int) -> None:
        r = self._result
        if ip not in r.talkers:
            r.talkers[ip] = TalkerStats(ip=ip)
        r.talkers[ip].packets += 1
        r.talkers[ip].bytes += pkt_bytes

    def _update_port(self, port: int, proto_label: str) -> None:
        key = (port, proto_label)
        r = self._result
        if key not in r.port_stats:
            r.port_stats[key] = PortStats(port=port, proto=proto_label)
        r.port_stats[key].packets += 1

    @staticmethod
    def _ip_proto_label(ip_proto: int) -> str:
        if ip_proto == PROTO_UDP:
            return "udp"
        if ip_proto == PROTO_TCP:
            return "tcp"
        if ip_proto == PROTO_ESP:
            return "esp"
        if ip_proto == PROTO_AH:
            return "ah"
        return str(ip_proto)
