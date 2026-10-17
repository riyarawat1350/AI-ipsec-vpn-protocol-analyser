"""L2-L4 packet decoding for PCAP frames (FR-09, FR-10)."""

import socket
import struct

from analyzer.capture.linktypes import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_LOOPBACK_BSD,
    LINKTYPE_NULL,
    LINKTYPE_RAW_IP_12,
    LINKTYPE_RAW_IP_14,
    LINKTYPE_RAW_IP_101,
    is_supported_linktype,
)
from analyzer.capture.reader import RawFrame
from analyzer.models import DecodedPacket

# Ethertypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

# IPv6 Extension Headers to skip
IPV6_EXT_HEADERS = {0, 43, 60, 135}  # Hop-by-hop, Routing, Destination Options, Mobility


class PacketDecoder:
    """Decodes RawFrame into DecodedPacket."""

    def __init__(self) -> None:
        self.unsupported_linktypes: set[int] = set()

    def decode(self, frame: RawFrame) -> DecodedPacket | None:
        """Decode raw frame to DecodedPacket. Returns None if unparseable or unsupported."""
        b = frame.raw_bytes
        linktype = frame.linktype

        if not is_supported_linktype(linktype):
            if linktype not in self.unsupported_linktypes:
                self.unsupported_linktypes.add(linktype)
            return None

        # 1. Strip L2 header to get L3 payload and ethertype
        l3_bytes, ethertype = self._strip_l2(b, linktype)
        if not l3_bytes:
            return None

        # 2. Decode L3 (IPv4 / IPv6)
        if ethertype == ETHERTYPE_IPV4:
            return self._decode_ipv4(frame, l3_bytes)
        elif ethertype == ETHERTYPE_IPV6:
            return self._decode_ipv6(frame, l3_bytes)
        else:
            # Check if raw IP packet without explicit ethertype
            if len(l3_bytes) >= 20:
                ver = l3_bytes[0] >> 4
                if ver == 4:
                    return self._decode_ipv4(frame, l3_bytes)
                elif ver == 6 and len(l3_bytes) >= 40:
                    return self._decode_ipv6(frame, l3_bytes)
            return None

    def _strip_l2(self, b: bytes, linktype: int) -> tuple[bytes | None, int | None]:
        """Strip L2 header and return (l3_bytes, ethertype)."""
        if linktype == LINKTYPE_ETHERNET:
            if len(b) < 14:
                return None, None
            ethertype = struct.unpack(">H", b[12:14])[0]
            offset = 14
            # Handle 802.1Q and QinQ stacked VLANs
            while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and offset + 4 <= len(b):
                ethertype = struct.unpack(">H", b[offset + 2 : offset + 4])[0]
                offset += 4
            return b[offset:], ethertype

        elif linktype == LINKTYPE_LINUX_SLL:  # Cooked v1 (16 bytes)
            if len(b) < 16:
                return None, None
            protocol = struct.unpack(">H", b[14:16])[0]
            return b[16:], protocol

        elif linktype == LINKTYPE_LINUX_SLL2:  # Cooked v2 (20 bytes)
            if len(b) < 20:
                return None, None
            protocol = struct.unpack(">H", b[0:2])[0]
            return b[20:], protocol

        elif linktype in (LINKTYPE_RAW_IP_12, LINKTYPE_RAW_IP_14, LINKTYPE_RAW_IP_101):
            if not b:
                return None, None
            ver = b[0] >> 4
            return b, (ETHERTYPE_IPV4 if ver == 4 else ETHERTYPE_IPV6 if ver == 6 else None)

        elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOPBACK_BSD):
            if len(b) < 4:
                return None, None
            family = struct.unpack("=I", b[:4])[0]
            # AF_INET is 2 on almost all systems
            if family == 2:
                return b[4:], ETHERTYPE_IPV4
            elif family in (24, 28, 30):
                return b[4:], ETHERTYPE_IPV6
            # Fallback by examining IP version nibble
            if len(b) >= 5:
                ver = b[4] >> 4
                if ver == 4:
                    return b[4:], ETHERTYPE_IPV4
                elif ver == 6:
                    return b[4:], ETHERTYPE_IPV6
            return None, None

        return None, None

    def _decode_ipv4(self, frame: RawFrame, b: bytes) -> DecodedPacket | None:
        """Decode IPv4 header and L4 transport."""
        if len(b) < 20:
            return None

        ver_ihl = b[0]
        if (ver_ihl >> 4) != 4:
            return None

        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(b) < ihl:
            return None

        total_len = struct.unpack(">H", b[2:4])[0]
        frag_id = struct.unpack(">H", b[4:6])[0]
        flags_frag = struct.unpack(">H", b[6:8])[0]
        more_fragments = bool(flags_frag & 0x2000)
        frag_offset = (flags_frag & 0x1FFF) * 8
        is_fragment = more_fragments or (frag_offset > 0)

        ip_proto = b[9]
        src_ip = socket.inet_ntoa(b[12:16])
        dst_ip = socket.inet_ntoa(b[16:20])

        payload_end = min(len(b), total_len) if total_len >= ihl else len(b)
        l4_data = b[ihl:payload_end]

        sport: int | None = None
        dport: int | None = None
        payload: bytes = l4_data

        # Decode UDP (proto 17) if first fragment or unfragmented
        if ip_proto == 17:
            if frag_offset == 0 and len(l4_data) >= 8:
                sport, dport, udp_len = struct.unpack(">HHH", l4_data[:6])
                payload_len = min(len(l4_data), udp_len) if udp_len >= 8 else len(l4_data)
                payload = l4_data[8:payload_len]
            else:
                payload = l4_data
        elif ip_proto == 6:  # TCP
            if frag_offset == 0 and len(l4_data) >= 20:
                sport, dport = struct.unpack(">HH", l4_data[:4])
                tcp_hl = (l4_data[12] >> 4) * 4
                if tcp_hl >= 20 and len(l4_data) >= tcp_hl:
                    payload = l4_data[tcp_hl:]
                else:
                    payload = l4_data[20:]
            else:
                payload = l4_data
        else:
            # ESP (50), AH (51), etc.
            payload = l4_data

        return DecodedPacket(
            pkt_no=frame.pkt_no,
            ts=frame.ts,
            src=src_ip,
            dst=dst_ip,
            ip_proto=ip_proto,
            sport=sport,
            dport=dport,
            payload=payload,
            reassembled=False,
            is_fragment=is_fragment,
            frag_offset=frag_offset,
            more_fragments=more_fragments,
            frag_id=frag_id,
        )

    def _decode_ipv6(self, frame: RawFrame, b: bytes) -> DecodedPacket | None:
        """Decode IPv6 header, extensions, and L4 transport."""
        if len(b) < 40:
            return None

        ver = b[0] >> 4
        if ver != 6:
            return None

        payload_len = struct.unpack(">H", b[4:6])[0]
        next_hdr = b[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, b[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, b[24:40])

        offset = 40
        data_limit = min(len(b), 40 + payload_len) if payload_len > 0 else len(b)

        is_fragment = False
        frag_offset = 0
        more_fragments = False
        frag_id = None

        # Parse extension headers
        while next_hdr in IPV6_EXT_HEADERS or next_hdr == 44:
            if offset >= data_limit:
                break
            if next_hdr == 44:  # Fragment header (8 bytes)
                if offset + 8 > data_limit:
                    break
                next_hdr, _, frag_off_flags, f_id = struct.unpack(">BBHI", b[offset : offset + 8])
                is_fragment = True
                more_fragments = bool(frag_off_flags & 0x0001)
                frag_offset = frag_off_flags & 0xFFF8
                frag_id = f_id
                offset += 8
            elif next_hdr in IPV6_EXT_HEADERS:
                if offset + 2 > data_limit:
                    break
                next_hdr = b[offset]
                hdr_len = (b[offset + 1] + 1) * 8
                offset += hdr_len
            else:
                break

        l4_data = b[offset:data_limit]
        ip_proto = next_hdr
        sport: int | None = None
        dport: int | None = None
        payload = l4_data

        if ip_proto == 17:  # UDP
            if frag_offset == 0 and len(l4_data) >= 8:
                sport, dport, udp_len = struct.unpack(">HHH", l4_data[:6])
                p_len = min(len(l4_data), udp_len) if udp_len >= 8 else len(l4_data)
                payload = l4_data[8:p_len]
            else:
                payload = l4_data
        elif ip_proto == 6:  # TCP
            if frag_offset == 0 and len(l4_data) >= 20:
                sport, dport = struct.unpack(">HH", l4_data[:4])
                tcp_hl = (l4_data[12] >> 4) * 4
                if tcp_hl >= 20 and len(l4_data) >= tcp_hl:
                    payload = l4_data[tcp_hl:]
                else:
                    payload = l4_data[20:]
            else:
                payload = l4_data

        return DecodedPacket(
            pkt_no=frame.pkt_no,
            ts=frame.ts,
            src=src_ip,
            dst=dst_ip,
            ip_proto=ip_proto,
            sport=sport,
            dport=dport,
            payload=payload,
            reassembled=False,
            is_fragment=is_fragment,
            frag_offset=frag_offset,
            more_fragments=more_fragments,
            frag_id=frag_id,
        )
