"""Independent PCAP/PCAPNG decoder for IPsec Ground Truth Verification.

PHASE 1 REQUIREMENT:
- Does NOT import any module from `analyzer`.
- Decodes frames using Scapy's RawPcapReader / RawPcapNgReader.
- Uses its own struct-based decoding logic for link layers, IPv4/IPv6, UDP, IKEv1/IKEv2, ESP, AH.
- Optional cross-validation with tshark when installed.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from scapy.utils import RawPcapNgReader, RawPcapReader

# Locate tshark
TSHARK_CANDIDATES = [
    shutil.which("tshark"),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
TSHARK_BIN = next((c for c in TSHARK_CANDIDATES if c and Path(c).is_file()), None)


class IndependentDecoder:
    """Independent ground-truth decoder for IPsec captures."""

    def __init__(self, pcap_path: str | Path) -> None:
        self.path = Path(pcap_path)

    def decode(self) -> dict[str, Any]:
        """Decode capture file completely into ground truth facts."""
        if not self.path.exists():
            raise FileNotFoundError(f"File not found: {self.path}")

        # Choose reader
        frames: list[tuple[bytes, int]] = []
        is_pcapng = False
        try:
            with open(self.path, "rb") as f:
                magic = f.read(4)
                if magic == b"\n\r\r\n":
                    is_pcapng = True
        except Exception:
            pass

        if is_pcapng:
            reader = RawPcapNgReader(str(self.path))
            for raw_data, pkt_info in reader:
                link_type = getattr(pkt_info, "linktype", 1)
                frames.append((raw_data, link_type))
        else:
            reader = RawPcapReader(str(self.path))
            link_type = getattr(reader, "linktype", 1)
            for raw_data, pkt_info in reader:
                caplen = getattr(pkt_info, "caplen", len(raw_data))
                if len(raw_data) < caplen:
                    break
                frames.append((raw_data, link_type))

        protocol_counts = {
            "ike": 0,
            "esp": 0,
            "ah": 0,
            "natt_keepalive": 0,
            "other": 0,
        }
        ike_messages: list[dict[str, Any]] = []
        esp_packets: list[dict[str, Any]] = []
        ah_packets: list[dict[str, Any]] = []

        for pkt_no, (data, link_type) in enumerate(frames, start=1):
            ip_payload, proto, src_ip, dst_ip = self._parse_link_and_ip(data, link_type)
            if ip_payload is None:
                protocol_counts["other"] += 1
                continue

            if proto == 17:  # UDP
                if len(ip_payload) < 8:
                    protocol_counts["other"] += 1
                    continue
                src_port, dst_port, udp_len = struct.unpack("!HHH", ip_payload[:6])
                udp_data = ip_payload[8:udp_len] if udp_len >= 8 else ip_payload[8:]

                if src_port in (500, 4500) or dst_port in (500, 4500):
                    if src_port == 4500 or dst_port == 4500:
                        if udp_data == b"\xff":
                            protocol_counts["natt_keepalive"] += 1
                            continue
                        elif udp_data.startswith(b"\x00\x00\x00\x00"):
                            # Non-ESP Marker followed by IKE
                            protocol_counts["ike"] += 1
                            ike_info = self._parse_ike_message(pkt_no, udp_data[4:], src_ip, dst_ip, src_port, dst_port)
                            if ike_info:
                                ike_messages.append(ike_info)
                        else:
                            # NAT-T encapsulated ESP
                            protocol_counts["esp"] += 1
                            esp_info = self._parse_esp(pkt_no, udp_data, src_ip, dst_ip, is_natt=True)
                            if esp_info:
                                esp_packets.append(esp_info)
                    else:
                        # Port 500 standard IKE
                        protocol_counts["ike"] += 1
                        ike_info = self._parse_ike_message(pkt_no, udp_data, src_ip, dst_ip, src_port, dst_port)
                        if ike_info:
                            ike_messages.append(ike_info)
                else:
                    protocol_counts["other"] += 1

            elif proto == 50:  # Native ESP
                protocol_counts["esp"] += 1
                esp_info = self._parse_esp(pkt_no, ip_payload, src_ip, dst_ip, is_natt=False)
                if esp_info:
                    esp_packets.append(esp_info)

            elif proto == 51:  # AH
                protocol_counts["ah"] += 1
                ah_info = self._parse_ah(pkt_no, ip_payload, src_ip, dst_ip)
                if ah_info:
                    ah_packets.append(ah_info)

            else:
                protocol_counts["other"] += 1

        res: dict[str, Any] = {
            "file": self.path.name,
            "total_packets": len(frames),
            "protocol_counts": protocol_counts,
            "ike_messages": ike_messages,
            "esp_packets": esp_packets,
            "ah_packets": ah_packets,
        }

        # Compare with tshark if available
        if TSHARK_BIN:
            tshark_res = self._run_tshark()
            if tshark_res:
                res["tshark"] = tshark_res

        return res

    def _parse_link_and_ip(
        self, data: bytes, link_type: int
    ) -> tuple[bytes | None, int | None, str | None, str | None]:
        """Strip link layer and parse IP header."""
        if link_type == 1:  # Ethernet
            if len(data) < 14:
                return None, None, None, None
            eth_proto = struct.unpack("!H", data[12:14])[0]
            offset = 14
            if eth_proto == 0x8100:  # 802.1Q VLAN
                offset += 4
                if len(data) < offset:
                    return None, None, None, None
                eth_proto = struct.unpack("!H", data[offset - 2 : offset])[0]
            ip_data = data[offset:]
        elif link_type == 113:  # Linux SLL
            if len(data) < 16:
                return None, None, None, None
            eth_proto = struct.unpack("!H", data[14:16])[0]
            ip_data = data[16:]
        elif link_type == 276:  # Linux SLL2
            if len(data) < 20:
                return None, None, None, None
            eth_proto = struct.unpack("!H", data[0:2])[0]
            ip_data = data[20:]
        elif link_type in (101, 12):  # Raw IP
            ip_data = data
            eth_proto = 0x0800 if (data and (data[0] >> 4) == 4) else 0x86DD
        elif link_type == 0:  # Loopback
            ip_data = data[4:]
            eth_proto = 0x0800 if (ip_data and (ip_data[0] >> 4) == 4) else 0x86DD
        else:
            ip_data = data[14:] if len(data) >= 14 else data
            eth_proto = 0x0800

        if not ip_data:
            return None, None, None, None

        version = ip_data[0] >> 4
        if version == 4:
            if len(ip_data) < 20:
                return None, None, None, None
            ihl = (ip_data[0] & 0x0F) * 4
            proto = ip_data[9]
            src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
            dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"
            return ip_data[ihl:], proto, src_ip, dst_ip
        elif version == 6:
            if len(ip_data) < 40:
                return None, None, None, None
            proto = ip_data[6]
            import ipaddress
            src_ip = str(ipaddress.IPv6Address(ip_data[8:24]))
            dst_ip = str(ipaddress.IPv6Address(ip_data[24:40]))
            return ip_data[40:], proto, src_ip, dst_ip

        return None, None, None, None

    def _parse_esp(
        self, pkt_no: int, data: bytes, src_ip: str | None, dst_ip: str | None, is_natt: bool
    ) -> dict[str, Any] | None:
        if len(data) < 8:
            return None
        spi, seq = struct.unpack("!II", data[:8])
        return {
            "pkt_no": pkt_no,
            "spi": f"0x{spi:08x}",
            "seq": seq,
            "src": src_ip,
            "dst": dst_ip,
            "is_natt": is_natt,
            "len": len(data),
        }

    def _parse_ah(
        self, pkt_no: int, data: bytes, src_ip: str | None, dst_ip: str | None
    ) -> dict[str, Any] | None:
        if len(data) < 12:
            return None
        next_hdr, payload_len, reserved, spi, seq = struct.unpack("!BBHII", data[:12])
        return {
            "pkt_no": pkt_no,
            "spi": f"0x{spi:08x}",
            "seq": seq,
            "next_header": next_hdr,
            "src": src_ip,
            "dst": dst_ip,
            "len": len(data),
        }

    def _parse_ike_message(
        self, pkt_no: int, data: bytes, src_ip: str | None, dst_ip: str | None, src_port: int, dst_port: int
    ) -> dict[str, Any] | None:
        if len(data) < 28:
            return None

        spi_i, spi_r = data[:8], data[8:16]
        next_payload, version_byte, exchange_type, flags, msg_id, total_len = struct.unpack(
            "!BBBBII", data[16:28]
        )
        major = (version_byte >> 4) & 0x0F
        minor = version_byte & 0x0F

        proposals: list[dict[str, Any]] = []
        notifies: list[int] = []
        vendor_ids: list[str] = []

        curr_payload = next_payload
        offset = 28

        while curr_payload != 0 and offset + 4 <= len(data):
            np, reserved, plen = struct.unpack("!BBH", data[offset : offset + 4])
            if plen < 4 or offset + plen > len(data):
                break
            payload_data = data[offset + 4 : offset + plen]

            if major == 2:
                # IKEv2
                if curr_payload == 33:  # SA
                    proposals.extend(self._parse_ikev2_sa(payload_data))
                elif curr_payload == 41:  # Notify
                    if len(payload_data) >= 4:
                        proto_id, spi_sz, notify_type = struct.unpack("!BBH", payload_data[:4])
                        notifies.append(notify_type)
                elif curr_payload == 43:  # Vendor ID
                    vendor_ids.append(payload_data.hex())
            elif major == 1:
                # IKEv1
                if curr_payload == 1:  # SA
                    proposals.extend(self._parse_ikev1_sa(payload_data))
                elif curr_payload == 11:  # Notify
                    if len(payload_data) >= 8:
                        doi, proto_id, spi_sz, notify_type = struct.unpack("!IBBH", payload_data[:8])
                        notifies.append(notify_type)
                elif curr_payload == 13:  # Vendor ID
                    vendor_ids.append(payload_data.hex())

            curr_payload = np
            offset += plen

        return {
            "pkt_no": pkt_no,
            "version": major,
            "minor_version": minor,
            "spi_i": spi_i.hex(),
            "spi_r": spi_r.hex(),
            "exchange_type": exchange_type,
            "flags": flags,
            "is_initiator": bool(flags & 0x08) if major == 2 else bool(flags & 0x01 == 0),
            "is_response": bool(flags & 0x20) if major == 2 else bool(flags & 0x01),
            "msg_id": msg_id,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "proposals": proposals,
            "notifies": notifies,
            "vendor_ids": vendor_ids,
        }

    def _parse_ikev2_sa(self, sa_data: bytes) -> list[dict[str, Any]]:
        proposals: list[dict[str, Any]] = []
        p_offset = 0
        while p_offset + 8 <= len(sa_data):
            more, _, p_len, p_num, proto_id, spi_sz, num_transforms = struct.unpack(
                "!BBHBBBB", sa_data[p_offset : p_offset + 8]
            )
            if p_len < 8 or p_offset + p_len > len(sa_data):
                break

            t_offset = p_offset + 8 + spi_sz
            transforms: list[dict[str, Any]] = []
            while t_offset + 8 <= p_offset + p_len:
                t_more, _, t_len, t_type, _, t_id = struct.unpack(
                    "!BBHBBH", sa_data[t_offset : t_offset + 8]
                )
                if t_len < 8 or t_offset + t_len > p_offset + p_len:
                    break

                attr_dict = {}
                attr_offset = t_offset + 8
                while attr_offset + 4 <= t_offset + t_len:
                    attr_type_raw, attr_val = struct.unpack("!HH", sa_data[attr_offset : attr_offset + 4])
                    if attr_type_raw & 0x8000:
                        attr_type = attr_type_raw & 0x7FFF
                        attr_dict[attr_type] = attr_val
                        attr_offset += 4
                    else:
                        attr_len = attr_val
                        attr_offset += 4 + attr_len

                transforms.append({
                    "transform_type": t_type,
                    "transform_id": t_id,
                    "attributes": attr_dict,
                })
                t_offset += t_len
                if t_more == 0:
                    break

            proposals.append({
                "proposal_num": p_num,
                "protocol_id": proto_id,
                "transforms": transforms,
            })
            p_offset += p_len
            if more == 0:
                break

        return proposals

    def _parse_ikev1_sa(self, sa_data: bytes) -> list[dict[str, Any]]:
        proposals: list[dict[str, Any]] = []
        if len(sa_data) < 8:
            return proposals
        # Skip DOI (4 bytes) and Situation (4 bytes)
        p_offset = 8
        while p_offset + 8 <= len(sa_data):
            np, _, p_len, p_num, proto_id, spi_sz, num_transforms = struct.unpack(
                "!BBHBBBB", sa_data[p_offset : p_offset + 8]
            )
            if p_len < 8 or p_offset + p_len > len(sa_data):
                break

            t_offset = p_offset + 8 + spi_sz
            transforms: list[dict[str, Any]] = []
            while t_offset + 8 <= p_offset + p_len:
                t_np, _, t_len, t_num, t_id = struct.unpack(
                    "!BBHBB", sa_data[t_offset : t_offset + 6]
                )
                if t_len < 8 or t_offset + t_len > p_offset + p_len:
                    break

                attrs = {}
                attr_offset = t_offset + 8
                while attr_offset + 4 <= t_offset + t_len:
                    attr_type_raw, attr_val = struct.unpack("!HH", sa_data[attr_offset : attr_offset + 4])
                    if attr_type_raw & 0x8000:
                        attr_type = attr_type_raw & 0x7FFF
                        attrs[attr_type] = attr_val
                        attr_offset += 4
                    else:
                        attr_len = attr_val
                        attr_offset += 4 + attr_len

                transforms.append({
                    "transform_num": t_num,
                    "transform_id": t_id,
                    "attributes": attrs,
                })
                t_offset += t_len
                if t_np == 0:
                    break

            proposals.append({
                "proposal_num": p_num,
                "protocol_id": proto_id,
                "transforms": transforms,
            })
            p_offset += p_len
            if np == 0:
                break

        return proposals

    def _run_tshark(self) -> dict[str, Any] | None:
        """Run tshark to extract protocol counts and basic fields."""
        if not TSHARK_BIN:
            return None
        cmd = [
            str(TSHARK_BIN),
            "-r", str(self.path),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.proto",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "ike.ispi",
            "-e", "ike.rspi",
            "-e", "ike.version",
            "-e", "ike.exchangetype",
            "-e", "esp.spi",
            "-e", "esp.sequence",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if p.returncode != 0:
                return {"error": p.stderr.strip()[:200]}

            lines = [line_str for line_str in p.stdout.strip().splitlines() if line_str]
            ike_pkts = 0
            esp_pkts = 0
            for line_str in lines:
                parts = line_str.split("\t")
                # parts: frame.num, ip.proto, srcport, dstport, ispi, rspi, ver, exch, esp.spi, esp.seq
                if len(parts) >= 7 and parts[6]:  # ike.version present
                    ike_pkts += 1
                if len(parts) >= 9 and parts[8]:  # esp.spi present
                    esp_pkts += 1

            return {
                "total_frames": len(lines),
                "tshark_ike_count": ike_pkts,
                "tshark_esp_count": esp_pkts,
            }
        except Exception as e:
            return {"error": str(e)}


def decode_capture_file(path: str | Path) -> dict[str, Any]:
    decoder = IndependentDecoder(path)
    return decoder.decode()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/pcaps/ikev2_modp1024_3des.pcap"
    out = decode_capture_file(target)
    print(json.dumps(out, indent=2))
