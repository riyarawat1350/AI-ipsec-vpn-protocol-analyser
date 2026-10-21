"""IKEv2 packet parser — TASK-014.

FR-20, FR-21, FR-23, FR-25..FR-28, FR-34.

Parses raw IKEv2 datagrams (starting at byte 0 of the IKE header) without
using tshark/pyshark. Payload length lies produce anomaly annotations, never
exceptions.  SK payloads are marked as encrypted and not further decoded.
"""

from __future__ import annotations

import struct

from analyzer.ike.common import (
    IKEMessage,
    IKEPayload,
    IKEProposal,
    IKETransform,
    ParseError,
    hex_spi,
    iter_payloads,
    protocol_name,
)
from analyzer.ike.constants import (
    ikev2_exchange_name,
    notify_name,
    payload_name,
    transform_name,
)

# IKEv2 flag bits (RFC 7296 §3.1)
_FLAG_RESPONSE = 0x20
_FLAG_VERSION  = 0x10
_FLAG_INITIATOR = 0x08

# IKEv2 payload type constants
_PL_SA     = 33
_PL_KE     = 34
_PL_IDi    = 35
_PL_IDr    = 36
_PL_CERT   = 37
_PL_CERTREQ = 38
_PL_AUTH   = 39
_PL_NONCE  = 40
_PL_NOTIFY = 41
_PL_DELETE = 42
_PL_VENDOR = 43
_PL_TSi    = 44
_PL_TSr    = 45
_PL_SK     = 46
_PL_CP     = 47
_PL_EAP    = 48
_PL_SKF    = 53

IKEv2_HEADER_LEN = 28  # bytes


def parse_ikev2_header(data: bytes) -> tuple[dict, int]:
    """Parse the 28-byte IKEv2 fixed header.

    Returns (header_dict, next_payload_start_offset).
    Raises ParseError if data is too short or version mismatch.
    """
    if len(data) < IKEv2_HEADER_LEN:
        raise ParseError(f"IKEv2 header requires 28 bytes, got {len(data)}")

    spi_i = data[0:8]
    spi_r = data[8:16]
    next_payload, version, exchange_type, flags = struct.unpack_from(">BBBB", data, 16)
    message_id, length = struct.unpack_from(">II", data, 20)

    major = (version >> 4) & 0x0F
    if major != 2:
        raise ParseError(f"Not an IKEv2 packet: major version = {major}")

    return {
        "spi_i": hex_spi(spi_i),
        "spi_r": hex_spi(spi_r),
        "next_payload": next_payload,
        "version": major,
        "exchange_type": exchange_type,
        "exchange_name": ikev2_exchange_name(exchange_type),
        "flags": flags,
        "is_response": bool(flags & _FLAG_RESPONSE),
        "is_initiator": bool(flags & _FLAG_INITIATOR),
        "message_id": message_id,
        "length": length,
    }, IKEv2_HEADER_LEN


def _parse_transform(data: bytes, offset: int) -> tuple[IKETransform, int]:
    """Parse one IKEv2 Transform substructure (RFC 7296 §3.3.2).

    Returns (IKETransform, new_offset). Does not raise.
    """
    if offset + 8 > len(data):
        raise ParseError("Transform: buffer too short for header")

    last_more, _, transform_len = struct.unpack_from(">BBH", data, offset)
    if transform_len < 8:
        raise ParseError(f"Transform length {transform_len} < 8")

    transform_type, _, transform_id = struct.unpack_from(">BBH", data, offset + 4)
    key_length: int | None = None
    raw_attrs: list[tuple[int, int | bytes]] = []

    # Parse transform attributes
    attr_offset = offset + 8
    end = offset + transform_len
    while attr_offset + 4 <= end:
        af_type, = struct.unpack_from(">H", data, attr_offset)
        is_tv = bool(af_type & 0x8000)
        attr_type = af_type & 0x7FFF
        if is_tv:
            val, = struct.unpack_from(">H", data, attr_offset + 2)
            if attr_type == 14:  # Key Length
                key_length = val
            raw_attrs.append((attr_type, val))
            attr_offset += 4
        else:
            attr_len, = struct.unpack_from(">H", data, attr_offset + 2)
            val_bytes = data[attr_offset + 4: attr_offset + 4 + attr_len]
            raw_attrs.append((attr_type, val_bytes))
            attr_offset += 4 + attr_len

    t = IKETransform(
        transform_type=transform_type,
        transform_id=transform_id,
        key_length=key_length,
        name=transform_name(transform_type, transform_id),
        raw_attrs=raw_attrs,
    )
    return t, offset + transform_len


def _parse_proposal(data: bytes, offset: int) -> tuple[IKEProposal, int]:
    """Parse one IKEv2 Proposal substructure (RFC 7296 §3.3.1).

    Returns (IKEProposal, new_offset).
    """
    if offset + 8 > len(data):
        raise ParseError("Proposal: buffer too short for header")

    last_more, _, prop_len, prop_num, proto_id, spi_size, num_transforms = \
        struct.unpack_from(">BBHBBBB", data, offset)

    if prop_len < 8:
        raise ParseError(f"Proposal length {prop_len} < 8")

    spi_end = offset + 8 + spi_size
    spi = data[offset + 8: spi_end]

    transforms: list[IKETransform] = []
    t_offset = spi_end
    for _ in range(num_transforms):
        if t_offset >= offset + prop_len:
            break
        try:
            t, t_offset = _parse_transform(data, t_offset)
            transforms.append(t)
        except ParseError:
            break

    return IKEProposal(
        num=prop_num,
        protocol_id=proto_id,
        protocol_name=protocol_name(proto_id),
        spi=spi,
        transforms=transforms,
    ), offset + prop_len


def _parse_sa_payload(body: bytes) -> list[IKEProposal]:
    """Parse SA payload body — list of proposals."""
    proposals: list[IKEProposal] = []
    offset = 0
    while offset < len(body):
        if offset + 8 > len(body):
            break
        last_more = body[offset]
        try:
            proposal, offset = _parse_proposal(body, offset)
            proposals.append(proposal)
        except ParseError:
            break
        if last_more == 0:  # last proposal
            break
    return proposals


def _parse_ke_payload(body: bytes) -> dict:
    """Parse KE payload body (RFC 7296 §3.4)."""
    if len(body) < 4:
        return {"dh_group": 0, "ke_data_len": 0}
    dh_group, _ = struct.unpack_from(">HH", body)
    ke_data = body[4:]
    return {"dh_group": dh_group, "ke_data_len": len(ke_data)}


def _parse_nonce_payload(body: bytes) -> dict:
    return {"nonce_len": len(body), "nonce_hex": body[:8].hex()}


def _parse_notify_payload(body: bytes) -> dict:
    """Parse Notify payload body (RFC 7296 §3.10)."""
    if len(body) < 4:
        return {"notify_type": 0, "notify_name": "TRUNCATED"}
    proto_id, spi_size, notify_type = struct.unpack_from(">BBH", body)
    spi = body[4: 4 + spi_size]
    notify_data = body[4 + spi_size:]
    return {
        "protocol_id": proto_id,
        "spi": spi.hex(),
        "notify_type": notify_type,
        "notify_name": notify_name(notify_type),
        "data_len": len(notify_data),
        "data_hex": notify_data[:16].hex(),
    }


def _parse_vendor_id(body: bytes) -> bytes:
    return body


def parse_ikev2(data: bytes, *, src_ip: str = "", dst_ip: str = "",
                src_port: int = 0, dst_port: int = 0,
                ts: float = 0.0, natt: bool = False) -> IKEMessage:
    """Parse a raw IKEv2 datagram into an IKEMessage.

    Never raises on malformed data — anomalies are recorded in IKEMessage.anomalies.
    """
    anomalies: list[str] = []

    try:
        hdr, payload_start = parse_ikev2_header(data)
    except ParseError as exc:
        # Return minimal message with anomaly note
        return IKEMessage(
            version=2, exchange_type=0, exchange_name="PARSE_FAILED",
            flags=0, message_id=0, length=len(data),
            spi_i="", spi_r="", is_initiator=False, is_response=False,
            encrypted=False, anomalies=[str(exc)],
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            ts=ts, natt=natt,
        )

    # Validate stated length vs actual
    if hdr["length"] != len(data):
        anomalies.append(
            f"Length field ({hdr['length']}) != actual datagram size ({len(data)})"
        )

    payload_data = data[payload_start:]
    raw_payloads = iter_payloads(payload_data, hdr["next_payload"])

    payloads: list[IKEPayload] = []
    proposals: list[IKEProposal] = []
    notifies: list[dict] = []
    vendor_ids: list[bytes] = []
    encrypted = False

    for ptype, critical, body in raw_payloads:
        pname = payload_name(ptype)
        parsed = None

        if ptype == _PL_SA:
            parsed = _parse_sa_payload(body)
            proposals.extend(parsed)
        elif ptype == _PL_KE:
            parsed = _parse_ke_payload(body)
        elif ptype == _PL_NONCE:
            parsed = _parse_nonce_payload(body)
        elif ptype == _PL_NOTIFY:
            parsed = _parse_notify_payload(body)
            notifies.append(parsed)
        elif ptype == _PL_VENDOR:
            parsed = _parse_vendor_id(body)
            vendor_ids.append(parsed)
        elif ptype in (_PL_SK, _PL_SKF):
            encrypted = True
            parsed = {"encrypted": True, "data_len": len(body)}

        payloads.append(IKEPayload(
            payload_type=ptype,
            payload_name=pname,
            critical=critical,
            data=body,
            parsed=parsed,
        ))

    return IKEMessage(
        version=2,
        exchange_type=hdr["exchange_type"],
        exchange_name=hdr["exchange_name"],
        flags=hdr["flags"],
        message_id=hdr["message_id"],
        length=hdr["length"],
        spi_i=hdr["spi_i"],
        spi_r=hdr["spi_r"],
        is_initiator=hdr["is_initiator"],
        is_response=hdr["is_response"],
        encrypted=encrypted,
        payloads=payloads,
        proposals=proposals,
        notifies=notifies,
        vendor_ids=vendor_ids,
        anomalies=anomalies,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ts=ts, natt=natt,
        raw_header=data[:IKEv2_HEADER_LEN],
    )
