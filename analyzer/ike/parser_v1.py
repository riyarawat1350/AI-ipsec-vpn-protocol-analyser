"""IKEv1 / ISAKMP packet parser — TASK-015.

FR-22, FR-24, FR-29, FR-34.

Parses raw IKEv1 datagrams without tshark. Encrypted (E-flag) messages are
marked opaque and not decoded. Aggressive Mode ID/HASH extracted with optional
identity redaction.
"""

from __future__ import annotations

import struct
from typing import Any

from analyzer.ike.common import (
    IKEMessage, IKEPayload, IKEProposal, IKETransform,
    ParseError, hex_spi, iter_payloads, protocol_name,
)
from analyzer.ike.constants import (
    IKEv1_AUTH, IKEv1_ENCR, IKEv1_HASH, IKEv1_LIFE_TYPE,
    dh_name, ikev1_exchange_name, payload_name,
)

# IKEv1 flag bits (RFC 2408)
_FLAG_ENCRYPTION = 0x01
_FLAG_COMMIT = 0x02
_FLAG_AUTH_ONLY = 0x04

# IKEv1 payload types
_PL_SA = 1
_PL_PROP = 2
_PL_TRANS = 3
_PL_KE = 4
_PL_ID = 5
_PL_CERT = 6
_PL_CERTREQ = 7
_PL_HASH = 8
_PL_SIG = 9
_PL_NONCE = 10
_PL_NOTIFY = 11
_PL_DELETE = 12
_PL_VENDOR = 13
_PL_NAT_D = 20
_PL_NAT_OA = 21

# Attribute classes (RFC 2409)
_ATTR_ENCR = 1
_ATTR_HASH = 2
_ATTR_AUTH = 3
_ATTR_GROUP = 4
_ATTR_LIFE_TYPE = 11
_ATTR_LIFE_DURATION = 12
_ATTR_KEY_LENGTH = 14

IKEv1_HEADER_LEN = 28


def redact_identity(id_type: int, value: bytes, *, redact: bool = True) -> dict[str, Any]:
    """Return a redacted identity dict for storage/display (FR-29).

    Default: ``ID type + first 2 chars + ***``.
    """
    if not redact:
        return {"id_type": id_type, "value_hex": value.hex(), "redacted": False}
    preview = ""
    try:
        text = value.decode("utf-8", errors="replace")
        preview = (text[:2] + "***") if text else "***"
    except Exception:
        preview = value[:2].hex() + "***" if value else "***"
    return {
        "id_type": id_type,
        "value_preview": preview,
        "value_len": len(value),
        "redacted": True,
    }


def parse_ikev1_header(data: bytes) -> tuple[dict, int]:
    """Parse the 28-byte IKEv1/ISAKMP fixed header.

    Returns (header_dict, payload_start_offset).
    Raises ParseError if too short or version mismatch.
    """
    if len(data) < IKEv1_HEADER_LEN:
        raise ParseError(f"IKEv1 header requires 28 bytes, got {len(data)}")

    cookie_i = data[0:8]
    cookie_r = data[8:16]
    next_payload, version, exchange_type, flags = struct.unpack_from(">BBBB", data, 16)
    message_id_raw = data[20:24]
    length, = struct.unpack_from(">I", data, 24)

    major = (version >> 4) & 0x0F
    if major != 1:
        raise ParseError(f"Not an IKEv1 packet: major version = {major}")

    return {
        "spi_i": hex_spi(cookie_i),
        "spi_r": hex_spi(cookie_r),
        "next_payload": next_payload,
        "version": major,
        "exchange_type": exchange_type,
        "exchange_name": ikev1_exchange_name(exchange_type),
        "flags": flags,
        "encrypted": bool(flags & _FLAG_ENCRYPTION),
        "message_id": int.from_bytes(message_id_raw, "big"),
        "length": length,
    }, IKEv1_HEADER_LEN


def _parse_attributes(data: bytes) -> list[dict[str, Any]]:
    """Parse IKEv1 TV/TLV attribute list (RFC 2408 §3.3)."""
    attrs: list[dict[str, Any]] = []
    pos = 0
    while pos + 4 <= len(data):
        af_type, = struct.unpack_from(">H", data, pos)
        is_tv = bool(af_type & 0x8000)
        attr_type = af_type & 0x7FFF
        if is_tv:
            val, = struct.unpack_from(">H", data, pos + 2)
            attrs.append(_decorate_attr(attr_type, val))
            pos += 4
        else:
            attr_len, = struct.unpack_from(">H", data, pos + 2)
            if attr_len < 0 or pos + 4 + attr_len > len(data):
                break
            val_bytes = data[pos + 4: pos + 4 + attr_len]
            # Interpret short integer values when possible
            if attr_len == 2:
                val: int | bytes = struct.unpack(">H", val_bytes)[0]
            elif attr_len == 4:
                val = struct.unpack(">I", val_bytes)[0]
            else:
                val = val_bytes
            attrs.append(_decorate_attr(attr_type, val))
            pos += 4 + attr_len
    return attrs


def _decorate_attr(attr_type: int, value: int | bytes) -> dict[str, Any]:
    name = {
        _ATTR_ENCR: "encryption",
        _ATTR_HASH: "hash",
        _ATTR_AUTH: "auth_method",
        _ATTR_GROUP: "group_description",
        _ATTR_LIFE_TYPE: "life_type",
        _ATTR_LIFE_DURATION: "life_duration",
        _ATTR_KEY_LENGTH: "key_length",
    }.get(attr_type, f"attr_{attr_type}")

    resolved: str | None = None
    if isinstance(value, int):
        if attr_type == _ATTR_ENCR:
            resolved = IKEv1_ENCR.get(value, f"UNKNOWN({value})")
        elif attr_type == _ATTR_HASH:
            resolved = IKEv1_HASH.get(value, f"UNKNOWN({value})")
        elif attr_type == _ATTR_AUTH:
            resolved = IKEv1_AUTH.get(value, f"UNKNOWN({value})")
        elif attr_type == _ATTR_GROUP:
            resolved = dh_name(value)
        elif attr_type == _ATTR_LIFE_TYPE:
            resolved = IKEv1_LIFE_TYPE.get(value, f"UNKNOWN({value})")

    return {
        "type": attr_type,
        "name": name,
        "value": value if not isinstance(value, bytes) else value.hex(),
        "resolved": resolved,
    }


def _parse_transform(data: bytes, offset: int) -> tuple[IKETransform, int]:
    """Parse one IKEv1 Transform structure."""
    if offset + 8 > len(data):
        raise ParseError("Transform: buffer too short")
    # next(1) reserved(1) length(2) num(1) id(1) reserved(2)
    next_p, _, trans_len, trans_num, transform_id, _res = struct.unpack_from(
        ">BBHBBH", data, offset
    )
    if trans_len < 8:
        raise ParseError(f"Transform length {trans_len} < 8")
    attr_data = data[offset + 8: offset + trans_len]
    attrs = _parse_attributes(attr_data)

    key_length = None
    for a in attrs:
        if a["type"] == _ATTR_KEY_LENGTH and isinstance(a["value"], int):
            key_length = a["value"]

    # Build a human-readable name from encryption attr if present
    encr_attr = next((a for a in attrs if a["type"] == _ATTR_ENCR), None)
    name = encr_attr["resolved"] if encr_attr and encr_attr["resolved"] else f"TRANSFORM({transform_id})"

    t = IKETransform(
        transform_type=0,  # IKEv1 uses transform id differently
        transform_id=transform_id,
        key_length=key_length,
        name=name or "",
        raw_attrs=[(a["type"], a["value"]) for a in attrs],
    )
    # Attach full attrs for callers
    t.raw_attrs = [(a["type"], a["value"]) for a in attrs]  # type: ignore[assignment]
    # Store decorated attrs on a dynamic field via name reuse — also return via parsed
    object.__setattr__(t, "_v1_attrs", attrs)  # type: ignore[attr-defined]
    return t, offset + trans_len


def _parse_proposal(data: bytes, offset: int) -> tuple[IKEProposal, int]:
    """Parse one IKEv1 Proposal structure."""
    if offset + 8 > len(data):
        raise ParseError("Proposal: buffer too short")
    next_p, _, prop_len, prop_num, proto_id, spi_size, num_transforms = \
        struct.unpack_from(">BBHBBBB", data, offset)
    if prop_len < 8:
        raise ParseError(f"Proposal length {prop_len} < 8")
    spi = data[offset + 8: offset + 8 + spi_size]
    transforms: list[IKETransform] = []
    t_offset = offset + 8 + spi_size
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


def _parse_sa_payload(body: bytes) -> dict[str, Any]:
    """Parse IKEv1 SA payload: DOI + situation + proposals."""
    if len(body) < 8:
        return {"doi": 0, "situation": 0, "proposals": []}
    doi, situation = struct.unpack_from(">II", body)
    proposals: list[IKEProposal] = []
    offset = 8
    while offset < len(body):
        if offset + 8 > len(body):
            break
        next_byte = body[offset]
        try:
            prop, offset = _parse_proposal(body, offset)
            proposals.append(prop)
        except ParseError:
            break
        if next_byte == 0:
            break
    return {"doi": doi, "situation": situation, "proposals": proposals}


def _parse_id_payload(body: bytes) -> dict[str, Any]:
    """Parse IKEv1 Identification payload."""
    if len(body) < 4:
        return {"id_type": 0, "id_data": b""}
    id_type, = struct.unpack_from(">B", body)
    # 3 bytes reserved / protocol / port
    id_data = body[4:]
    return {"id_type": id_type, "id_data": id_data}


def parse_ikev1(
    data: bytes,
    *,
    src_ip: str = "",
    dst_ip: str = "",
    src_port: int = 0,
    dst_port: int = 0,
    ts: float = 0.0,
    natt: bool = False,
    redact_identities: bool = True,
) -> IKEMessage:
    """Parse a raw IKEv1 datagram into an IKEMessage.

    Never raises on malformed data — anomalies recorded on the message.
    """
    anomalies: list[str] = []

    try:
        hdr, payload_start = parse_ikev1_header(data)
    except ParseError as exc:
        return IKEMessage(
            version=1, exchange_type=0, exchange_name="PARSE_FAILED",
            flags=0, message_id=0, length=len(data),
            spi_i="", spi_r="", is_initiator=False, is_response=False,
            encrypted=False, anomalies=[str(exc)],
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            ts=ts, natt=natt,
        )

    if hdr["length"] != len(data):
        anomalies.append(
            f"Length field ({hdr['length']}) != actual datagram size ({len(data)})"
        )

    encrypted = hdr["encrypted"]
    payloads: list[IKEPayload] = []
    proposals: list[IKEProposal] = []
    notifies: list[dict] = []
    vendor_ids: list[bytes] = []
    v1_id: dict[str, Any] | None = None
    v1_hash_len: int | None = None

    # E-flag ⇒ opaque — do not walk payloads (FR-34)
    if encrypted:
        return IKEMessage(
            version=1,
            exchange_type=hdr["exchange_type"],
            exchange_name=hdr["exchange_name"],
            flags=hdr["flags"],
            message_id=hdr["message_id"],
            length=hdr["length"],
            spi_i=hdr["spi_i"],
            spi_r=hdr["spi_r"],
            is_initiator=hdr["spi_r"] == "0000000000000000",
            is_response=hdr["spi_r"] != "0000000000000000",
            encrypted=True,
            payloads=[],
            proposals=[],
            notifies=[],
            vendor_ids=[],
            anomalies=anomalies + ["encrypted_not_observable"],
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            ts=ts, natt=natt,
            raw_header=data[:IKEv1_HEADER_LEN],
        )

    payload_data = data[payload_start:]
    raw_payloads = iter_payloads(payload_data, hdr["next_payload"])

    for ptype, critical, body in raw_payloads:
        pname = payload_name(ptype, version=1)
        parsed: Any = None

        if ptype == _PL_SA:
            parsed = _parse_sa_payload(body)
            proposals.extend(parsed.get("proposals", []))
        elif ptype == _PL_KE:
            parsed = {"ke_data_len": len(body)}
        elif ptype == _PL_NONCE:
            parsed = {"nonce_len": len(body)}
        elif ptype == _PL_ID:
            raw_id = _parse_id_payload(body)
            v1_id = redact_identity(
                raw_id["id_type"], raw_id["id_data"], redact=redact_identities
            )
            parsed = v1_id
        elif ptype == _PL_HASH:
            v1_hash_len = len(body)
            parsed = {"hash_len": len(body)}
        elif ptype == _PL_NOTIFY:
            if len(body) >= 12:
                doi, protocol_id, spi_size, notify_type = struct.unpack_from(">IBBH", body)
                parsed = {
                    "doi": doi,
                    "protocol_id": protocol_id,
                    "notify_type": notify_type,
                    "data_len": len(body) - 12 - spi_size,
                }
                notifies.append(parsed)
            else:
                parsed = {"truncated": True}
        elif ptype == _PL_VENDOR:
            parsed = body
            vendor_ids.append(body)
        elif ptype in (_PL_NAT_D, _PL_NAT_OA):
            parsed = {"data_len": len(body)}

        payloads.append(IKEPayload(
            payload_type=ptype,
            payload_name=pname,
            critical=critical,
            data=body,
            parsed=parsed,
        ))

    # Initiator heuristic: first message of a pair has zero responder cookie
    is_initiator = hdr["spi_r"] == "0000000000000000"
    is_response = not is_initiator

    msg = IKEMessage(
        version=1,
        exchange_type=hdr["exchange_type"],
        exchange_name=hdr["exchange_name"],
        flags=hdr["flags"],
        message_id=hdr["message_id"],
        length=hdr["length"],
        spi_i=hdr["spi_i"],
        spi_r=hdr["spi_r"],
        is_initiator=is_initiator,
        is_response=is_response,
        encrypted=False,
        payloads=payloads,
        proposals=proposals,
        notifies=notifies,
        vendor_ids=vendor_ids,
        anomalies=anomalies,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ts=ts, natt=natt,
        raw_header=data[:IKEv1_HEADER_LEN],
    )
    # Attach AM-specific extras for callers
    object.__setattr__(msg, "v1_id", v1_id)
    object.__setattr__(msg, "v1_hash_len", v1_hash_len)
    return msg
