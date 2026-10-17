"""IKE session reconstruction — TASK-017.

FR-30..FR-33 per SPEC §5.5:
- Groups individual IKE messages into bidirectional IKE sessions.
- Handles IKEv2 session keys: (initiator_ip, spi_i)
- Handles IKEv1 session keys: (cookie_i, cookie_r)
- Preserves single session through COOKIE and INVALID_KE_PAYLOAD retries
- Detects retransmissions
- Tracks offered and selected proposals
- Classifies outcome: established_observed, failed_notify, unanswered,
  incomplete_capture, unknown
- Populates encrypted_not_observable lists
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal
from analyzer.models import (
    Endpoint,
    IkeMessage,
    IkeNotify,
    IkeProposal,
    IkeSession,
    IkeTransform,
)
from analyzer.ike.common import IKEMessage


def ikemessage_to_model(
    msg: IKEMessage,
    pkt_no: int,
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    natt: bool = False,
    raw_bytes: bytes = b"",
) -> IkeMessage:
    """Convert an IKEMessage dataclass into an IkeMessage Pydantic model."""
    _KIND_MAP = {
        1: "ENCR",
        2: "PRF",
        3: "INTEG",
        4: "DH",
        5: "ESN",
    }
    proposals_model: list[IkeProposal] = []
    for prop in msg.proposals:
        transforms_model = []
        for t in prop.transforms:
            kind_str = getattr(t, "kind", None)
            if not kind_str:
                ttype = getattr(t, "transform_type", 1)
                kind_str = _KIND_MAP.get(ttype, "ENCR")
            tid = getattr(t, "id", None)
            if tid is None:
                tid = getattr(t, "transform_id", 0)
            tname = getattr(t, "name", "")
            tkey_len = getattr(t, "key_length", None)
            transforms_model.append(
                IkeTransform(
                    kind=kind_str,  # type: ignore[arg-type]
                    id=tid,
                    name=tname,
                    key_length=tkey_len,
                )
            )

        proto_val = getattr(prop, "protocol_name", None) or getattr(prop, "protocol", "IKE")
        proto_literal = proto_val if proto_val in ("IKE", "ESP", "AH") else "IKE"
        proposals_model.append(
            IkeProposal(
                num=prop.num,
                protocol=proto_literal,  # type: ignore[arg-type]
                transforms=transforms_model,
            )
        )

    notifies_model: list[IkeNotify] = []
    for n in msg.notifies:
        if isinstance(n, dict):
            notifies_model.append(
                IkeNotify(
                    type=n.get("notify_type", 0),
                    name=n.get("notify_name", ""),
                    protocol_id=n.get("protocol_id", 0),
                    data_len=n.get("data_len", 0),
                    data_hex=n.get("data_hex"),
                )
            )
        else:
            notifies_model.append(
                IkeNotify(
                    type=n.type,
                    name=n.name,
                    protocol_id=getattr(n, "protocol_id", 0),
                    data_len=getattr(n, "data_len", len(getattr(n, "data", b""))),
                    data_hex=getattr(n, "data_hex", getattr(n, "data", b"").hex() if getattr(n, "data", b"") else None),
                )
            )

    raw_header_hex = raw_bytes[:28].hex() if raw_bytes else ""
    raw_excerpt_hex = raw_bytes[28:92].hex() if len(raw_bytes) > 28 else ""

    spi_i_str = msg.spi_i if isinstance(msg.spi_i, str) else msg.spi_i.hex()
    spi_r_str = msg.spi_r if isinstance(msg.spi_r, str) else msg.spi_r.hex()

    direction_val: Literal["i2r", "r2i"] = "i2r"
    if hasattr(msg, "is_initiator"):
        direction_val = "i2r" if msg.is_initiator else "r2i"
    elif hasattr(msg, "direction"):
        direction_val = "i2r" if msg.direction == "i2r" else "r2i"
    elif msg.version == 2:
        direction_val = "i2r" if (msg.flags & 0x08) != 0 else "r2i"

    vids = []
    for v in msg.vendor_ids:
        vids.append(v.hex().lower() if isinstance(v, bytes) else str(v).lower())

    return IkeMessage(
        pkt_no=pkt_no,
        ts=ts,
        src=Endpoint(ip=src_ip, port=src_port),
        dst=Endpoint(ip=dst_ip, port=dst_port),
        natt=natt,
        version=msg.version,
        exchange_type=msg.exchange_type,
        exchange_name=msg.exchange_name,
        flags=msg.flags,
        message_id=msg.message_id,
        length=msg.length,
        spi_i=spi_i_str.lower(),
        spi_r=spi_r_str.lower(),
        direction=direction_val,
        payload_types=[p.payload_type for p in msg.payloads] if msg.payloads else [],
        encrypted=msg.encrypted,
        proposals=proposals_model,
        ke_group=getattr(msg, "ke_group", None),
        ke_len=getattr(msg, "ke_len", None),
        nonce_len=getattr(msg, "nonce_len", None),
        notifies=notifies_model,
        vendor_ids=vids,
        nat_detection=[n.hex().lower() if isinstance(n, bytes) else str(n).lower() for n in getattr(msg, "nat_detection", [])],
        v1_id=getattr(msg, "v1_id", None),
        v1_hash_len=getattr(msg, "v1_hash_len", None),
        anomalies=msg.anomalies,
        raw_header_hex=raw_header_hex,
        raw_excerpt_hex=raw_excerpt_hex,
    )


class IkeSessionReconstructor:
    """Stateful IKE session reconstructor adhering to SPEC §5.5."""

    def __init__(self) -> None:
        self.sessions: dict[str, IkeSession] = {}
        # Mapping from (cookie_i, "0000000000000000") to established session id for IKEv1
        self._v1_initiator_map: dict[str, str] = {}
        # Mapping from (initiator_ip, spi_i) to session id for IKEv2
        self._v2_initiator_map: dict[tuple[str, str], str] = {}
        # Fallback mapping from spi_i to session id for IKEv2
        self._v2_spi_map: dict[str, str] = {}
        # Track seen message signatures for retransmission detection:
        # session_id -> set of (direction, exchange_type, message_id, payload_hash)
        self._seen_signatures: dict[str, set[tuple[str, int, int, str]]] = {}

    def _message_hash(self, msg: IkeMessage) -> str:
        h = hashlib.sha256()
        h.update(f"{msg.version}_{msg.exchange_type}_{msg.message_id}_{msg.flags}_{msg.raw_header_hex}_{msg.raw_excerpt_hex}".encode())
        return h.hexdigest()

    def process_message(self, msg: IkeMessage) -> IkeSession:
        """Process an IkeMessage and add it to its reconstructed session."""
        if msg.version == 2:
            return self._process_ikev2(msg)
        return self._process_ikev1(msg)

    def _process_ikev2(self, msg: IkeMessage) -> IkeSession:
        spi_i = msg.spi_i
        spi_r = msg.spi_r
        is_initiator = (msg.direction == "i2r")
        initiator_ip = msg.src.ip if is_initiator else msg.dst.ip
        key = (initiator_ip, spi_i)

        session_id = self._v2_initiator_map.get(key)
        if not session_id and spi_i in self._v2_spi_map:
            session_id = self._v2_spi_map[spi_i]

        session: IkeSession | None = self.sessions.get(session_id) if session_id else None

        if session is None:
            # Create a new IKEv2 session
            session_id = f"ikev2_{initiator_ip}_{spi_i}"
            init_ep = msg.src if is_initiator else msg.dst
            resp_ep = msg.dst if is_initiator else msg.src
            session = IkeSession(
                id=session_id,
                version=2,
                spi_i=spi_i,
                spi_r=spi_r if spi_r != "0000000000000000" else None,
                initiator=init_ep,
                responder=resp_ep,
                natt=msg.natt,
                first_ts=msg.ts,
                last_ts=msg.ts,
                messages=[],
                offered=[],
                selected=None,
                outcome="unknown",
                retransmissions=0,
                ke_retries=0,
                aggressive_mode=False,
                encrypted_not_observable=[
                    "IKE_AUTH identities (IDi, IDr)",
                    "IKE_AUTH authentication credentials (AUTH)",
                    "Child SA (ESP/AH) proposal parameters",
                    "Traffic selectors (TSi, TSr)",
                ],
            )
            self.sessions[session_id] = session
            self._v2_initiator_map[key] = session_id
            self._v2_spi_map[spi_i] = session_id
            self._seen_signatures[session_id] = set()

        # Update last_ts
        session.last_ts = max(session.last_ts, msg.ts)
        if msg.natt:
            session.natt = True

        # Update spi_r if not set yet and responder provides one
        if not session.spi_r and spi_r != "0000000000000000":
            session.spi_r = spi_r

        # Check for retransmission
        sig = (msg.direction, msg.exchange_type, msg.message_id, self._message_hash(msg))
        if sig in self._seen_signatures[session.id]:
            session.retransmissions += 1
        else:
            self._seen_signatures[session.id].add(sig)

        # Check for INVALID_KE_PAYLOAD retry (notify type 17)
        if any(n.type == 17 for n in msg.notifies):
            session.ke_retries += 1

        # Track proposals:
        # IKE_SA_INIT is exchange_type 34
        if msg.exchange_type == 34:
            if is_initiator and msg.proposals and not session.offered:
                session.offered = list(msg.proposals)
            elif not is_initiator and msg.proposals and session.selected is None:
                session.selected = msg.proposals[0]

        session.messages.append(msg)
        self._update_ikev2_outcome(session)
        return session

    def _update_ikev2_outcome(self, session: IkeSession) -> None:
        has_initiator = any(m.direction == "i2r" for m in session.messages)
        has_responder = any(m.direction == "r2i" for m in session.messages)

        if not has_responder:
            session.outcome = "unanswered"
            return

        if not has_initiator and has_responder:
            session.outcome = "incomplete_capture"
            return

        # Check for error notify from responder (type < 16384)
        for m in session.messages:
            if m.direction == "r2i":
                if any(n.type < 16384 for n in m.notifies):
                    session.outcome = "failed_notify"
                    return

        # Check for established:
        # IKE_AUTH response seen (exchange_type 35, r2i, encrypted)
        for m in session.messages:
            if m.exchange_type == 35 and m.direction == "r2i" and m.encrypted:
                session.outcome = "established_observed"
                return

        # If SA_INIT completed (both directions seen) but no AUTH yet
        sa_init_i = any(m.exchange_type == 34 and m.direction == "i2r" for m in session.messages)
        sa_init_r = any(m.exchange_type == 34 and m.direction == "r2i" for m in session.messages)
        if sa_init_i and sa_init_r:
            session.outcome = "incomplete_capture"
        else:
            session.outcome = "unknown"

    def _process_ikev1(self, msg: IkeMessage) -> IkeSession:
        cookie_i = msg.spi_i
        cookie_r = msg.spi_r
        is_initiator = (msg.direction == "i2r")

        # Try to find existing session
        session_id = None
        if cookie_r != "0000000000000000":
            direct_key = f"ikev1_{cookie_i}_{cookie_r}"
            if direct_key in self.sessions:
                session_id = direct_key
        if not session_id and cookie_i in self._v1_initiator_map:
            session_id = self._v1_initiator_map[cookie_i]

        session = self.sessions.get(session_id) if session_id else None

        if session is None:
            # Create session
            resolved_r = cookie_r if cookie_r != "0000000000000000" else None
            session_id = f"ikev1_{cookie_i}_{cookie_r}"
            init_ep = msg.src if is_initiator else msg.dst
            resp_ep = msg.dst if is_initiator else msg.src
            is_am = (msg.exchange_type == 4)
            unobs = (
                ["Quick Mode (Phase 2) SA proposals and keys"]
                if is_am
                else [
                    "Phase 1 identities (ID payload)",
                    "Phase 1 authentication hashes (HASH)",
                    "Quick Mode (Phase 2) SA proposals and keys",
                ]
            )

            session = IkeSession(
                id=session_id,
                version=1,
                spi_i=cookie_i,
                spi_r=resolved_r,
                initiator=init_ep,
                responder=resp_ep,
                natt=msg.natt,
                first_ts=msg.ts,
                last_ts=msg.ts,
                messages=[],
                offered=[],
                selected=None,
                outcome="unknown",
                retransmissions=0,
                ke_retries=0,
                aggressive_mode=is_am,
                encrypted_not_observable=unobs,
            )
            self.sessions[session_id] = session
            self._v1_initiator_map[cookie_i] = session_id
            self._seen_signatures[session_id] = set()

        session.last_ts = max(session.last_ts, msg.ts)
        if msg.natt:
            session.natt = True
        if msg.exchange_type == 4:
            session.aggressive_mode = True

        if not session.spi_r and cookie_r != "0000000000000000":
            session.spi_r = cookie_r
            # Update key mapping if needed
            new_id = f"ikev1_{cookie_i}_{cookie_r}"
            if new_id != session.id and new_id not in self.sessions:
                old_id = session.id
                session.id = new_id
                self.sessions[new_id] = session
                del self.sessions[old_id]
                self._seen_signatures[new_id] = self._seen_signatures.pop(old_id, set())
                self._v1_initiator_map[cookie_i] = new_id

        # Retransmission check
        sig = (msg.direction, msg.exchange_type, msg.message_id, self._message_hash(msg))
        if sig in self._seen_signatures[session.id]:
            session.retransmissions += 1
        else:
            self._seen_signatures[session.id].add(sig)

        # Track proposals: Main Mode (2) or Aggressive Mode (4)
        if msg.exchange_type in (2, 4):
            if is_initiator and msg.proposals and not session.offered:
                session.offered = list(msg.proposals)
            elif not is_initiator and msg.proposals and session.selected is None:
                session.selected = msg.proposals[0]

        session.messages.append(msg)
        self._update_ikev1_outcome(session)
        return session

    def _update_ikev1_outcome(self, session: IkeSession) -> None:
        has_initiator = any(m.direction == "i2r" for m in session.messages)
        has_responder = any(m.direction == "r2i" for m in session.messages)

        if not has_responder:
            session.outcome = "unanswered"
            return
        if not has_initiator and has_responder:
            session.outcome = "incomplete_capture"
            return

        # Check for error notification
        for m in session.messages:
            if m.direction == "r2i":
                if any(n.type < 16384 for n in m.notifies):
                    session.outcome = "failed_notify"
                    return

        # Check for established:
        # Quick Mode (exchange 32) seen OR Main Mode msg 5 and 6 seen (encrypted)
        quick_mode = any(m.exchange_type == 32 for m in session.messages)
        if quick_mode:
            session.outcome = "established_observed"
            return

        encrypted_msgs = [m for m in session.messages if m.encrypted]
        if len(encrypted_msgs) >= 2:
            session.outcome = "established_observed"
            return

        if len(session.messages) < (3 if session.aggressive_mode else 6):
            session.outcome = "incomplete_capture"
        else:
            session.outcome = "unknown"

    def get_sessions(self) -> list[IkeSession]:
        """Return all reconstructed IKE sessions sorted by first timestamp."""
        return sorted(self.sessions.values(), key=lambda s: s.first_ts)


def reconstruct_ike_sessions(messages: list[IkeMessage]) -> list[IkeSession]:
    """Convenience helper to reconstruct sessions from a list of IkeMessages."""
    reconstructor = IkeSessionReconstructor()
    for msg in sorted(messages, key=lambda m: (m.ts, m.pkt_no)):
        reconstructor.process_message(msg)
    return reconstructor.get_sessions()
