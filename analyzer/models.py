"""Core domain models for IPsecScope analyzer (Pydantic v2) per SPEC §4."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    """Network endpoint with IP and optional port."""

    ip: str
    port: int | None = None


class DecodedPacket(BaseModel):
    """L2-L4 decoded packet container."""

    pkt_no: int
    ts: float
    src: str
    dst: str
    ip_proto: int
    sport: int | None = None
    dport: int | None = None
    payload: bytes
    reassembled: bool = False

    # IP fragmentation tracking
    is_fragment: bool = False
    frag_offset: int = 0
    more_fragments: bool = False
    frag_id: int | None = None


class IkeTransform(BaseModel):
    """Single transform attribute inside an SA proposal."""

    kind: Literal[
        "ENCR", "PRF", "INTEG", "DH", "ESN", "HASH", "AUTH", "LIFE_TYPE", "LIFE_DURATION"
    ]
    id: int
    name: str
    key_length: int | None = None


class IkeProposal(BaseModel):
    """Proposal payload containing a set of cryptographic transforms."""

    num: int
    protocol: Literal["IKE", "ESP", "AH"] = "IKE"
    transforms: list[IkeTransform] = Field(default_factory=list)


class IkeNotify(BaseModel):
    """Notification payload."""

    type: int
    name: str
    protocol_id: int = 0
    data_len: int = 0
    data_hex: str | None = None


class IkeMessage(BaseModel):
    """Parsed IKEv1 or IKEv2 message."""

    pkt_no: int
    ts: float
    src: Endpoint
    dst: Endpoint
    natt: bool
    version: int
    exchange_type: int
    exchange_name: str
    flags: int
    message_id: int
    length: int
    spi_i: str
    spi_r: str
    direction: Literal["i2r", "r2i"]
    payload_types: list[int] = Field(default_factory=list)
    encrypted: bool = False
    proposals: list[IkeProposal] = Field(default_factory=list)
    ke_group: int | None = None
    ke_len: int | None = None
    nonce_len: int | None = None
    notifies: list[IkeNotify] = Field(default_factory=list)
    vendor_ids: list[str] = Field(default_factory=list)
    nat_detection: list[str] = Field(default_factory=list)
    v1_id: dict[str, Any] | None = None
    v1_hash_len: int | None = None
    anomalies: list[str] = Field(default_factory=list)
    raw_header_hex: str = ""
    raw_excerpt_hex: str = ""  # <= 64 bytes of the relevant payload


class IkeSession(BaseModel):
    """Reconstructed IKE session."""

    id: str
    version: int
    spi_i: str
    spi_r: str | None = None
    initiator: Endpoint
    responder: Endpoint
    natt: bool
    first_ts: float
    last_ts: float
    messages: list[IkeMessage] = Field(default_factory=list)
    offered: list[IkeProposal] = Field(default_factory=list)
    selected: IkeProposal | None = None
    outcome: Literal[
        "established_observed", "failed_notify", "unanswered", "incomplete_capture", "unknown"
    ]
    retransmissions: int = 0
    ke_retries: int = 0
    aggressive_mode: bool = False
    encrypted_not_observable: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """Input unit for declarative rules engine."""

    session_id: str
    kind: Literal["encr", "prf", "integ", "dh", "hash", "auth_method", "lifetime"]
    id: int
    name: str
    key_length: int | None = None
    role: Literal["offered", "selected"]
    pkt_no: int
    field_path: str
    raw_hex: str
    ike_version: int


class FlowSeqStats(BaseModel):
    """Sequence number statistics for an ESP/AH flow."""

    max_seq: int = 0
    gaps: list[tuple[int, int, int]] = Field(default_factory=list)  # (start_seq, end_seq, pkt_no)
    duplicates: int = 0
    reorders: int = 0
    wrap_near: bool = False


class IpsecFlow(BaseModel):
    """Directional ESP or AH flow."""

    id: str
    proto: Literal["esp", "ah"]
    src: str
    dst: str
    spi: str
    encap: Literal["raw", "natt"]
    first_ts: float
    last_ts: float
    packets: int
    bytes: int
    seq: FlowSeqStats
    null_suspected: bool = False
    null_confidence: float | None = None
    inferred_mode: str | None = None
    paired_flow_id: str | None = None
    linked_ike_session_id: str | None = None
    link_confidence: float | None = None
    sample_pkt_nos: list[int] = Field(default_factory=list)


class Facts(BaseModel):
    """Extracted facts summarizing the entire capture."""

    capture: dict[str, Any] = Field(default_factory=dict)
    protocol_stats: dict[str, Any] = Field(default_factory=dict)
    sessions: list[IkeSession] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    flows: list[IpsecFlow] = Field(default_factory=list)
    windows: list[dict[str, Any]] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """Packet-level evidence for a security finding."""

    packet_no: int
    ts: float
    message: str
    field_path: str
    raw_value: Any = None
    decoded: str | None = None
    hex_excerpt: str
    note: str | None = None


class RawFinding(BaseModel):
    """Unscored finding generated by rule or detector."""

    rule_id: str
    origin: Literal["rule", "detector", "ml"]
    category: str
    title: str
    explanation: str
    why_this_matters: str
    impact: int
    likelihood: int
    confidence: float
    evidence: list[Evidence] = Field(default_factory=list)
    affected_sessions: list[str] = Field(default_factory=list)
    count: int = 1
    references: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    recommendation_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    override_severity: str | None = None


class Finding(RawFinding):
    """Scored security finding with risk score and fingerprint."""

    id: str
    risk_score: float
    severity: str
    scoring: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str


class AnalysisResult(BaseModel):
    """Complete output of analysis pipeline."""

    facts: Facts
    findings: list[Finding] = Field(default_factory=list)
    posture: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    narrative: dict[str, Any] = Field(default_factory=dict)
    ml_status: dict[str, Any] = Field(default_factory=dict)
    coverage_notes: list[str] = Field(default_factory=list)
    analyzer_version: str = "0.1.0"
