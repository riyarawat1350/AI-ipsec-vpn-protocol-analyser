"""Capabilities registry for IPsecScope.

Defines the implementation status of features (FR-85).
Must honestly reflect system capabilities without faking or pretending.
"""

from typing import Literal

from pydantic import BaseModel, Field

CapabilityStatus = Literal["implemented", "partial", "not_implemented"]
CapabilityPriority = Literal["M", "S", "A", "F"]


class CapabilityEntry(BaseModel):
    """Entry describing a functional capability and its implementation status."""

    id: str
    feature: str
    status: CapabilityStatus
    priority: CapabilityPriority
    notes: str = Field(..., description="Technical rationale, boundaries, or limitations")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    heuristic: bool = Field(default=False)


# Authoritative capabilities registry
CAPABILITIES_REGISTRY: list[CapabilityEntry] = [
    # Core Ingestion & Protocol Decoding (Priority M)
    CapabilityEntry(
        id="FR-01",
        feature="PCAP and PCAPNG file upload and streaming ingestion",
        status="implemented",
        priority="M",
        notes="Streaming frames via scapy RawPcapReader / RawPcapNgReader without loading full capture into memory.",
    ),
    CapabilityEntry(
        id="FR-02",
        feature="Magic byte file format validation",
        status="implemented",
        priority="M",
        notes="Validates standard pcap (microsecond/nanosecond, big/little endian) and pcapng magic headers.",
    ),
    CapabilityEntry(
        id="FR-08",
        feature="PCAP/PCAPNG packet streaming",
        status="implemented",
        priority="M",
        notes="Streams frames with constant memory footprint ≤ 300 MB RSS for 200 MB files.",
    ),
    CapabilityEntry(
        id="FR-09",
        feature="Link layer decoding (Ethernet, raw, Linux SLL/SLL2, loopback)",
        status="implemented",
        priority="M",
        notes="Decodes link types 1, 101, 113, 276, 0, 108. Unsupported link types reported as warnings.",
    ),
    CapabilityEntry(
        id="FR-10",
        feature="VLAN tag handling and IPv4/IPv6 decoding",
        status="implemented",
        priority="M",
        notes="Decodes 802.1Q single and QinQ stacked VLAN tags, IPv4, and IPv6 extension headers.",
    ),
    CapabilityEntry(
        id="FR-11",
        feature="IPv4 packet defragmentation",
        status="implemented",
        priority="M",
        notes="Reassembles out-of-order and multi-fragment IPv4 packets with strict 10 MB cache limits. IPv6 defrag is partial.",
    ),
    CapabilityEntry(
        id="FR-14",
        feature="IKEv1 and IKEv2 detection and binary parsing",
        status="implemented",
        priority="M",
        notes="Custom struct-based parser on UDP/500 and UDP/4500 (stripping 4-byte non-ESP marker). No tshark in core.",
    ),
    CapabilityEntry(
        id="FR-15",
        feature="ESP protocol detection and tracking",
        status="implemented",
        priority="M",
        notes="Parses raw IP proto 50 and UDP/4500 encapsulated ESP with sequence number tracking.",
    ),
    CapabilityEntry(
        id="FR-16",
        feature="AH protocol detection and tracking",
        status="implemented",
        priority="M",
        notes="Parses IP proto 51 Authentication Header.",
    ),
    CapabilityEntry(
        id="FR-17",
        feature="NAT-T keepalive detection",
        status="implemented",
        priority="M",
        notes="Detects single-byte 0xFF keepalive frames on UDP/4500.",
    ),
    CapabilityEntry(
        id="FR-34",
        feature="Observability boundary enforcement",
        status="implemented",
        priority="M",
        notes="Never claims to decrypt encrypted regions (IKE_AUTH, Quick Mode, ESP payloads, PFS status).",
    ),

    # Advanced Features (Priority A)
    CapabilityEntry(
        id="FR-39",
        feature="ESP-NULL payload detection heuristic",
        status="partial",
        priority="A",
        notes="Heuristic detects plaintext IPv4 payload inside ESP by verifying IPv4 header checksum in ≥90% packets. Does NOT cover IPv6-in-ESP or transport mode.",
        confidence=0.85,
        heuristic=True,
    ),
    CapabilityEntry(
        id="FR-43",
        feature="Windowed behavioural feature extraction",
        status="implemented",
        priority="A",
        notes="Computes rolling 10s window metrics per initiator (packet rates, IKE/ESP ratio, retransmissions, error rates).",
    ),
    CapabilityEntry(
        id="FR-55",
        feature="Reproducible ML training pipeline",
        status="partial",
        priority="A",
        notes="Training pipeline script exists. If no lab dataset or trained model is present, ML module reports unavailable.",
    ),
    CapabilityEntry(
        id="FR-56",
        feature="ML Isolation Forest anomaly detection",
        status="partial",
        priority="A",
        notes="Inference module validates model schema. Without verified lab model, reports unavailable instead of fabricating.",
        confidence=0.60,
        heuristic=True,
    ),
    CapabilityEntry(
        id="FR-57",
        feature="ML anomaly top-3 feature deviation reporting",
        status="implemented",
        priority="A",
        notes="Calculates z-scores against baseline distribution to explain anomaly triggers.",
    ),
    CapabilityEntry(
        id="FR-58",
        feature="ML graceful degradation on missing model / insufficient data",
        status="implemented",
        priority="A",
        notes="Reports 'unavailable' if model missing, 'insufficient_data' if windows < 20. Never fabricates scores.",
    ),
    CapabilityEntry(
        id="FR-59",
        feature="ML model artifact schema validation",
        status="implemented",
        priority="A",
        notes="Strict feature schema verification at load time; rejects drifted or mismatched models.",
    ),
    CapabilityEntry(
        id="FR-60",
        feature="LLM executive summary narrative generation",
        status="implemented",
        priority="A",
        notes="Deterministic template-based narrative generator by default; optional pluggable LLM provider.",
    ),
    CapabilityEntry(
        id="FR-61",
        feature="LLM input sanitization and output schema validation",
        status="implemented",
        priority="A",
        notes="Pseudonymizes IP addresses and strips raw hex before prompt generation; validates IDs in responses.",
    ),
    CapabilityEntry(
        id="FR-66",
        feature="MITRE ATT&CK technique mapping",
        status="implemented",
        priority="A",
        notes="Maps specific rules (IKE-RECON-001 -> T1046, IKE-DOS-001 -> T1498, CRY-ENC-001 -> T1557) as related techniques.",
    ),
    CapabilityEntry(
        id="FR-67",
        feature="IOC extraction and export",
        status="implemented",
        priority="A",
        notes="Extracts observable peer IPs, SPIs, Vendor IDs, and cleartext Aggressive Mode IDs.",
    ),
    CapabilityEntry(
        id="FR-74",
        feature="Analysis comparison and posture delta",
        status="implemented",
        priority="A",
        notes="Fingerprint-based comparison identifying new, resolved, and persistent findings between two captures.",
    ),

    # Future Scope (Priority F)
    CapabilityEntry(
        id="FR-87",
        feature="Key-assisted decryption with user-supplied keys",
        status="not_implemented",
        priority="F",
        notes="Key-assisted decryption of IKE_AUTH or ESP payloads is out of scope for passive analyzer baseline.",
    ),
]


def get_capabilities() -> list[CapabilityEntry]:
    """Return all capability entries."""
    return list(CAPABILITIES_REGISTRY)
