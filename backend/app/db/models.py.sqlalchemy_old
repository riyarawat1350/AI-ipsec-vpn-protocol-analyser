"""SQLAlchemy models for IPsecScope per SRS §10."""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base


def generate_uuid() -> str:
    """Generate a UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class UploadModel(Base):
    """Uploads table (chain of custody, duplicate detection)."""

    __tablename__ = "uploads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_format: Mapped[str] = mapped_column(String(16), nullable=False)  # pcap / pcapng
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analyses: Mapped[list["AnalysisModel"]] = relationship(
        "AnalysisModel", back_populates="upload", cascade="all, delete-orphan"
    )


class AnalysisModel(Base):
    """Analyses table (job state and high-level assessment summary)."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    upload_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("uploads.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), index=True, default="queued")  # queued/running/completed/failed
    stage: Mapped[str] = mapped_column(String(64), default="initializing")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    policy_id: Mapped[str] = mapped_column(String(64), default="nist_default")
    policy_hash: Mapped[str] = mapped_column(String(64), default="")
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    capture_meta: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    protocol_stats: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    posture_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(8), nullable=True)
    severity_counts: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    narrative: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    coverage_notes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    warnings: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    ml_status: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    analyzer_version: Mapped[str] = mapped_column(String(32), default="0.1.0")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    upload: Mapped["UploadModel"] = relationship("UploadModel", back_populates="analyses")
    ike_sessions: Mapped[list["IkeSessionModel"]] = relationship(
        "IkeSessionModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    ipsec_flows: Mapped[list["IpsecFlowModel"]] = relationship(
        "IpsecFlowModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        "FindingModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    anomaly_windows: Mapped[list["AnomalyWindowModel"]] = relationship(
        "AnomalyWindowModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IocModel"]] = relationship(
        "IocModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    reports: Mapped[list["ReportModel"]] = relationship(
        "ReportModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list["TimelineEventModel"]] = relationship(
        "TimelineEventModel", back_populates="analysis", cascade="all, delete-orphan"
    )


class IkeSessionModel(Base):
    """IKE sessions reconstructed from capture."""

    __tablename__ = "ike_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    spi_i: Mapped[str] = mapped_column(String(32), nullable=False)
    spi_r: Mapped[str | None] = mapped_column(String(32), nullable=True)
    initiator_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    responder_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    initiator_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    responder_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    natt: Mapped[bool] = mapped_column(Boolean, default=False)
    first_ts: Mapped[float] = mapped_column(Float, nullable=False)
    last_ts: Mapped[float] = mapped_column(Float, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    exchange_types: Mapped[list[int]] = mapped_column(JSON, default=list)
    offered_proposals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    selected_proposal: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    vendor_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    notifies: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    retransmissions: Mapped[int] = mapped_column(Integer, default=0)
    ke_retries: Mapped[int] = mapped_column(Integer, default=0)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    parse_anomalies: Mapped[list[str]] = mapped_column(JSON, default=list)
    aggressive_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    redacted_identity: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="ike_sessions")
    messages: Mapped[list["IkeMessageModel"]] = relationship(
        "IkeMessageModel", back_populates="session", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_ike_sessions_analysis_outcome", "analysis_id", "outcome"),
    )


class IkeMessageModel(Base):
    """Individual IKE packet messages associated with an IKE session."""

    __tablename__ = "ike_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("ike_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    analysis_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    packet_no: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    direction: Mapped[str] = mapped_column(String(8), nullable=False)  # i2r / r2i
    exchange_type: Mapped[int] = mapped_column(Integer, nullable=False)
    flags: Mapped[int] = mapped_column(Integer, nullable=False)
    message_id: Mapped[int] = mapped_column(Integer, nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_types: Mapped[list[int]] = mapped_column(JSON, default=list)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    parsed: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_retransmission: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    session: Mapped["IkeSessionModel"] = relationship("IkeSessionModel", back_populates="messages")


class IpsecFlowModel(Base):
    """ESP and AH directional flows and sequence statistics."""

    __tablename__ = "ipsec_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    proto: Mapped[str] = mapped_column(String(8), nullable=False)  # esp / ah
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    spi: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    encap: Mapped[str] = mapped_column(String(8), nullable=False)  # raw / natt
    first_ts: Mapped[float] = mapped_column(Float, nullable=False)
    last_ts: Mapped[float] = mapped_column(Float, nullable=False)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)

    seq_stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    size_stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    iat_stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    series: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    null_suspected: Mapped[bool] = mapped_column(Boolean, default=False)
    null_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    inferred_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    paired_flow_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    linked_ike_session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    link_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="ipsec_flows")

    __table_args__ = (
        Index("ix_ipsec_flows_analysis_spi", "analysis_id", "spi"),
    )


class FindingModel(Base):
    """Security findings identified by rules, detectors, or ML."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    origin: Mapped[str] = mapped_column(String(16), nullable=False)  # rule / detector / ml
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    scoring: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    why_this_matters: Mapped[str] = mapped_column(Text, nullable=False)
    affected_sessions: Mapped[list[str]] = mapped_column(JSON, default=list)
    count: Mapped[int] = mapped_column(Integer, default=1)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="findings")
    evidence: Mapped[list["EvidenceModel"]] = relationship(
        "EvidenceModel", back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_findings_analysis_severity", "analysis_id", "severity"),
        Index("ix_findings_analysis_risk", "analysis_id", "risk_score"),
    )


class EvidenceModel(Base):
    """Packet-level evidence records supporting a finding."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    packet_no: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    message: Mapped[str] = mapped_column(String(255), nullable=False)
    field_path: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_value: Mapped[Any] = mapped_column(JSON, nullable=True)
    decoded: Mapped[str | None] = mapped_column(Text, nullable=True)
    hex_excerpt: Mapped[str] = mapped_column(String(192), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped["FindingModel"] = relationship("FindingModel", back_populates="evidence")


class AnomalyWindowModel(Base):
    """Feature windows evaluated by ML anomaly detector."""

    __tablename__ = "anomaly_windows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    window_start: Mapped[float] = mapped_column(Float, nullable=False)
    window_end: Mapped[float] = mapped_column(Float, nullable=False)
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    top_features: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="anomaly_windows")


class IocModel(Base):
    """Indicators of Compromise / Interest extracted from traffic."""

    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # ip/spi/vendor_id/identity
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    context: Mapped[str] = mapped_column(String(255), default="")
    first_seen: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="iocs")


class ReportModel(Base):
    """Generated report artifacts (HTML, PDF, JSON, CSV)."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    format: Mapped[str] = mapped_column(String(16), nullable=False)  # html / pdf / json / csv
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="reports")


class TimelineEventModel(Base):
    """Events plotted on the session / flow timeline."""

    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    ref_type: Mapped[str] = mapped_column(String(32), nullable=False)
    ref_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    analysis: Mapped["AnalysisModel"] = relationship("AnalysisModel", back_populates="timeline_events")
