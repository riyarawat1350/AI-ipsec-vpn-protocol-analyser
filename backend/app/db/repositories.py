"""Database repository helpers for CRUD operations."""

from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from backend.app.db.models import (
    AnalysisModel,
    EvidenceModel,
    FindingModel,
    IkeMessageModel,
    IkeSessionModel,
    IpsecFlowModel,
    ReportModel,
    UploadModel,
)


class UploadRepository:
    """Repository for uploads management."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        original_filename: str,
        stored_path: str,
        sha256: str,
        size_bytes: int,
        detected_format: str,
    ) -> UploadModel:
        upload = UploadModel(
            original_filename=original_filename,
            stored_path=stored_path,
            sha256=sha256,
            size_bytes=size_bytes,
            detected_format=detected_format,
        )
        self.db.add(upload)
        self.db.commit()
        self.db.refresh(upload)
        return upload

    def get_by_id(self, upload_id: str) -> UploadModel | None:
        return self.db.execute(select(UploadModel).where(UploadModel.id == upload_id)).scalar_one_or_none()

    def get_by_sha256(self, sha256: str) -> UploadModel | None:
        return self.db.execute(select(UploadModel).where(UploadModel.sha256 == sha256)).scalar_one_or_none()

    def delete(self, upload: UploadModel) -> None:
        self.db.delete(upload)
        self.db.commit()


class AnalysisRepository:
    """Repository for analysis jobs and results."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, upload_id: str, policy_id: str = "nist_default", options: dict[str, Any] | None = None) -> AnalysisModel:
        analysis = AnalysisModel(
            upload_id=upload_id,
            policy_id=policy_id,
            options=options or {},
            status="queued",
            stage="queued",
            progress=0,
        )
        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def get_by_id(self, analysis_id: str) -> AnalysisModel | None:
        return self.db.execute(select(AnalysisModel).where(AnalysisModel.id == analysis_id)).scalar_one_or_none()

    def list_all(self, limit: int = 50, offset: int = 0) -> list[AnalysisModel]:
        stmt = select(AnalysisModel).order_by(desc(AnalysisModel.created_at)).offset(offset).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def update_progress(self, analysis_id: str, stage: str, progress: int) -> None:
        analysis = self.get_by_id(analysis_id)
        if analysis:
            analysis.stage = stage
            analysis.progress = progress
            self.db.commit()

    def mark_failed(self, analysis_id: str, error_code: str, error_message: str) -> None:
        analysis = self.get_by_id(analysis_id)
        if analysis:
            analysis.status = "failed"
            analysis.stage = "failed"
            analysis.error_code = error_code
            analysis.error_message = error_message
            self.db.commit()

    def delete(self, analysis: AnalysisModel) -> None:
        self.db.delete(analysis)
        self.db.commit()


class FindingRepository:
    """Repository for security findings."""

    def __init__(self, db: Session):
        self.db = db

    def list_by_analysis(
        self,
        analysis_id: str,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[FindingModel]:
        stmt = select(FindingModel).where(FindingModel.analysis_id == analysis_id)
        if severity:
            stmt = stmt.where(FindingModel.severity == severity.capitalize())
        if category:
            stmt = stmt.where(FindingModel.category == category)
        stmt = stmt.order_by(desc(FindingModel.risk_score)).offset(offset).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def get_by_id(self, finding_id: str) -> FindingModel | None:
        return self.db.execute(select(FindingModel).where(FindingModel.id == finding_id)).scalar_one_or_none()

    def add_evidence(
        self,
        finding_id: str,
        packet_no: int,
        ts: float,
        message: str,
        field_path: str,
        hex_excerpt: str,
        raw_value: Any = None,
        decoded: str | None = None,
        note: str | None = None,
    ) -> EvidenceModel:
        ev = EvidenceModel(
            finding_id=finding_id,
            packet_no=packet_no,
            ts=ts,
            message=message,
            field_path=field_path,
            hex_excerpt=hex_excerpt,
            raw_value=raw_value,
            decoded=decoded,
            note=note,
        )
        self.db.add(ev)
        self.db.commit()
        self.db.refresh(ev)
        return ev


class IkeSessionRepository:
    """Repository for IKE sessions."""

    def __init__(self, db: Session):
        self.db = db

    def list_by_analysis(
        self,
        analysis_id: str,
        outcome: str | None = None,
        version: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IkeSessionModel]:
        stmt = select(IkeSessionModel).where(IkeSessionModel.analysis_id == analysis_id)
        if outcome:
            stmt = stmt.where(IkeSessionModel.outcome == outcome)
        if version:
            stmt = stmt.where(IkeSessionModel.version == version)
        stmt = stmt.offset(offset).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def get_by_id(self, session_id: str) -> IkeSessionModel | None:
        return self.db.execute(select(IkeSessionModel).where(IkeSessionModel.id == session_id)).scalar_one_or_none()

    def get_messages(self, session_id: str) -> list[IkeMessageModel]:
        stmt = select(IkeMessageModel).where(IkeMessageModel.session_id == session_id).order_by(IkeMessageModel.packet_no)
        return list(self.db.execute(stmt).scalars().all())


class FlowRepository:
    """Repository for ESP/AH flows."""

    def __init__(self, db: Session):
        self.db = db

    def list_by_analysis(self, analysis_id: str, proto: str | None = None, limit: int = 50, offset: int = 0) -> list[IpsecFlowModel]:
        stmt = select(IpsecFlowModel).where(IpsecFlowModel.analysis_id == analysis_id)
        if proto:
            stmt = stmt.where(IpsecFlowModel.proto == proto.lower())
        stmt = stmt.offset(offset).limit(limit)
        return list(self.db.execute(stmt).scalars().all())


class ReportRepository:
    """Repository for generated reports."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, analysis_id: str, format: str, path: str, sha256: str) -> ReportModel:
        rep = ReportModel(
            analysis_id=analysis_id,
            format=format,
            path=path,
            sha256=sha256,
        )
        self.db.add(rep)
        self.db.commit()
        self.db.refresh(rep)
        return rep

    def list_by_analysis(self, analysis_id: str) -> list[ReportModel]:
        stmt = select(ReportModel).where(ReportModel.analysis_id == analysis_id)
        return list(self.db.execute(stmt).scalars().all())
