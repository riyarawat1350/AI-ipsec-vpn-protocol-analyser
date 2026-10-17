"""MongoDB repositories — CRUD helpers for all collections.

Replaces backend/app/db/repositories.py (SQLAlchemy version).
All IDs are UUID4 strings stored as MongoDB _id field.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.db.mongo import Collections


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Upload repository
# ---------------------------------------------------------------------------

class UploadRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.UPLOADS]

    async def create(
        self,
        original_filename: str,
        stored_path: str,
        sha256: str,
        size_bytes: int,
        detected_format: str,
    ) -> dict[str, Any]:
        doc = {
            "_id": _new_id(),
            "original_filename": original_filename,
            "stored_path": stored_path,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "detected_format": detected_format,
            "created_at": _now(),
        }
        await self._col.insert_one(doc)
        return doc

    async def get_by_id(self, upload_id: str) -> dict[str, Any] | None:
        return await self._col.find_one({"_id": upload_id})

    async def get_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        return await self._col.find_one({"sha256": sha256})

    async def delete(self, upload_id: str) -> bool:
        result = await self._col.delete_one({"_id": upload_id})
        return result.deleted_count > 0


# ---------------------------------------------------------------------------
# Analysis repository
# ---------------------------------------------------------------------------

class AnalysisRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.ANALYSES]

    async def create(self, upload_id: str, policy: str = "nist_default") -> dict[str, Any]:
        doc = {
            "_id": _new_id(),
            "upload_id": upload_id,
            "status": "queued",
            "policy": policy,
            "created_at": _now(),
            "started_at": None,
            "completed_at": None,
            "progress": 0,
            "error_code": None,
            "error_detail": None,
            # High-level summary fields (filled when completed)
            "risk_score": None,
            "posture": None,
            "finding_counts": None,
            "analyzer_version": "0.1.0",
            "capture_stats": None,
        }
        await self._col.insert_one(doc)
        return doc

    async def get_by_id(self, analysis_id: str) -> dict[str, Any] | None:
        return await self._col.find_one({"_id": analysis_id})

    async def list_by_upload(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self._col.find({"upload_id": upload_id}).sort("created_at", -1)
        return await cursor.to_list(length=100)

    async def list_all(
        self,
        status: str | None = None,
        skip: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        cursor = self._col.find(query).sort("created_at", -1).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    async def update_status(
        self,
        analysis_id: str,
        status: str,
        progress: int | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        update: dict[str, Any] = {"status": status}
        if progress is not None:
            update["progress"] = progress
        if error_code is not None:
            update["error_code"] = error_code
        if error_detail is not None:
            update["error_detail"] = error_detail
        if status == "running":
            update["started_at"] = _now()
        if status in ("completed", "failed"):
            update["completed_at"] = _now()
        await self._col.update_one({"_id": analysis_id}, {"$set": update})

    async def save_result(
        self,
        analysis_id: str,
        risk_score: float,
        posture: dict[str, Any],
        finding_counts: dict[str, int],
        capture_stats: dict[str, Any],
    ) -> None:
        await self._col.update_one(
            {"_id": analysis_id},
            {
                "$set": {
                    "risk_score": risk_score,
                    "posture": posture,
                    "finding_counts": finding_counts,
                    "capture_stats": capture_stats,
                    "status": "completed",
                    "completed_at": _now(),
                    "progress": 100,
                }
            },
        )

    async def delete(self, analysis_id: str) -> bool:
        result = await self._col.delete_one({"_id": analysis_id})
        return result.deleted_count > 0

    async def count(self, status: str | None = None) -> int:
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        return await self._col.count_documents(query)


# ---------------------------------------------------------------------------
# Findings repository
# ---------------------------------------------------------------------------

class FindingsRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.FINDINGS]

    async def insert_many(
        self, analysis_id: str, findings: list[dict[str, Any]]
    ) -> int:
        if not findings:
            return 0
        docs = [{"_id": _new_id(), "analysis_id": analysis_id, **f} for f in findings]
        result = await self._col.insert_many(docs)
        return len(result.inserted_ids)

    async def list_by_analysis(
        self,
        analysis_id: str,
        severity: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"analysis_id": analysis_id}
        if severity:
            query["severity"] = severity
        cursor = (
            self._col.find(query)
            .sort("risk_score", -1)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def count_by_analysis(
        self, analysis_id: str, severity: str | None = None
    ) -> int:
        query: dict[str, Any] = {"analysis_id": analysis_id}
        if severity:
            query["severity"] = severity
        return await self._col.count_documents(query)

    async def delete_by_analysis(self, analysis_id: str) -> int:
        result = await self._col.delete_many({"analysis_id": analysis_id})
        return result.deleted_count


# ---------------------------------------------------------------------------
# IKE Sessions repository
# ---------------------------------------------------------------------------

class IkeSessionRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.IKE_SESSIONS]

    async def insert_many(
        self, analysis_id: str, sessions: list[dict[str, Any]]
    ) -> int:
        if not sessions:
            return 0
        docs = [{"_id": _new_id(), "analysis_id": analysis_id, **s} for s in sessions]
        result = await self._col.insert_many(docs)
        return len(result.inserted_ids)

    async def list_by_analysis(
        self,
        analysis_id: str,
        skip: int = 0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        cursor = (
            self._col.find({"analysis_id": analysis_id})
            .sort("first_ts", 1)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def get_by_session_id(
        self, analysis_id: str, session_id: str
    ) -> dict[str, Any] | None:
        return await self._col.find_one(
            {"analysis_id": analysis_id, "id": session_id}
        )

    async def delete_by_analysis(self, analysis_id: str) -> int:
        result = await self._col.delete_many({"analysis_id": analysis_id})
        return result.deleted_count


# ---------------------------------------------------------------------------
# IPsec Flows repository
# ---------------------------------------------------------------------------

class IpsecFlowRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.IPSEC_FLOWS]

    async def insert_many(
        self, analysis_id: str, flows: list[dict[str, Any]]
    ) -> int:
        if not flows:
            return 0
        docs = [{"_id": _new_id(), "analysis_id": analysis_id, **f} for f in flows]
        result = await self._col.insert_many(docs)
        return len(result.inserted_ids)

    async def list_by_analysis(
        self, analysis_id: str, skip: int = 0, limit: int = 50
    ) -> list[dict[str, Any]]:
        cursor = (
            self._col.find({"analysis_id": analysis_id})
            .sort("packets", -1)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def delete_by_analysis(self, analysis_id: str) -> int:
        result = await self._col.delete_many({"analysis_id": analysis_id})
        return result.deleted_count


# ---------------------------------------------------------------------------
# Recommendations repository
# ---------------------------------------------------------------------------

class RecommendationRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.RECOMMENDATIONS]

    async def insert_many(
        self, analysis_id: str, recs: list[dict[str, Any]]
    ) -> int:
        if not recs:
            return 0
        docs = [{"_id": _new_id(), "analysis_id": analysis_id, **r} for r in recs]
        result = await self._col.insert_many(docs)
        return len(result.inserted_ids)

    async def list_by_analysis(
        self, analysis_id: str
    ) -> list[dict[str, Any]]:
        cursor = self._col.find({"analysis_id": analysis_id}).sort("priority", 1)
        return await cursor.to_list(length=200)

    async def delete_by_analysis(self, analysis_id: str) -> int:
        result = await self._col.delete_many({"analysis_id": analysis_id})
        return result.deleted_count


# ---------------------------------------------------------------------------
# Audit log repository
# ---------------------------------------------------------------------------

class AuditRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[Collections.AUDIT_LOG]

    async def log(
        self,
        event: str,
        analysis_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        doc = {
            "_id": _new_id(),
            "event": event,
            "analysis_id": analysis_id,
            "detail": detail or {},
            "timestamp": _now(),
        }
        await self._col.insert_one(doc)
