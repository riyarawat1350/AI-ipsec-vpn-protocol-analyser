"""Findings and Recommendations API routes — TASK-034 per SRS §9.1."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections, get_db
from backend.app.deps import get_current_token

router = APIRouter(prefix="/analyses/{id}", tags=["Findings & Recommendations"])


@router.get("/findings")
async def list_findings(
    id: str,
    severity: str | None = Query(None),
    rule_id: str | None = Query(None),
    category: str | None = Query(None),
    q: str | None = Query(None),
    sort_by: str = Query("risk_score"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve filterable, paginated list of security findings."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    query: dict[str, Any] = {"analysis_id": id}
    if severity:
        query["severity"] = severity
    if rule_id:
        query["rule_id"] = rule_id
    if category:
        query["category"] = category
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"explanation": {"$regex": q, "$options": "i"}},
            {"rule_id": {"$regex": q, "$options": "i"}},
        ]

    sort_direction = -1 if order.lower() == "desc" else 1
    sort_field = "risk_score" if sort_by == "risk_score" else "severity"

    skip = (page - 1) * page_size
    col = db[Collections.FINDINGS]

    cursor = col.find(query).sort(sort_field, sort_direction).skip(skip).limit(page_size)
    items = await cursor.to_list(length=page_size)
    total = await col.count_documents(query)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/findings/{fid}")
async def get_finding_detail(
    id: str,
    fid: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve full finding detail including packet evidence and remediation."""
    finding = await db[Collections.FINDINGS].find_one({
        "analysis_id": id,
        "$or": [{"_id": fid}, {"id": fid}],
    })
    if not finding:
        raise AppError(code="NOT_FOUND", message=f"Finding '{fid}' not found.", status_code=404)

    return finding


@router.get("/recommendations")
async def list_recommendations(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> list[dict[str, Any]]:
    """Retrieve prioritized fix-first recommendations ranked by risk reduction."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    cursor = db[Collections.RECOMMENDATIONS].find({"analysis_id": id}).sort("rank", 1)
    recs = await cursor.to_list(length=200)
    return recs
