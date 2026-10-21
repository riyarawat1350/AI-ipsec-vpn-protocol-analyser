"""ESP and AH Flows API routes — TASK-034 per SRS §9.1."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections, get_db
from backend.app.deps import get_current_token

router = APIRouter(prefix="/analyses/{id}", tags=["ESP/AH Flows"])


@router.get("/esp")
@router.get("/esp/flows")
async def list_ipsec_flows(
    id: str,
    proto: str | None = Query(None),
    spi: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve directional ESP/AH flows with sequence tracking and NULL detection."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    query: dict[str, Any] = {"analysis_id": id}
    if proto:
        query["proto"] = proto
    if spi:
        query["spi"] = spi.lower()

    col = db[Collections.IPSEC_FLOWS]
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("packets", -1).skip(skip).limit(page_size)
    items = await cursor.to_list(length=page_size)
    total = await col.count_documents(query)

    from analyzer.explain.engine import generate_esp_flow_story

    for item in items:
        if "story" not in item:
            item["story"] = generate_esp_flow_story(item)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/esp/{fid}")
@router.get("/esp/flows/{fid}")
async def get_flow_detail(
    id: str,
    fid: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve detailed flow metrics, sequence gaps, and linked IKE session."""
    flow = await db[Collections.IPSEC_FLOWS].find_one({
        "analysis_id": id,
        "$or": [{"_id": fid}, {"id": fid}],
    })
    if not flow:
        raise AppError(code="NOT_FOUND", message=f"Flow '{fid}' not found.", status_code=404)

    from analyzer.explain.engine import generate_esp_flow_story
    if "story" not in flow:
        flow["story"] = generate_esp_flow_story(flow)

    return cast(dict[str, Any], flow)
