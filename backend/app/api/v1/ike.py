"""IKE Sessions API routes — TASK-034 per SRS §9.1."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections, get_db
from backend.app.deps import get_current_token

router = APIRouter(prefix="/analyses/{id}", tags=["IKE Sessions"])


@router.get("/ike")
@router.get("/ike/sessions")
async def list_ike_sessions(
    id: str,
    version: int | None = Query(None),
    outcome: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve list of reconstructed IKE negotiations."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    query: dict[str, Any] = {"analysis_id": id}
    if version:
        query["version"] = version
    if outcome:
        query["outcome"] = outcome

    col = db[Collections.IKE_SESSIONS]
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("first_ts", 1).skip(skip).limit(page_size)
    items = await cursor.to_list(length=page_size)
    total = await col.count_documents(query)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/ike/{sid}")
@router.get("/ike/sessions/{sid}")
async def get_ike_session_detail(
    id: str,
    sid: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve complete IKE session detail including messages for handshake ladder."""
    session = await db[Collections.IKE_SESSIONS].find_one({
        "analysis_id": id,
        "$or": [{"_id": sid}, {"id": sid}],
    })
    if not session:
        raise AppError(code="NOT_FOUND", message=f"IKE session '{sid}' not found.", status_code=404)

    # Messages
    msgs_cursor = db[Collections.IKE_MESSAGES].find({
        "analysis_id": id,
        "session_id": session.get("id", sid),
    }, {"_id": 0}).sort("pkt_no", 1)
    messages = await msgs_cursor.to_list(length=500)

    # Related findings
    findings_cursor = db[Collections.FINDINGS].find({
        "analysis_id": id,
    })
    findings = await findings_cursor.to_list(length=100)

    from analyzer.explain.engine import generate_ike_story
    from analyzer.ike.vendor_ids import decode_vendor_id

    # Plain handshake story
    session["story"] = generate_ike_story(session)

    # Enrich vendor IDs
    if "vendor_ids" in session:
        session["vendor_ids"] = [
            decode_vendor_id(v) if not isinstance(v, dict) else v
            for v in session.get("vendor_ids", [])
        ]

    for m in messages:
        if "vendor_ids" in m:
            m["vendor_ids_decoded"] = [
                decode_vendor_id(v) if not isinstance(v, dict) else v
                for v in m.get("vendor_ids", [])
            ]

    return {
        "session": session,
        "story": session["story"],
        "messages": messages or session.get("messages", []),
        "findings": findings,
    }

