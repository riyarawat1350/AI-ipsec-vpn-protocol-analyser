"""Capture Comparison API route — TASK-046 per SRS §9.1."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from backend.app.db.mongo import get_db
from backend.app.deps import get_current_token
from backend.app.services.compare import compare_analyses

router = APIRouter(prefix="/compare", tags=["Comparison"])


class CompareRequest(BaseModel):
    baseline_id: str
    candidate_id: str


@router.post("")
async def compare_two_analyses(
    req: CompareRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Compare baseline analysis with candidate analysis and compute posture delta."""
    return await compare_analyses(db, baseline_id=req.baseline_id, candidate_id=req.candidate_id)
