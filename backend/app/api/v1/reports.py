"""Report API routes — TASK-048 per SRS §9.1 and §14."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections, get_db
from backend.app.deps import get_current_token
from backend.app.services.reports import generate_report

router = APIRouter(tags=["Reports"])


class GenerateReportRequest(BaseModel):
    format: str = "html"  # html, json, csv, pdf


@router.post("/analyses/{id}/reports", status_code=status.HTTP_201_CREATED)
async def create_analysis_report(
    id: str,
    req: GenerateReportRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Generate and store audit report for analysis."""
    return await generate_report(db, analysis_id=id, report_format=req.format)


@router.get("/analyses/{id}/report")
async def preview_html_report(
    id: str,
    format: str = Query("html", description="Report format: html, json, csv, pdf"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> Response:
    """Preview or download report in requested format (html, json, csv)."""
    fmt = format.lower()
    rep = await generate_report(db, analysis_id=id, report_format=fmt)
    path = Path(rep["stored_path"])
    if not path.exists():
        raise AppError(code="NOT_FOUND", message="Report not generated.", status_code=404)

    text_content = path.read_text(encoding="utf-8")
    if fmt == "json":
        return Response(content=text_content, media_type="application/json")
    if fmt == "csv":
        return Response(
            content=text_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="report_{id}.csv"'},
        )
    return HTMLResponse(content=text_content)


@router.get("/reports/{report_id}/download")
async def download_report_file(
    report_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> FileResponse:
    """Download generated report artifact."""
    rep = await db["reports"].find_one({"_id": report_id})
    if not rep:
        raise AppError(code="NOT_FOUND", message=f"Report '{report_id}' not found.", status_code=404)

    path = Path(rep["stored_path"])
    if not path.exists():
        raise AppError(code="NOT_FOUND", message="Report artifact missing on disk.", status_code=404)

    media_types = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }
    media_type = media_types.get(rep.get("format", "html"), "application/octet-stream")

    return FileResponse(
        path=path,
        media_type=media_type,
        filename=path.name,
    )
