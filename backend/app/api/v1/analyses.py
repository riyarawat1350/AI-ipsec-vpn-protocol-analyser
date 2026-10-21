"""Analyses API routes — TASK-033/034 per SRS §9.1."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections, get_db
from backend.app.db.repositories import AnalysisRepository, UploadRepository
from backend.app.deps import get_current_token
from backend.app.services.jobs import execute_analysis_job
from backend.app.services.uploads import handle_upload

router = APIRouter(prefix="/analyses", tags=["Analyses"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    file: UploadFile = File(...),
    policy: str = Form("nist_default"),
    enable_ml: bool = Form(True),
    enable_llm: bool = Form(False),
    redact_identities: bool = Form(True),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Upload capture file and enqueue security analysis job."""
    upload = await handle_upload(db, file)
    analysis_repo = AnalysisRepository(db)

    analysis = await analysis_repo.create(upload_id=upload["_id"], policy=policy)
    analysis_id = analysis["_id"]

    options = {
        "enable_ml": enable_ml,
        "enable_llm": enable_llm,
        "redact_identities": redact_identities,
    }

    # Launch background processing task
    asyncio.create_task(
        execute_analysis_job(
            db=db,
            analysis_id=analysis_id,
            stored_path=upload["stored_path"],
            policy_id=policy,
            options=options,
        )
    )

    return {"analysis_id": analysis_id, "status": "queued"}


@router.get("")
async def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """List recent capture analyses with posture scores and grades."""
    analysis_repo = AnalysisRepository(db)
    upload_repo = UploadRepository(db)

    skip = (page - 1) * page_size
    analyses = await analysis_repo.list_all(status=status_filter, skip=skip, limit=page_size)
    total = await analysis_repo.count(status=status_filter)

    items = []
    for a in analyses:
        up = await upload_repo.get_by_id(a["upload_id"])
        items.append({
            "id": a["_id"],
            "upload_id": a["upload_id"],
            "filename": up["original_filename"] if up else "unknown.pcap",
            "sha256": up["sha256"] if up else "",
            "size_bytes": up["size_bytes"] if up else 0,
            "status": a.get("status", "queued"),
            "progress": a.get("progress", 0),
            "policy": a.get("policy", "nist_default"),
            "created_at": a.get("created_at"),
            "completed_at": a.get("completed_at"),
            "posture_score": a.get("posture", {}).get("score") if a.get("posture") else None,
            "grade": a.get("grade") or (a.get("posture", {}).get("grade") if a.get("posture") else None),
            "finding_counts": a.get("finding_counts") or {},
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{id}")
async def get_analysis_status(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve analysis state, progress, and high-level summary."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    upload = await db[Collections.UPLOADS].find_one({"_id": analysis["upload_id"]})

    return {
        "id": analysis["_id"],
        "upload_id": analysis["upload_id"],
        "filename": upload["original_filename"] if upload else "capture.pcap",
        "sha256": upload["sha256"] if upload else "",
        "size_bytes": upload["size_bytes"] if upload else 0,
        "status": analysis.get("status", "queued"),
        "progress": analysis.get("progress", 0),
        "stage": analysis.get("stage", "analyzing"),
        "error_code": analysis.get("error_code"),
        "error_detail": analysis.get("error_detail"),
        "policy": analysis.get("policy", "nist_default"),
        "created_at": analysis.get("created_at"),
        "completed_at": analysis.get("completed_at"),
        "posture": analysis.get("posture"),
        "grade": analysis.get("grade"),
        "risk_score": analysis.get("risk_score"),
        "finding_counts": analysis.get("finding_counts") or {},
        "summary": analysis.get("narrative", {}).get("executive_summary"),
        "warnings": analysis.get("warnings") or [],
    }


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> None:
    """Delete analysis and all associated findings, sessions, and flows."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    # Cascading deletes across collections
    await db[Collections.ANALYSES].delete_one({"_id": id})
    await db[Collections.FINDINGS].delete_many({"analysis_id": id})
    await db[Collections.IKE_SESSIONS].delete_many({"analysis_id": id})
    await db[Collections.IKE_MESSAGES].delete_many({"analysis_id": id})
    await db[Collections.IPSEC_FLOWS].delete_many({"analysis_id": id})
    await db[Collections.RECOMMENDATIONS].delete_many({"analysis_id": id})
    await db["timeline_events"].delete_many({"analysis_id": id})
    await db["iocs"].delete_many({"analysis_id": id})
    await db["reports"].delete_many({"analysis_id": id})


@router.get("/{id}/overview")
async def get_analysis_overview(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve full dashboard overview summary per SRS §9.1."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    if analysis.get("status") != "completed":
        raise AppError(code="ANALYSIS_NOT_COMPLETE", message="Analysis not complete.", status_code=409)

    upload = await db[Collections.UPLOADS].find_one({"_id": analysis["upload_id"]})
    top_findings = await db[Collections.FINDINGS].find({"analysis_id": id}).sort("risk_score", -1).limit(5).to_list(5)

    # Session counts
    ike_v1_count = await db[Collections.IKE_SESSIONS].count_documents({"analysis_id": id, "version": 1})
    ike_v2_count = await db[Collections.IKE_SESSIONS].count_documents({"analysis_id": id, "version": 2})
    esp_count = await db[Collections.IPSEC_FLOWS].count_documents({"analysis_id": id, "proto": "esp"})
    ah_count = await db[Collections.IPSEC_FLOWS].count_documents({"analysis_id": id, "proto": "ah"})
    natt_count = await db[Collections.IPSEC_FLOWS].count_documents({"analysis_id": id, "encap": "natt"})

    return {
        "analysis_id": id,
        "filename": upload.get("original_filename") if upload else "capture.pcap",
        "capture": analysis.get("capture_stats") or {},
        "protocols": analysis.get("protocol_stats", {}).get("distribution") or {},
        "ipsec": {
            "ike_v1_sessions": ike_v1_count,
            "ike_v2_sessions": ike_v2_count,
            "esp_flows": esp_count,
            "ah_flows": ah_count,
            "natt_flows": natt_count,
        },
        "posture": analysis.get("posture") or {},
        "grade": analysis.get("grade", "A"),
        "severity_counts": analysis.get("finding_counts") or {},
        "finding_counts": analysis.get("finding_counts") or {},
        "top_findings": top_findings,
        "narrative": analysis.get("narrative") or {},
        "coverage_notes": analysis.get("coverage_notes") or [],
        "warnings": analysis.get("warnings") or [],
    }


@router.get("/{id}/protocols")
async def get_analysis_protocols(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve protocol distribution, top talkers, and port metrics."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    if analysis.get("status") != "completed":
        raise AppError(code="ANALYSIS_NOT_COMPLETE", message="Analysis not complete.", status_code=409)

    stats = analysis.get("protocol_stats") or {}
    counts = dict(stats.get("counts") or {})
    capture = analysis.get("capture_stats") or {}
    total_pkts = capture.get("total_packets", 0)
    counts["total_packets"] = total_pkts

    # Calculate protocol distribution packet counters
    ike_pkts = counts.get("ikev2", 0) + counts.get("ikev1", 0) + counts.get("ike", 0)
    esp_pkts = counts.get("esp", 0)
    ah_pkts = counts.get("ah", 0)
    nat_keepalives = counts.get("natt_keepalive", 0)
    known_pkts = ike_pkts + esp_pkts + ah_pkts + nat_keepalives
    other_pkts = max(0, total_pkts - known_pkts) if total_pkts > 0 else counts.get("other", 0)

    # Discover observed endpoint roles from IKE sessions (ground truth)
    ike_sessions = await db[Collections.IKE_SESSIONS].find({"analysis_id": id}).to_list(10)
    initiator_ips = set()
    responder_ips = set()
    for s in ike_sessions:
        if s.get("initiator") and isinstance(s["initiator"], dict):
            initiator_ips.add(s["initiator"].get("ip"))
        elif s.get("initiator_ip"):
            initiator_ips.add(s.get("initiator_ip"))
        if s.get("responder") and isinstance(s["responder"], dict):
            responder_ips.add(s["responder"].get("ip"))
        elif s.get("responder_ip"):
            responder_ips.add(s.get("responder_ip"))

    # Conversations: prefer pairwise conversations from stats
    raw_convs = stats.get("conversations")
    normalized_talkers: list[dict[str, Any]] = []

    if raw_convs:
        for c in raw_convs:
            ep_a = c.get("endpoint_a") or "Unknown"
            ep_b = c.get("endpoint_b") or "Unknown"
            role_a = "Initiator" if ep_a in initiator_ips else ("Responder" if ep_a in responder_ips else None)
            role_b = "Responder" if ep_b in responder_ips else ("Initiator" if ep_b in initiator_ips else None)
            normalized_talkers.append({
                "endpoint_a": ep_a,
                "role_a": role_a,
                "endpoint_b": ep_b,
                "role_b": role_b,
                "packets": c.get("packets", 0),
                "bytes": c.get("bytes", 0),
            })
    elif ike_sessions:
        for s in ike_sessions:
            ep_a = s.get("initiator", {}).get("ip") or s.get("initiator_ip") or "Unknown"
            ep_b = s.get("responder", {}).get("ip") or s.get("responder_ip") or "Unknown"
            normalized_talkers.append({
                "endpoint_a": ep_a,
                "role_a": "Initiator",
                "endpoint_b": ep_b,
                "role_b": "Responder",
                "packets": total_pkts,
                "bytes": capture.get("total_bytes", 0),
            })
    else:
        raw_talkers = stats.get("top_talkers") or []
        for t in raw_talkers:
            ep_a = t.get("ip") or t.get("endpoint_a") or "Unknown"
            normalized_talkers.append({
                "endpoint_a": ep_a,
                "role_a": "Initiator" if ep_a in initiator_ips else None,
                "endpoint_b": t.get("endpoint_b") or "-",
                "role_b": None,
                "packets": t.get("packets", 0),
                "bytes": t.get("bytes", 0),
            })


    return {
        "capture": capture,
        "protocol_distribution": {
            "ike_packets": ike_pkts,
            "esp_packets": esp_pkts,
            "ah_packets": ah_pkts,
            "nat_keepalive_packets": nat_keepalives,
            "other_packets": other_pkts,
        },
        "distribution": stats.get("distribution") or {},
        "counts": counts,
        "top_talkers": normalized_talkers,
        "top_ports": stats.get("top_ports") or [],
        "nat_traversal": {
            "detected": bool(counts.get("natt", 0) or nat_keepalives > 0),
            "port_4500_flows": counts.get("natt", 0),
            "non_esp_marker_packets": counts.get("natt_ike", 0),
        },
        "ike_versions": {
            "v1": counts.get("ikev1", 0),
            "v2": counts.get("ikev2", 0),
        },
        "unsupported_protocols": [],
        "warnings": analysis.get("warnings") or [],
    }


@router.get("/{id}/timeline")
async def get_analysis_timeline(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> list[dict[str, Any]]:
    """Retrieve chronological event timeline."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    cursor = db["timeline_events"].find({"analysis_id": id}, {"_id": 0}).sort("ts", 1)
    return await cursor.to_list(length=1000)


@router.get("/{id}/iocs")
async def get_analysis_iocs(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> list[dict[str, Any]]:
    """Retrieve indicators of compromise / interest."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    cursor = db["iocs"].find({"analysis_id": id}, {"_id": 0})
    return await cursor.to_list(length=500)


@router.get("/{id}/anomalies")
async def get_analysis_anomalies(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _token: str | None = Depends(get_current_token),
) -> dict[str, Any]:
    """Retrieve ML anomaly windows and model metrics."""
    analysis = await db[Collections.ANALYSES].find_one({"_id": id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{id}' not found.", status_code=404)

    return {
        "ml_status": analysis.get("ml_status") or {
            "status": "unavailable",
            "reason": "Evaluated with rule-based heuristics only",
        },
        "windows": [],
    }
