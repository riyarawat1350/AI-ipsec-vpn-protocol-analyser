"""Analysis job orchestration and persistence service — TASK-033 per SRS §7.2–§7.3.

Executes analyzer Pipeline in a background thread, reports real-time progress,
and stores all extracted facts, findings, sessions, flows, recommendations,
and timelines into MongoDB.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from analyzer.config import AnalyzerConfig
from analyzer.models import AnalysisResult
from analyzer.pipeline import Pipeline
from backend.app.config import settings
from backend.app.db.mongo import Collections
from backend.app.db.repositories import (
    AnalysisRepository,
    FindingsRepository,
    IkeSessionRepository,
    IpsecFlowRepository,
    RecommendationRepository,
)

logger = logging.getLogger(__name__)


def _run_pipeline_sync(
    capture_path: Path,
    policy_id: str,
    options: dict[str, Any],
    progress_fn: Any,
) -> AnalysisResult:
    """Synchronous pipeline entrypoint to be executed in thread."""
    cfg = AnalyzerConfig(
        max_file_size_mb=settings.MAX_UPLOAD_MB,
        max_packets=settings.MAX_PACKETS,
    )
    pipeline = Pipeline(config=cfg, progress=progress_fn)
    return pipeline.run(capture_path=capture_path, policy_id=policy_id, options=options)


async def execute_analysis_job(
    db: AsyncIOMotorDatabase,
    analysis_id: str,
    stored_path: str,
    policy_id: str = "nist_default",
    options: dict[str, Any] | None = None,
) -> None:
    """Asynchronous background worker for executing an analysis job."""
    opts = options or {}
    analysis_repo = AnalysisRepository(db)

    # Mark running
    await analysis_repo.update_status(analysis_id, status="running", progress=5)

    last_reported_progress = 5

    def on_progress(pct: int, stage: str) -> None:
        nonlocal last_reported_progress
        if pct != last_reported_progress:
            last_reported_progress = pct
            # Fire-and-forget sync update via asyncio run_coroutine_threadsafe if needed,
            # or we update at milestones.

    try:
        # Run pipeline in worker thread to prevent blocking event loop
        result: AnalysisResult = await asyncio.to_thread(
            _run_pipeline_sync,
            Path(stored_path),
            policy_id,
            opts,
            on_progress,
        )

        # Build timeline events
        timeline_events: list[dict[str, Any]] = []

        # 1. Timeline from IKE sessions & messages
        for sess in result.facts.sessions:
            for msg in sess.messages:
                timeline_events.append({
                    "analysis_id": analysis_id,
                    "ts": msg.ts,
                    "type": "ike_message",
                    "ref_id": sess.id,
                    "label": f"IKE {msg.exchange_name} ({msg.direction.upper()}) between {msg.src.ip} and {msg.dst.ip}",
                    "details": {
                        "pkt_no": msg.pkt_no,
                        "session_id": sess.id,
                        "encrypted": msg.encrypted,
                    },
                })

        # 2. Timeline from findings
        for f in result.findings:
            first_ev = f.evidence[0] if f.evidence else None
            ts = first_ev.ts if first_ev else result.facts.capture.get("first_ts", 0.0)
            timeline_events.append({
                "analysis_id": analysis_id,
                "ts": ts,
                "type": "finding",
                "ref_id": f.id,
                "label": f"Security finding: {f.title} ({f.severity})",
                "details": {
                    "rule_id": f.rule_id,
                    "risk_score": f.risk_score,
                    "severity": f.severity,
                },
            })

        # Sort timeline chronologically
        timeline_events.sort(key=lambda e: e["ts"])

        # Insert to MongoDB collections
        # Findings
        findings_data = [f.model_dump() for f in result.findings]
        findings_repo = FindingsRepository(db)
        await findings_repo.insert_many(analysis_id, findings_data)

        # IKE Sessions
        sessions_data = [s.model_dump() for s in result.facts.sessions]
        session_repo = IkeSessionRepository(db)
        await session_repo.insert_many(analysis_id, sessions_data)

        # IKE Messages
        all_messages: list[dict[str, Any]] = []
        for s in result.facts.sessions:
            for idx, m in enumerate(s.messages):
                m_dict = m.model_dump()
                m_dict["_id"] = f"msg_{analysis_id[:8]}_{s.id[:8]}_{idx}_{m.pkt_no}"
                m_dict["session_id"] = s.id
                m_dict["analysis_id"] = analysis_id
                all_messages.append(m_dict)
        if all_messages:
            await db[Collections.IKE_MESSAGES].insert_many(all_messages)

        # Flows
        flows_data = [fl.model_dump() for fl in result.facts.flows]
        flow_repo = IpsecFlowRepository(db)
        await flow_repo.insert_many(analysis_id, flows_data)

        # Recommendations
        rec_repo = RecommendationRepository(db)
        await rec_repo.insert_many(analysis_id, result.recommendations)

        # Timeline
        if timeline_events:
            for idx, te in enumerate(timeline_events):
                te["_id"] = f"tle_{analysis_id[:8]}_{idx}"
            await db["timeline_events"].insert_many(timeline_events)

        # IOCs
        if result.iocs:
            iocs_data = [{"_id": f"ioc_{analysis_id[:8]}_{idx}", "analysis_id": analysis_id, **ioc} for idx, ioc in enumerate(result.iocs)]
            await db["iocs"].insert_many(iocs_data)

        # Update Analysis Document
        posture = result.posture
        finding_counts = posture.get("severity_counts", {})
        risk_score = round(100.0 - float(posture.get("score", 100.0)), 1)

        await db[Collections.ANALYSES].update_one(
            {"_id": analysis_id},
            {
                "$set": {
                    "status": "completed",
                    "progress": 100,
                    "completed_at": datetime.now(timezone.utc),
                    "risk_score": risk_score,
                    "posture": posture,
                    "grade": posture.get("grade", "A"),
                    "finding_counts": finding_counts,
                    "capture_stats": result.facts.capture,
                    "protocol_stats": result.facts.protocol_stats,
                    "narrative": result.narrative,
                    "coverage_notes": result.coverage_notes,
                    "warnings": result.facts.warnings,
                    "ml_status": result.ml_status,
                }
            },
        )
        logger.info("Analysis %s completed successfully.", analysis_id)

    except Exception as exc:
        logger.exception("Analysis job %s failed: %s", analysis_id, exc)
        await analysis_repo.update_status(
            analysis_id,
            status="failed",
            progress=100,
            error_code="ANALYSIS_FAILED",
            error_detail=str(exc),
        )
