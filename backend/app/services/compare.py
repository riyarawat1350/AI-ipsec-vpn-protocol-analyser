"""Analysis comparison service — TASK-046 per SRS §9.1 and §10.

Compares two capture analyses (baseline vs candidate), matching findings by
deterministic parameter fingerprint, and computes resolved, new, persistent
findings, and posture score change.
"""

from __future__ import annotations

from typing import Any
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections


async def compare_analyses(
    db: AsyncIOMotorDatabase,
    baseline_id: str,
    candidate_id: str,
) -> dict[str, Any]:
    """Compare baseline analysis against candidate analysis."""
    analyses_col = db[Collections.ANALYSES]
    findings_col = db[Collections.FINDINGS]

    baseline = await analyses_col.find_one({"_id": baseline_id})
    if not baseline:
        raise AppError(code="NOT_FOUND", message=f"Baseline analysis '{baseline_id}' not found.", status_code=404)

    candidate = await analyses_col.find_one({"_id": candidate_id})
    if not candidate:
        raise AppError(code="NOT_FOUND", message=f"Candidate analysis '{candidate_id}' not found.", status_code=404)

    if baseline.get("status") != "completed" or candidate.get("status") != "completed":
        raise AppError(
            code="ANALYSIS_NOT_COMPLETE",
            message="Both analyses must be in 'completed' state for comparison.",
            status_code=409,
        )

    # Fetch findings
    b_cursor = findings_col.find({"analysis_id": baseline_id})
    b_findings = await b_cursor.to_list(length=1000)

    c_cursor = findings_col.find({"analysis_id": candidate_id})
    c_findings = await c_cursor.to_list(length=1000)

    # Group by fingerprint
    b_map = {f.get("fingerprint", f.get("rule_id")): f for f in b_findings}
    c_map = {f.get("fingerprint", f.get("rule_id")): f for f in c_findings}

    resolved: list[dict[str, Any]] = []
    new_findings: list[dict[str, Any]] = []
    persistent: list[dict[str, Any]] = []

    for fp, b_item in b_map.items():
        if fp not in c_map:
            resolved.append(b_item)
        else:
            persistent.append(c_map[fp])

    for fp, c_item in c_map.items():
        if fp not in b_map:
            new_findings.append(c_item)

    b_score = baseline.get("posture", {}).get("score", 100.0)
    c_score = candidate.get("posture", {}).get("score", 100.0)
    posture_delta = round(float(c_score) - float(b_score), 1)

    return {
        "baseline_id": baseline_id,
        "candidate_id": candidate_id,
        "baseline_posture": baseline.get("posture", {}),
        "candidate_posture": candidate.get("posture", {}),
        "posture_delta": posture_delta,
        "resolved_count": len(resolved),
        "new_count": len(new_findings),
        "persistent_count": len(persistent),
        "resolved_findings": resolved,
        "new_findings": new_findings,
        "persistent_findings": persistent,
    }
