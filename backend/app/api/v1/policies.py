"""Policies and Rules API routes per SRS §9.1."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from analyzer.rules.loader import get_available_policies, load_policy
from backend.app.deps import get_current_token

router = APIRouter(tags=["Policies & Rules"])


@router.get("/policies")
async def list_policies(
    _token: str | None = Depends(get_current_token),
) -> list[dict[str, Any]]:
    """List available security policy profiles."""
    policy_ids = get_available_policies()
    profiles = []
    for pid in policy_ids:
        try:
            p = load_policy(pid)
            profiles.append({
                "id": p.policy_id,
                "name": p.policy_id.replace("_", " ").title(),
                "description": p.description,
                "version": p.version,
                "rule_count": len(p.rules),
                "policy_hash": p.policy_hash,
            })
        except Exception:
            profiles.append({
                "id": pid,
                "name": pid.replace("_", " ").title(),
                "description": f"{pid} policy profile",
                "version": "1.0",
                "rule_count": 0,
                "policy_hash": "",
            })
    return profiles


@router.get("/rules")
async def list_rules(
    policy: str = Query("nist_default"),
    _token: str | None = Depends(get_current_token),
) -> list[dict[str, Any]]:
    """List rules included in a given policy profile."""
    try:
        p = load_policy(policy)
        return [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "explanation": r.explanation,
                "target": r.target,
                "confidence": r.confidence,
                "references": r.references,
                "mitre": r.mitre,
                "recommendation_id": r.recommendation_id,
            }
            for r in p.rules
        ]
    except Exception:
        return []
