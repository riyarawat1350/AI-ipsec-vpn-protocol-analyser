"""Glossary API endpoints per Phase 4 requirements."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from analyzer.explain.engine import get_term, load_glossary

router = APIRouter(prefix="/glossary", tags=["glossary"])


@router.get("")
@router.get("/")
async def list_glossary_terms(
    q: str | None = Query(default=None, description="Search term in name, expansion, or explanation"),
) -> dict[str, Any]:
    """Return all glossary entries with optional case-insensitive search."""
    glossary = load_glossary()
    seen = set()
    unique_terms = []
    for t in glossary.values():
        if t["id"] not in seen:
            unique_terms.append(t)
            seen.add(t["id"])

    if q:
        q_lower = q.lower().strip()
        unique_terms = [
            t for t in unique_terms
            if q_lower in t.get("name", "").lower()
            or q_lower in t.get("expansion", "").lower()
            or q_lower in t.get("simple", "").lower()
            or q_lower in t.get("why_it_matters", "").lower()
        ]
    return {
        "items": unique_terms,
        "total": len(unique_terms),
    }


@router.get("/{term_id}", response_model=dict[str, Any])
async def get_glossary_term(term_id: str) -> dict[str, Any]:
    """Retrieve a single glossary definition by term ID."""
    term = get_term(term_id)
    if not term:
        raise HTTPException(status_code=404, detail=f"Glossary term '{term_id}' not found")
    return term
