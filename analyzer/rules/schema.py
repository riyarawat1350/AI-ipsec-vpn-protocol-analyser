"""Pydantic schema for declarative security policies — TASK-023.

FR-44, NFR-08:
Strict validation (extra fields forbidden, safe types only).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ImpactDef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default: int | None = None
    table: str | None = None
    fixed: int | None = None


class LikelihoodDef(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    fixed: int | None = None
    from_role: str | None = Field(default=None, alias="from")


class RuleDef(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    target: Literal["observation", "session", "flow"]
    category: str
    title: str
    explanation: str
    why_this_matters: str = ""
    condition: dict[str, Any]
    impact: ImpactDef | int | dict[str, Any]
    likelihood: LikelihoodDef | int | dict[str, Any]
    confidence: float = 1.0
    override_severity: str | None = None
    group_by: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    recommendation_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    plain_summary: str = ""
    plain_impact: str = ""
    plain_fix: str = ""


class PolicyDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    version: str = "1.0"
    description: str = ""
    tables: dict[str, dict[str, int]] = Field(default_factory=dict)
    rules: list[RuleDef] = Field(default_factory=list)
    detector_settings: dict[str, Any] = Field(default_factory=dict)
    policy_hash: str = ""
