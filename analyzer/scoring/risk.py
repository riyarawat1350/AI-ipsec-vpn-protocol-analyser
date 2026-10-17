"""Risk and severity scoring per SRS §12.3 / SPEC §5.11 — TASK-025/029.

R = round(impact * likelihood / 25 * 100 * (0.5 + 0.5 * confidence), 1)
Bands:
- Critical >= 85.0
- High >= 65.0
- Medium >= 35.0
- Low >= 15.0
- Info < 15.0 (or impact == 0)
"""

from __future__ import annotations


def calculate_risk(impact: int, likelihood: int, confidence: float = 1.0) -> float:
    """Calculate risk score R in range [0.0, 100.0]."""
    impact_clamped = max(1, min(5, impact))
    likelihood_clamped = max(1, min(5, likelihood))
    conf_clamped = max(0.0, min(1.0, confidence))

    r = (impact_clamped * likelihood_clamped / 25.0) * 100.0 * (0.5 + 0.5 * conf_clamped)
    return round(r, 1)


def calculate_severity(
    risk_score: float,
    impact: int = 1,
    override: str | None = None,
) -> str:
    """Map risk score to severity band, respecting impact=0 and overrides."""
    if override:
        return override
    if impact == 0:
        return "Info"
    if risk_score >= 85.0:
        return "Critical"
    if risk_score >= 65.0:
        return "High"
    if risk_score >= 35.0:
        return "Medium"
    if risk_score >= 15.0:
        return "Low"
    return "Info"
