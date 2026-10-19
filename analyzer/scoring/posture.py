"""Posture calculation and grading per SRS §12.3 and SPEC §5.11.

Formula:
  P = 100 * prod(1 - 0.6 * min(r, 95) / 100 for r in findings with severity >= Low)
  Caps:
    any Critical finding => P <= 39.0
    any High finding => P <= 59.0
  Grade:
    P >= 90: "A"
    P >= 75: "B"
    P >= 60: "C"
    P >= 40: "D"
    P < 40: "F"
"""

from __future__ import annotations

import math
from typing import Any

from analyzer.models import Finding


def calculate_posture(findings: list[Finding]) -> dict[str, Any]:
    """Calculate the overall security posture score (0-100) and grade."""
    qualifying_severities = {"Low", "Medium", "High", "Critical"}

    # Compute multiplicative risk product
    p = 100.0
    for f in findings:
        if f.severity in qualifying_severities:
            r = min(float(f.risk_score), 95.0)
            factor = 1.0 - (0.6 * (r / 100.0))
            p *= factor

    # Enforce boundaries
    p = max(0.0, min(100.0, p))

    # Apply caps
    caps_applied: list[str] = []
    has_critical = any(f.severity == "Critical" for f in findings)
    has_high = any(f.severity == "High" for f in findings)

    if has_critical and p > 39.0:
        p = 39.0
        caps_applied.append("Critical finding present (cap 39)")
    elif has_high and p > 59.0:
        p = 59.0
        caps_applied.append("High finding present (cap 59)")

    p = round(p, 1)

    # Determine letter grade
    if p >= 90.0:
        grade = "A"
    elif p >= 75.0:
        grade = "B"
    elif p >= 60.0:
        grade = "C"
    elif p >= 40.0:
        grade = "D"
    else:
        grade = "F"

    # Count findings by severity
    severity_counts = {
        "Critical": sum(1 for f in findings if f.severity == "Critical"),
        "High": sum(1 for f in findings if f.severity == "High"),
        "Medium": sum(1 for f in findings if f.severity == "Medium"),
        "Low": sum(1 for f in findings if f.severity == "Low"),
        "Info": sum(1 for f in findings if f.severity == "Info"),
    }

    return {
        "score": p,
        "grade": grade,
        "formula": "100 * prod(1 - 0.6 * min(r, 95)/100)",
        "caps_applied": caps_applied,
        "severity_counts": severity_counts,
        "total_qualifying": sum(
            1 for f in findings if f.severity in qualifying_severities
        ),
    }
