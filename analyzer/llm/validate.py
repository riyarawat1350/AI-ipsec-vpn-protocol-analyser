"""Sanitization and output validation for LLM narrative (TASK-039 / SRS §11.5).

Ensures:
1. Prompts contain NO raw packets, NO hex payloads, and real IPs are pseudonymized (Peer-A, Peer-B).
2. LLM outputs conform to schema: {executive_summary (<=250 words), key_points: [{finding_id, text}]}.
3. Every finding_id exists in the actual findings list.
4. Numerical claims (posture score, finding counts) match actual analysis data.
5. Invalid or hallucinated output is discarded in favor of deterministic template.
"""

from __future__ import annotations

import json
import re
from typing import Any

from analyzer.models import Finding

# Regex for IPv4 addresses
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
# Regex for long hex sequences (packet dumps / raw bytes)
HEX_REGEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")


def sanitize_text(text: str, ip_map: dict[str, str], redact_hex: bool = True) -> str:
    """Replace real IP addresses with pseudonyms and strip raw hex."""
    if not text:
        return ""

    out = text
    # Strip long hex
    if redact_hex:
        out = HEX_REGEX.sub("[RAW_HEX_REDACTED]", out)

    # Replace IPs
    for real_ip, pseudonym in ip_map.items():
        out = out.replace(real_ip, pseudonym)

    return out


def build_ip_map(findings: list[Finding], facts: Any = None) -> dict[str, str]:
    """Build a deterministic mapping from discovered real IPs to Peer-A, Peer-B, etc."""
    seen_ips: list[str] = []

    def _add_ip(ip_str: str | None) -> None:
        if not ip_str:
            return
        # Extract individual IPs if present
        for match in IPV4_REGEX.findall(ip_str):
            if match not in seen_ips:
                seen_ips.append(match)

    # 1. Harvest from findings
    for f in findings:
        _add_ip(f.title)
        _add_ip(f.explanation)
        for s in f.affected_sessions:
            _add_ip(s)
        for ev in f.evidence:
            _add_ip(ev.field_path)

    # 2. Harvest from facts if available
    if facts is not None:
        for sess in getattr(facts, "ike_sessions", []):
            if hasattr(sess, "initiator") and hasattr(sess.initiator, "ip"):
                _add_ip(sess.initiator.ip)
            if hasattr(sess, "responder") and hasattr(sess.responder, "ip"):
                _add_ip(sess.responder.ip)
        for flow in getattr(facts, "ipsec_flows", []):
            _add_ip(getattr(flow, "src", None))
            _add_ip(getattr(flow, "dst", None))

    mapping: dict[str, str] = {}
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for idx, ip in enumerate(seen_ips):
        tag = letters[idx] if idx < len(letters) else f"Peer-{idx+1}"
        mapping[ip] = f"Peer-{tag}"

    return mapping


def sanitize_prompt_payload(
    posture: dict[str, Any],
    findings: list[Finding],
    recommendations: list[dict[str, Any]],
    capture_meta: dict[str, Any],
    facts: Any = None,
    send_real_ips: bool = False,
) -> dict[str, Any]:
    """Create a clean, structured payload containing only safe findings data."""
    ip_map = {} if send_real_ips else build_ip_map(findings, facts)

    sanitized_findings: list[dict[str, Any]] = []
    for f in findings[:15]:  # limit to top 15 to stay within token budget
        sanitized_findings.append({
            "finding_id": f.id,
            "rule_id": f.rule_id,
            "title": sanitize_text(f.title, ip_map),
            "severity": f.severity,
            "risk_score": round(float(f.risk_score), 1),
            "plain_explanation": sanitize_text(f.explanation, ip_map),
        })

    sanitized_recs: list[dict[str, Any]] = []
    for r in recommendations[:5]:
        sanitized_recs.append({
            "recommendation_id": r.get("recommendation_id"),
            "title": sanitize_text(r.get("title", ""), ip_map),
            "risk_reduction": r.get("risk_reduction"),
        })

    severity_counts = {
        "Critical": sum(1 for f in findings if f.severity == "Critical"),
        "High": sum(1 for f in findings if f.severity == "High"),
        "Medium": sum(1 for f in findings if f.severity == "Medium"),
        "Low": sum(1 for f in findings if f.severity == "Low"),
    }

    return {
        "posture": {
            "score": round(float(posture.get("score", 100.0)), 1),
            "grade": posture.get("grade", "A"),
            "severity_counts": severity_counts,
        },
        "capture": {
            "total_packets": capture_meta.get("total_packets", 0),
            "duration_seconds": round(float(capture_meta.get("duration_seconds", 0.0)), 1),
        },
        "findings": sanitized_findings,
        "recommendations": sanitized_recs,
    }


def validate_llm_output(
    raw_output: str | None,
    allowed_findings: list[Finding],
    source_metrics: dict[str, Any],
) -> dict[str, Any] | None:
    """Validate JSON schema, finding IDs, word count, and numerical consistency.

    Returns validated dict if valid, or None if validation fails.
    """
    if not raw_output or not raw_output.strip():
        return None

    # Parse JSON
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        # Fallback regex search for JSON block
        match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    if not isinstance(data, dict):
        return None

    # 1. Schema check
    executive_summary = data.get("executive_summary")
    key_points = data.get("key_points")

    if not isinstance(executive_summary, str) or not executive_summary.strip():
        return None

    if not isinstance(key_points, list):
        return None

    # 2. Word count check (<= 250 words)
    words = executive_summary.split()
    if len(words) > 250:
        return None

    # 3. Finding IDs check: every key_point finding_id MUST exist in source findings
    allowed_ids = {f.id for f in allowed_findings} | {f.rule_id for f in allowed_findings}
    # If no findings exist, key_points should be empty
    if not allowed_findings and len(key_points) > 0:
        return None

    clean_key_points: list[dict[str, str]] = []
    for kp in key_points:
        if not isinstance(kp, dict):
            return None
        fid = kp.get("finding_id") or kp.get("id")
        text = kp.get("text") or kp.get("summary") or ""
        if not fid or fid not in allowed_ids:
            # Hallucinated or unknown finding_id -> reject whole LLM output
            return None
        clean_key_points.append({"finding_id": str(fid), "text": str(text).strip()})

    # 4. Numerical validation
    # Extract mentioned score: "score of X", "score X/100", "posture score: X"
    full_text = executive_summary + " " + " ".join(kp["text"] for kp in clean_key_points)

    actual_score = float(source_metrics.get("score", 100.0))
    score_matches = re.findall(r"(?:score\s+(?:of\s+)?|score:\s*)(\d+(?:\.\d+)?)", full_text, re.IGNORECASE)
    for sm in score_matches:
        try:
            val = float(sm)
            # If the number is in 0..100 range and looks like a score mention, verify it matches
            if 0.0 <= val <= 100.0 and abs(val - actual_score) > 2.0:
                return None  # Hallucinated score
        except ValueError:
            pass

    # Severity count checks
    critical_count = int(source_metrics.get("critical_count", 0))
    crit_matches = re.findall(r"(\d+)\s+Critical", full_text, re.IGNORECASE)
    for cm in crit_matches:
        if int(cm) != critical_count:
            return None  # Hallucinated critical count

    high_count = int(source_metrics.get("high_count", 0))
    high_matches = re.findall(r"(\d+)\s+High", full_text, re.IGNORECASE)
    for hm in high_matches:
        if int(hm) != high_count:
            return None  # Hallucinated high count

    return {
        "executive_summary": executive_summary.strip(),
        "key_points": clean_key_points,
    }
