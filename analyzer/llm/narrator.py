"""Executive summary and findings narrator (TASK-031 / TASK-039 / SPEC §5.12).

Provides deterministic, auditable executive summary generation referencing
real finding IDs, numbers, and posture grades.
Optionally integrates with OpenAI-compatible LLM providers (e.g. Groq) with
strict sanitization, pseudonymization, and hallucination rejection.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from analyzer.llm.providers import LLMProvider, get_llm_provider
from analyzer.llm.validate import sanitize_prompt_payload, validate_llm_output
from analyzer.models import Finding

logger = logging.getLogger(__name__)

LLM_SYSTEM_PROMPT = """You are an expert IPsec VPN security auditor.
Analyze the provided sanitized security findings and write an executive summary for C-level and network engineering leaders.

CRITICAL INSTRUCTIONS:
1. Output MUST be valid JSON adhering strictly to this schema:
{
  "executive_summary": "High-level summary paragraph describing the overall IPsec security posture and principal risks (strictly <= 250 words).",
  "key_points": [
    {"finding_id": "exact finding_id from the input findings list", "text": "One-line clear description of the specific risk and consequence."}
  ]
}
2. ONLY reference finding_id values that exist in the input. Do NOT invent new IDs or numbers.
3. Accurate numerical claims only: accurately reflect the posture score, grade, and severity counts provided.
4. Keep the summary under 250 words.
"""


def generate_template_narrative(
    posture: dict[str, Any],
    findings: list[Finding],
    capture_meta: dict[str, Any],
    recommendations: list[dict[str, Any]],
    facts: Any = None,
) -> dict[str, Any]:
    """Generate deterministic narrative referencing actual analysis outputs."""
    score = posture.get("score", 100.0)
    grade = posture.get("grade", "A")
    total_pkts = capture_meta.get("total_packets") or 0
    duration = capture_meta.get("duration_seconds") or 0.0

    # Check if any IPsec / IKE traffic exists
    has_ipsec = True
    sessions = []
    flows = []
    counts: dict[str, int] = {}
    if facts is not None:
        sessions = getattr(facts, "sessions", []) or getattr(facts, "ike_sessions", []) or []
        flows = getattr(facts, "flows", []) or getattr(facts, "ipsec_flows", []) or []
        ike_count = len(sessions)
        flow_count = len(flows)

        pstats = getattr(facts, "protocol_stats", {})
        if isinstance(pstats, dict):
            counts = pstats.get("counts", {}) or {}
        else:
            counts = getattr(pstats, "counts", {}) or {}

        ipsec_pkts = (
            counts.get("ikev1", 0)
            + counts.get("ikev2", 0)
            + counts.get("ike", 0)
            + counts.get("esp", 0)
            + counts.get("ah", 0)
            + counts.get("natt_keepalive", 0)
        )
        if total_pkts > 0 and ike_count == 0 and flow_count == 0 and ipsec_pkts == 0:
            has_ipsec = False

    # Count by severity
    critical_count = sum(1 for f in findings if f.severity == "Critical")
    high_count = sum(1 for f in findings if f.severity == "High")
    med_count = sum(1 for f in findings if f.severity == "Medium")
    low_count = sum(1 for f in findings if f.severity == "Low")
    info_count = sum(1 for f in findings if f.severity == "Info")

    top_risks = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:3]
    top_risk_summaries = [
        f"{f.rule_id} ({f.severity}, Risk {f.risk_score:.1f}): {f.title}"
        for f in top_risks
    ]

    # Generate executive summary paragraph without banned words ("secure", "safe", "strong security", "unhackable", "protected")
    if not has_ipsec and total_pkts > 0:
        posture_desc = (
            f"No IPsec or IKE VPN traffic was detected in this capture ({total_pkts} total packets observed). "
            f"The network traffic consists of standard non-VPN packets (e.g. HTTP, HTTPS, TCP, DNS). "
            f"Consequently, no IPsec configuration parameters or cryptographic algorithms could be evaluated."
        )
        summary_text = (
            f"{posture_desc} Zero security findings were recorded because no IPsec/IKE packets (UDP 500/4500, ESP, AH) "
            f"were found. To analyze your VPN tunnel, please upload a packet capture recorded during active IPsec handshake or data transfer."
        )
    elif grade in ("A", "B"):
        # Construct specific observed summary
        peer_details = ""
        if sessions:
            s0 = sessions[0]
            init_ip = getattr(getattr(s0, "initiator", None), "ip", None) or "Initiator"
            resp_ip = getattr(getattr(s0, "responder", None), "ip", None) or "Responder"
            v_str = f"IKEv{getattr(s0, 'version', 2)}"
            flow_str = f"{len(flows)} ESP flows" if flows else "ESP flows"
            peer_details = (
                f"Observed 1 {v_str} tunnel between {init_ip} and {resp_ip} with {flow_str}."
            )
        else:
            peer_details = f"Observed {counts.get('ikev2', 0) + counts.get('ikev1', 0)} IKE packets and {counts.get('esp', 0)} ESP packets."

        posture_desc = (
            f"No weaknesses found in the parts we could observe (Score: {score}/100, Grade {grade}). "
            f"{peer_details} Encrypted parts (IKE_AUTH identity payloads, ESP tunnel payload contents) were not checked."
        )
        summary_text = (
            f"{posture_desc} A total of {len(findings)} findings were recorded across {total_pkts} "
            f"packets ({duration:.1f}s capture duration): {critical_count} Critical, {high_count} High, "
            f"{med_count} Medium, {low_count} Low, and {info_count} Informational items."
        )
    elif grade == "C":
        posture_desc = (
            f"Moderate configuration risks detected (Score: {score}/100, Grade {grade}). "
            f"While communication is established, legacy parameters were observed that require remediation. "
            f"Encrypted parts (IKE_AUTH, ESP data) were not checked."
        )
        summary_text = (
            f"{posture_desc} A total of {len(findings)} findings were recorded across {total_pkts} "
            f"packets ({duration:.1f}s capture duration): {critical_count} Critical, {high_count} High, "
            f"{med_count} Medium, and {low_count} Low severity items."
        )
    else:
        posture_desc = (
            f"CRITICAL WARNING: Significant cryptographic weaknesses detected (Score: {score}/100, Grade {grade}). "
            f"Deprecated algorithms or cleartext exposures were observed in the unencrypted exchanges. "
            f"Encrypted parts (IKE_AUTH, ESP data) were not checked."
        )
        summary_text = (
            f"{posture_desc} A total of {len(findings)} findings were recorded across {total_pkts} "
            f"packets ({duration:.1f}s capture duration): {critical_count} Critical, {high_count} High, "
            f"{med_count} Medium, and {low_count} Low severity items."
        )

    top_recs = recommendations[:3]
    key_points = []
    for r in top_recs:
        key_points.append({
            "recommendation_id": r["recommendation_id"],
            "title": r["title"],
            "effort": r["effort"],
            "risk_reduction": r["risk_reduction"],
        })

    return {
        "origin": "template",
        "executive_summary": summary_text,
        "posture_assessment": posture_desc,
        "key_risk_points": top_risk_summaries,
        "action_items": key_points,
    }


def generate_narrative(
    posture: dict[str, Any],
    findings: list[Finding],
    capture_meta: dict[str, Any],
    recommendations: list[dict[str, Any]],
    facts: Any = None,
    enable_llm: bool = False,
    provider: LLMProvider | None = None,
    send_real_ips: bool | None = None,
) -> dict[str, Any]:
    """Generate executive summary narrative via optional LLM or deterministic template.

    When enable_llm is True, calls the configured LLM provider with sanitized structured findings.
    If the LLM output fails schema validation, contains hallucinated finding IDs, or misstates
    numbers, it is rejected and deterministic template summary is returned (origin = 'template').
    """
    # Deterministic template baseline
    template_res = generate_template_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recommendations,
        facts=facts,
    )

    if not enable_llm:
        return template_res

    # Resolve provider
    llm_p = provider or get_llm_provider()
    if llm_p is None:
        logger.info("LLM narrative requested but no provider is configured. Using template summary.")
        return template_res

    real_ips = send_real_ips if send_real_ips is not None else (os.getenv("LLM_SEND_REAL_IPS", "false").lower() == "true")

    # Sanitize prompt payload (pseudonymizes IPs, strips raw hex)
    payload = sanitize_prompt_payload(
        posture=posture,
        findings=findings,
        recommendations=recommendations,
        capture_meta=capture_meta,
        facts=facts,
        send_real_ips=real_ips,
    )

    try:
        raw_output = llm_p.generate(
            prompt=json.dumps(payload, indent=2),
            system_prompt=LLM_SYSTEM_PROMPT,
            json_mode=True,
        )
    except Exception as exc:
        logger.warning("LLM provider call raised exception: %s. Using template fallback.", exc)
        return template_res

    if not raw_output:
        logger.info("LLM provider returned empty output. Using template fallback.")
        return template_res

    # Prepare metrics for validation
    source_metrics = {
        "score": posture.get("score", 100.0),
        "critical_count": sum(1 for f in findings if f.severity == "Critical"),
        "high_count": sum(1 for f in findings if f.severity == "High"),
        "total_findings": len(findings),
    }

    validated = validate_llm_output(
        raw_output=raw_output,
        allowed_findings=findings,
        source_metrics=source_metrics,
    )

    if validated is None:
        logger.warning("LLM output rejected by validator (hallucinated finding ID, invalid schema, or altered number). Using template fallback.")
        return template_res

    key_points_text = [
        f"{kp['finding_id']}: {kp['text']}" for kp in validated["key_points"]
    ]
    if not key_points_text:
        key_points_text = template_res.get("key_risk_points", [])

    return {
        "origin": "llm",
        "executive_summary": validated["executive_summary"],
        "posture_assessment": template_res.get("posture_assessment", ""),
        "key_risk_points": key_points_text,
        "action_items": template_res.get("action_items", []),
    }
