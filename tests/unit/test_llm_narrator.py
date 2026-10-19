"""Tests for TASK-039: Optional LLM Narrator (TC-056, TC-057).

Verifies:
1. TC-056: LLM output with unknown finding_id or altered number is rejected
   and template summary is used with origin = 'template'.
2. TC-057: LLM prompt payload contains no raw IPs or hex when send_real_ips=False;
   pseudonyms (Peer-A, Peer-B) are present.
3. Live smoke test with real Groq OpenAI-compat API (guarded by skipif).
"""

from __future__ import annotations

import json
import os
import pytest
from dotenv import load_dotenv

from analyzer.llm.narrator import generate_narrative, generate_template_narrative
from analyzer.llm.providers import FakeLLMProvider, OpenAICompatProvider
from analyzer.llm.validate import sanitize_prompt_payload, validate_llm_output
from analyzer.models import Evidence, Finding

load_dotenv()


def _make_sample_findings() -> list[Finding]:
    """Create sample findings for testing."""
    return [
        Finding(
            id="f_enc_3des_001",
            rule_id="CRY-ENC-001",
            origin="rule",
            category="cryptography",
            title="Deprecated 3DES Encryption Negotiated with 192.168.1.50",
            severity="Critical",
            risk_score=85.0,
            impact=5,
            likelihood=4,
            confidence=1.0,
            fingerprint="fp_3des_001",
            explanation="3DES uses 64-bit block size vulnerable to collision attacks between 192.168.1.50 and 10.0.0.1 with hex payload 0x4a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d",
            why_this_matters="Confidentiality breach via Sweet32 attack (CVE-2016-2183)",
            affected_sessions=["192.168.1.50:500 -> 10.0.0.1:500"],
            recommendation_id="REC-CRY-001",
            evidence=[
                Evidence(
                    packet_no=1,
                    ts=100.0,
                    message="IKE_SA_INIT",
                    field_path="ike.sa.proposal.encr.3des (192.168.1.50)",
                    raw_value="ENCR_3DES",
                    hex_excerpt="0x4a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d",
                )
            ],
        ),
        Finding(
            id="f_dh_grp2_002",
            rule_id="CRY-DH-001",
            origin="rule",
            category="cryptography",
            title="Weak Diffie-Hellman Group 2 (MODP-1024) Offered",
            severity="High",
            risk_score=72.0,
            impact=4,
            likelihood=3,
            confidence=1.0,
            fingerprint="fp_dh_002",
            explanation="1024-bit MODP group does not meet NIST SP 800-77 requirements.",
            why_this_matters="Key exchange vulnerable to discrete log precomputation",
            affected_sessions=["192.168.1.50:500 -> 10.0.0.1:500"],
            recommendation_id="REC-CRY-002",
            evidence=[],
        ),
    ]


def test_tc056_hallucinated_finding_id_rejected():
    """TC-056: Output with unknown finding_id is rejected and template is used."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = [{"recommendation_id": "REC-CRY-001", "title": "Upgrade to AES-256-GCM", "effort": "Low", "risk_reduction": 50.0}]

    # Fake LLM outputs an invented/unknown finding_id "f_hallucinated_999"
    hallucinated_output = json.dumps({
        "executive_summary": "The IPsec analysis detected severe cryptographic weaknesses with a posture score of 35.0.",
        "key_points": [
            {"finding_id": "f_hallucinated_999", "text": "Invented attack vulnerability not present in source findings"}
        ],
    })

    fake_provider = FakeLLMProvider(canned_response=hallucinated_output)

    result = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=fake_provider,
    )

    # Must fall back to deterministic template
    assert result["origin"] == "template"
    assert "Significant cryptographic weaknesses detected" in result["executive_summary"]


def test_tc056_altered_number_rejected():
    """TC-056: Output with altered numbers (score or severity count) is rejected."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = [{"recommendation_id": "REC-CRY-001", "title": "Upgrade to AES-256-GCM", "effort": "Low", "risk_reduction": 50.0}]

    # Actual score is 35.0, but LLM claims a score of 95.0
    altered_score_output = json.dumps({
        "executive_summary": "The audit shows an excellent posture score of 95.0 across the capture.",
        "key_points": [
            {"finding_id": "f_enc_3des_001", "text": "Deprecated 3DES found"}
        ],
    })

    fake_provider = FakeLLMProvider(canned_response=altered_score_output)
    result = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=fake_provider,
    )
    assert result["origin"] == "template"

    # Actual Critical count is 1, but LLM claims 5 Critical findings
    altered_crit_output = json.dumps({
        "executive_summary": "The audit identified 5 Critical vulnerabilities in the tunnel configuration with a score of 35.0.",
        "key_points": [
            {"finding_id": "f_enc_3des_001", "text": "3DES is broken"}
        ],
    })
    fake_provider_crit = FakeLLMProvider(canned_response=altered_crit_output)
    result_crit = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=fake_provider_crit,
    )
    assert result_crit["origin"] == "template"


def test_tc056_valid_llm_output_accepted():
    """TC-056: Valid schema with matching finding IDs and accurate numbers is accepted."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = [{"recommendation_id": "REC-CRY-001", "title": "Upgrade to AES-256-GCM", "effort": "Low", "risk_reduction": 50.0}]

    valid_output = json.dumps({
        "executive_summary": "The IPsec analysis indicates a posture score of 35.0 (Grade F). Exactly 1 Critical and 1 High risk findings require immediate remediation.",
        "key_points": [
            {"finding_id": "f_enc_3des_001", "text": "Deprecated 3DES encryption leaves communication open to Sweet32 attacks."},
            {"finding_id": "f_dh_grp2_002", "text": "MODP-1024 Diffie-Hellman group is below modern security thresholds."}
        ],
    })

    fake_provider = FakeLLMProvider(canned_response=valid_output)
    result = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=fake_provider,
    )

    assert result["origin"] == "llm"
    assert "posture score of 35.0" in result["executive_summary"]
    assert len(result["key_risk_points"]) == 2
    assert "f_enc_3des_001:" in result["key_risk_points"][0]


def test_tc056_excessive_length_rejected():
    """TC-056: Executive summary exceeding 250 words is rejected."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = []

    long_text = "word " * 260
    long_output = json.dumps({
        "executive_summary": long_text,
        "key_points": [{"finding_id": "f_enc_3des_001", "text": "risk"}],
    })

    fake_provider = FakeLLMProvider(canned_response=long_output)
    result = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=fake_provider,
    )
    assert result["origin"] == "template"


def test_tc057_sanitization_no_raw_ips_or_hex():
    """TC-057: Prompt payload contains NO raw IPs and NO hex; pseudonyms present."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = [{"recommendation_id": "REC-CRY-001", "title": "Upgrade to AES-GCM", "risk_reduction": 50.0}]

    payload = sanitize_prompt_payload(
        posture=posture,
        findings=findings,
        recommendations=recs,
        capture_meta=capture_meta,
        send_real_ips=False,
    )

    payload_str = json.dumps(payload)

    # 1. No raw IPs must exist in the payload
    assert "192.168.1.50" not in payload_str
    assert "10.0.0.1" not in payload_str

    # 2. Pseudonyms must be present
    assert "Peer-A" in payload_str
    assert "Peer-B" in payload_str

    # 3. No long hex dumps must exist
    assert "0x4a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d" not in payload_str
    assert "[RAW_HEX_REDACTED]" in payload_str


def test_tc057_send_real_ips_opt_in():
    """TC-057: When send_real_ips=True, IPs are retained."""
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = []

    payload = sanitize_prompt_payload(
        posture=posture,
        findings=findings,
        recommendations=recs,
        capture_meta=capture_meta,
        send_real_ips=True,
    )

    payload_str = json.dumps(payload)
    assert "192.168.1.50" in payload_str


@pytest.mark.skipif(
    not os.getenv("LLM_API_KEY") or os.getenv("LLM_PROVIDER") != "openai_compat",
    reason="Live LLM test requires LLM_API_KEY and LLM_PROVIDER=openai_compat",
)
def test_live_groq_smoke_test():
    """Live smoke test calling Groq LLaMA 3.3 via OpenAICompatProvider.

    Ensures the live endpoint responds with valid JSON and origin = 'llm'.
    NOTE: Key is never printed or logged.
    """
    findings = _make_sample_findings()
    posture = {"score": 35.0, "grade": "F"}
    capture_meta = {"total_packets": 20, "duration_seconds": 3.5}
    recs = [{"recommendation_id": "REC-CRY-001", "title": "Upgrade to AES-GCM", "effort": "Low", "risk_reduction": 50.0}]

    provider = OpenAICompatProvider()
    assert provider.model_name == (os.getenv("LLM_MODEL") or "llama-3.3-70b-versatile")

    result = generate_narrative(
        posture=posture,
        findings=findings,
        capture_meta=capture_meta,
        recommendations=recs,
        enable_llm=True,
        provider=provider,
    )

    # Valid output should produce origin == 'llm'
    assert result["origin"] == "llm"
    assert isinstance(result["executive_summary"], str)
    assert len(result["executive_summary"]) > 20
    assert len(result["executive_summary"].split()) <= 250
    assert isinstance(result["key_risk_points"], list)
