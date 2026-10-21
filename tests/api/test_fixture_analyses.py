"""Automated tests for F01, F02, F10, F13 fixture lifecycles, PDF reports, and failure cases (Task 8)."""

from pathlib import Path

import pytest

from analyzer.config import AnalyzerConfig
from analyzer.pipeline import Pipeline
from backend.app.services.reports import _build_pdf_report

PCAP_DIR = Path("tests/fixtures/pcap")


@pytest.mark.api
def test_f02_lifecycle_posture_and_findings():
    """Verify F02 weak DH/3DES capture matches Document 05 Section 3 expectations."""
    pcap_path = PCAP_DIR / "ikev2_modp1024_3des.pcap"
    assert pcap_path.exists(), "F02 fixture must exist"

    pipeline = Pipeline(config=AnalyzerConfig())
    res = pipeline.run(pcap_path, policy_id="nist_default")

    assert res.posture["score"] == pytest.approx(25.8, abs=0.5)
    assert res.posture["grade"] == "F"

    rule_ids = [f.rule_id for f in res.findings]
    assert "CRY-DH-001" in rule_ids
    assert "CRY-ENC-001" in rule_ids
    assert "CRY-INT-001" in rule_ids


@pytest.mark.api
def test_f01_hardened_profile():
    """Verify F01 modern AES-GCM + X25519 capture matches Document 05 expectations."""
    pcap_path = PCAP_DIR / "ikev2_modern_gcm_x25519.pcap"
    assert pcap_path.exists(), "F01 fixture must exist"

    pipeline = Pipeline(config=AnalyzerConfig())
    res = pipeline.run(pcap_path, policy_id="nist_default")

    assert res.posture["score"] == pytest.approx(100.0, abs=0.1)
    assert res.posture["grade"] == "A"

    rule_ids = [f.rule_id for f in res.findings]
    assert "IKE-INFO-001" in rule_ids


@pytest.mark.api
def test_f10_flood_detection():
    """Verify F10 IKE SA_INIT flood triggers both IKE-DOS-001 and IKE-DOS-002."""
    pcap_path = PCAP_DIR / "lab_ike_init_flood.pcap"
    assert pcap_path.exists(), "F10 fixture must exist"

    pipeline = Pipeline(config=AnalyzerConfig())
    res = pipeline.run(pcap_path, policy_id="nist_default")

    rule_ids = {f.rule_id for f in res.findings}
    assert "IKE-DOS-001" in rule_ids
    assert "IKE-DOS-002" in rule_ids


@pytest.mark.api
def test_f13_esp_null_detection():
    """Verify F13 plaintext ESP triggers ESP-NULL-001 and ESP-NOIKE-001."""
    pcap_path = PCAP_DIR / "esp_null.pcap"
    assert pcap_path.exists(), "F13 fixture must exist"

    pipeline = Pipeline(config=AnalyzerConfig())
    res = pipeline.run(pcap_path, policy_id="nist_default")

    assert res.posture["grade"] == "F"
    assert res.posture["score"] <= 39.0

    rule_ids = {f.rule_id for f in res.findings}
    assert "ESP-NULL-001" in rule_ids
    assert "ESP-NOIKE-001" in rule_ids


@pytest.mark.api
def test_pdf_report_generation(tmp_path):
    """Verify generating and storing a valid PDF audit report."""
    pipeline = Pipeline(config=AnalyzerConfig())
    pcap_path = PCAP_DIR / "ikev2_modp1024_3des.pcap"
    res = pipeline.run(pcap_path, policy_id="nist_default")

    pdf_out = tmp_path / "test_report.pdf"
    findings_data = [f.model_dump() for f in res.findings]
    sessions_data = [s.model_dump() for s in res.facts.sessions]
    flows_data = [fl.model_dump() for fl in res.facts.flows]

    _build_pdf_report(
        filepath=pdf_out,
        analysis={"_id": "test_analysis_001", "posture": res.posture, "narrative": res.narrative},
        upload={"original_filename": "ikev2_modp1024_3des.pcap", "sha256": "abcdef1234567890"},
        findings=findings_data,
        sessions=sessions_data,
        flows=flows_data,
        recommendations=res.recommendations,
    )

    assert pdf_out.exists()
    content = pdf_out.read_bytes()
    assert len(content) > 1000
    assert content.startswith(b"%PDF-")
    assert b"%%EOF" in content[-100:]


@pytest.mark.api
def test_truncated_pcap_handled():
    """Verify truncated PCAP completes with warning and does not crash."""
    pcap_path = PCAP_DIR / "truncated.pcap"
    assert pcap_path.exists(), "truncated.pcap must exist"

    pipeline = Pipeline(config=AnalyzerConfig())
    res = pipeline.run(pcap_path, policy_id="nist_default")

    assert res.posture["score"] is not None
    assert any("Truncated" in w for w in res.facts.warnings)
