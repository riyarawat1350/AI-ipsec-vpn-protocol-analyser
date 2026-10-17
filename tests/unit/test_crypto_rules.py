"""Tests for Cryptographic Security Rules (TASK-025).

Acceptance criteria:
- Positive and negative fixture test per rule
- Risk values equal SRS worked examples: 80.0, 48.0, 60.0
"""

from __future__ import annotations

from pathlib import Path
import pytest

from analyzer.capture.reader import CaptureReader
from analyzer.capture.decode import PacketDecoder
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.sessions import reconstruct_ike_sessions, ikemessage_to_model
from analyzer.features.facts import build_facts
from analyzer.rules.loader import load_policy
from analyzer.rules.engine import RuleEngine
from analyzer.scoring.risk import calculate_risk

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


def test_worked_example_risk_values() -> None:
    """SRS §12.3 worked examples: 80.0, 48.0, 60.0."""
    # 1. DH group 2 selected: impact=4, likelihood=5, confidence=1.0 -> 80.0
    r_dh_selected = calculate_risk(impact=4, likelihood=5, confidence=1.0)
    assert r_dh_selected == 80.0

    # 2. DH group 2 offered: impact=4, likelihood=3, confidence=1.0 -> 48.0
    r_dh_offered = calculate_risk(impact=4, likelihood=3, confidence=1.0)
    assert r_dh_offered == 48.0

    # 3. 3DES selected: impact=3, likelihood=5, confidence=1.0 -> 60.0
    r_3des_selected = calculate_risk(impact=3, likelihood=5, confidence=1.0)
    assert r_3des_selected == 60.0

    # 4. 3DES offered: impact=3, likelihood=3, confidence=1.0 -> 36.0
    r_3des_offered = calculate_risk(impact=3, likelihood=3, confidence=1.0)
    assert r_3des_offered == 36.0


def _facts_from_pcap(pcap_path: Path) -> any:
    reader = CaptureReader(pcap_path)
    decoder = PacketDecoder()
    messages = []
    for frame in reader.iter_frames():
        parsed = decoder.decode(frame)
        if parsed and parsed.payload and (parsed.sport in (500, 4500) or parsed.dport in (500, 4500)):
            ike = parse_ikev2(parsed.payload)
            if ike:
                model = ikemessage_to_model(
                    ike,
                    pkt_no=frame.pkt_no,
                    ts=frame.ts,
                    src_ip=parsed.src,
                    src_port=parsed.sport or 500,
                    dst_ip=parsed.dst,
                    dst_port=parsed.dport or 500,
                )
                messages.append(model)
    sessions = reconstruct_ike_sessions(messages)
    return build_facts(sessions=sessions)


def test_positive_crypto_rules_weak_dh_fixture() -> None:
    """ikev2_weak_dh.pcap offers DH 1, 3DES, MD5: triggers CRY-DH-001, CRY-ENC-001, CRY-INT-001."""
    pcap_path = FIXTURES_DIR / "ikev2_weak_dh.pcap"
    assert pcap_path.exists()

    facts = _facts_from_pcap(pcap_path)
    policy = load_policy("nist_default")
    engine = RuleEngine(policy)
    findings = engine.evaluate(facts)

    rule_ids = {f.rule_id for f in findings}
    assert "CRY-DH-001" in rule_ids
    assert "CRY-ENC-001" in rule_ids
    assert "CRY-INT-001" in rule_ids

    # Check DH finding properties
    dh_finding = next(f for f in findings if f.rule_id == "CRY-DH-001")
    assert dh_finding.impact == 5  # DH Group 1 is broken (impact 5)
    assert dh_finding.likelihood == 3  # offered


def test_negative_crypto_rules_strong_fixture() -> None:
    """ikev2_sa_init.pcap has AES-CBC-256, DH 14, SHA2-256: no weak crypto findings."""
    pcap_path = FIXTURES_DIR / "ikev2_sa_init.pcap"
    assert pcap_path.exists()

    facts = _facts_from_pcap(pcap_path)
    policy = load_policy("nist_default")
    engine = RuleEngine(policy)
    findings = engine.evaluate(facts)

    rule_ids = {f.rule_id for f in findings}
    assert "CRY-DH-001" not in rule_ids
    assert "CRY-ENC-001" not in rule_ids
    assert "CRY-INT-001" not in rule_ids
    # CRY-ENC-002 may be present as informational
    if "CRY-ENC-002" in rule_ids:
        f = next(f for f in findings if f.rule_id == "CRY-ENC-002")
        assert f.override_severity == "Info"


def test_strict_policy_flags_modp2048() -> None:
    """Strict policy flags MODP-2048 (DH 14) and AES-CBC."""
    pcap_path = FIXTURES_DIR / "ikev2_sa_init.pcap"
    facts = _facts_from_pcap(pcap_path)
    strict_policy = load_policy("strict")
    engine = RuleEngine(strict_policy)
    findings = engine.evaluate(facts)

    rule_ids = {f.rule_id for f in findings}
    assert "CRY-DH-001" in rule_ids
    assert "CRY-ENC-001" in rule_ids
