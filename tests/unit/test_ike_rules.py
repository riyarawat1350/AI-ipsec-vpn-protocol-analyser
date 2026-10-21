"""Unit tests for IKE policy rules — TASK-026.

Verifies:
- IKE-V1-001: IKEv1 protocol in use (40.0 Medium)
- IKE-V1-002: Aggressive Mode used (60.0 Medium)
- IKE-V1-003: Aggressive Mode with PSK exposes authentication hash (80.0 High, MITRE T1110.002)
- IKE-V1-004: Excessive IKEv1 SA lifetime (> 86400s) (40.0 Medium, negative at 28800s)
- IKE-V1-005: IKEv1 PSK authentication in use (20.0 Low)
- IKE-PROTO-001: Malformed IKE messages / anomalies (22.8 Low)
- IKE-PROTO-002: Key Exchange length mismatch (45.6 Medium)
- IKE-INFO-001: Peer implementation fingerprint (Info)
- IKE-INFO-002: NAT-Traversal active (Info)
"""

from __future__ import annotations

import pytest

from analyzer.features.facts import build_facts
from analyzer.models import Endpoint, IkeSession, Observation
from analyzer.rules.engine import RuleEngine
from analyzer.rules.loader import load_policy
from analyzer.scoring.risk import calculate_risk, calculate_severity


@pytest.fixture
def default_engine() -> RuleEngine:
    policy = load_policy("nist_default")
    return RuleEngine(policy)


def _make_dummy_session(
    version: int = 1,
    aggressive_mode: bool = False,
    has_psk: bool = False,
    has_cleartext_hash: bool = False,
    has_anomalies: bool = False,
    ke_mismatch: bool = False,
    has_vendor_ids: bool = False,
    natt: bool = False,
    session_id: str = "sess-1",
) -> IkeSession:
    return IkeSession(
        id=session_id,
        version=version,
        spi_i="0123456789abcdef",
        spi_r="fedcba9876543210",
        initiator=Endpoint(ip="10.0.0.1", port=500),
        responder=Endpoint(ip="10.0.0.2", port=500),
        natt=natt,
        first_ts=1700000000.0,
        last_ts=1700000001.0,
        messages=[],
        offered=[],
        selected=None,
        outcome="established_observed",
        retransmissions=0,
        ke_retries=0,
        aggressive_mode=aggressive_mode,
        encrypted_not_observable=[],
        has_anomalies=has_anomalies,
        has_vendor_ids=has_vendor_ids,
        has_psk=has_psk,
        has_cleartext_hash=has_cleartext_hash,
        ke_mismatch=ke_mismatch,
    )


def test_ike_v1_001_deprecated_protocol(default_engine: RuleEngine) -> None:
    """IKE-V1-001 triggers on IKEv1 with score 40.0 Medium, clean on IKEv2."""
    v1_session = _make_dummy_session(version=1)
    facts = build_facts(sessions=[v1_session])
    findings = default_engine.evaluate(facts)

    v1_finding = next((f for f in findings if f.rule_id == "IKE-V1-001"), None)
    assert v1_finding is not None
    assert v1_finding.impact == 2
    assert v1_finding.likelihood == 5
    risk = calculate_risk(v1_finding.impact, v1_finding.likelihood, v1_finding.confidence)
    assert risk == 40.0
    assert calculate_severity(risk, v1_finding.impact) == "Medium"
    assert v1_finding.recommendation_id == "REC-IKEV2"

    # Clean on IKEv2
    v2_session = _make_dummy_session(version=2)
    facts_v2 = build_facts(sessions=[v2_session])
    findings_v2 = default_engine.evaluate(facts_v2)
    assert not any(f.rule_id == "IKE-V1-001" for f in findings_v2)


def test_ike_v1_002_aggressive_mode(default_engine: RuleEngine) -> None:
    """IKE-V1-002 triggers when aggressive_mode is True, score 60.0 Medium."""
    am_session = _make_dummy_session(version=1, aggressive_mode=True)
    facts = build_facts(sessions=[am_session])
    findings = default_engine.evaluate(facts)

    am_finding = next((f for f in findings if f.rule_id == "IKE-V1-002"), None)
    assert am_finding is not None
    assert am_finding.impact == 3
    assert am_finding.likelihood == 5
    risk = calculate_risk(am_finding.impact, am_finding.likelihood, am_finding.confidence)
    assert risk == 60.0
    assert calculate_severity(risk, am_finding.impact) == "Medium"
    assert am_finding.recommendation_id == "REC-NO-AGGR"

    # Main mode (aggressive_mode=False) does not trigger IKE-V1-002
    mm_session = _make_dummy_session(version=1, aggressive_mode=False)
    facts_mm = build_facts(sessions=[mm_session])
    findings_mm = default_engine.evaluate(facts_mm)
    assert not any(f.rule_id == "IKE-V1-002" for f in findings_mm)


def test_ike_v1_003_aggressive_psk_hash_exposure(default_engine: RuleEngine) -> None:
    """IKE-V1-003 triggers when AM + PSK + cleartext hash, score 80.0 High, MITRE T1110.002."""
    psk_am_session = _make_dummy_session(
        version=1,
        aggressive_mode=True,
        has_psk=True,
        has_cleartext_hash=True,
    )
    facts = build_facts(sessions=[psk_am_session])
    findings = default_engine.evaluate(facts)

    psk_finding = next((f for f in findings if f.rule_id == "IKE-V1-003"), None)
    assert psk_finding is not None
    assert psk_finding.impact == 4
    assert psk_finding.likelihood == 5
    risk = calculate_risk(psk_finding.impact, psk_finding.likelihood, psk_finding.confidence)
    assert risk == 80.0
    assert calculate_severity(risk, psk_finding.impact) == "High"
    assert "T1110.002" in psk_finding.mitre
    assert psk_finding.recommendation_id == "REC-NO-AGGR"

    # Negative case: AM without PSK (e.g. cert auth)
    no_psk_session = _make_dummy_session(
        version=1,
        aggressive_mode=True,
        has_psk=False,
        has_cleartext_hash=True,
    )
    facts_no_psk = build_facts(sessions=[no_psk_session])
    findings_no_psk = default_engine.evaluate(facts_no_psk)
    assert not any(f.rule_id == "IKE-V1-003" for f in findings_no_psk)


def test_ike_v1_004_excessive_lifetime(default_engine: RuleEngine) -> None:
    """IKE-V1-004 triggers on lifetime > 86400s (score 40.0 Medium), not on 28800s."""
    excessive_obs = Observation(
        session_id="s1",
        kind="lifetime",
        id=100000,
        name="100000s",
        role="selected",
        pkt_no=1,
        field_path="session.selected.transforms[0]",
        raw_hex="000186a0",
        ike_version=1,
    )
    facts = build_facts(observations=[excessive_obs])
    findings = default_engine.evaluate(facts)
    f4 = next((f for f in findings if f.rule_id == "IKE-V1-004"), None)
    assert f4 is not None
    assert f4.impact == 2
    assert f4.likelihood == 5
    risk = calculate_risk(f4.impact, f4.likelihood, f4.confidence)
    assert risk == 40.0
    assert calculate_severity(risk, f4.impact) == "Medium"
    assert f4.recommendation_id == "REC-LIFETIME"

    # Negative case: normal lifetime 28800s (8 hours) <= 86400s
    normal_obs = Observation(
        session_id="s1",
        kind="lifetime",
        id=28800,
        name="28800s",
        role="selected",
        pkt_no=1,
        field_path="session.selected.transforms[0]",
        raw_hex="00007080",
        ike_version=1,
    )
    facts_normal = build_facts(observations=[normal_obs])
    findings_normal = default_engine.evaluate(facts_normal)
    assert not any(f.rule_id == "IKE-V1-004" for f in findings_normal)


def test_ike_v1_005_psk_authentication(default_engine: RuleEngine) -> None:
    """IKE-V1-005 triggers on selected transform with AUTH=PSK, score 20.0 Low."""
    psk_obs = Observation(
        session_id="s1",
        kind="auth_method",
        id=1,
        name="PSK",
        role="selected",
        pkt_no=2,
        field_path="session.selected.transforms[1]",
        raw_hex="0001",
        ike_version=1,
    )
    facts = build_facts(observations=[psk_obs])
    findings = default_engine.evaluate(facts)
    f5 = next((f for f in findings if f.rule_id == "IKE-V1-005"), None)
    assert f5 is not None
    assert f5.impact == 1
    assert f5.likelihood == 5
    risk = calculate_risk(f5.impact, f5.likelihood, f5.confidence)
    assert risk == 20.0
    assert calculate_severity(risk, f5.impact) == "Low"
    assert f5.recommendation_id == "REC-CERT-AUTH"


def test_ike_proto_001_malformed_anomalies(default_engine: RuleEngine) -> None:
    """IKE-PROTO-001 triggers when has_anomalies=True, score 22.8 Low."""
    anom_session = _make_dummy_session(has_anomalies=True)
    facts = build_facts(sessions=[anom_session])
    findings = default_engine.evaluate(facts)
    f_proto = next((f for f in findings if f.rule_id == "IKE-PROTO-001"), None)
    assert f_proto is not None
    assert f_proto.impact == 2
    assert f_proto.likelihood == 3
    assert f_proto.confidence == 0.9
    risk = calculate_risk(f_proto.impact, f_proto.likelihood, f_proto.confidence)
    assert risk == 22.8
    assert calculate_severity(risk, f_proto.impact) == "Low"
    assert f_proto.recommendation_id == "REC-INVESTIGATE-PEER"


def test_ike_proto_002_ke_length_mismatch(default_engine: RuleEngine) -> None:
    """IKE-PROTO-002 triggers when ke_mismatch=True, score 45.6 Medium."""
    ke_session = _make_dummy_session(ke_mismatch=True)
    facts = build_facts(sessions=[ke_session])
    findings = default_engine.evaluate(facts)
    f_ke = next((f for f in findings if f.rule_id == "IKE-PROTO-002"), None)
    assert f_ke is not None
    assert f_ke.impact == 3
    assert f_ke.likelihood == 4
    assert f_ke.confidence == 0.9
    risk = calculate_risk(f_ke.impact, f_ke.likelihood, f_ke.confidence)
    assert risk == 45.6
    assert calculate_severity(risk, f_ke.impact) == "Medium"
    assert f_ke.recommendation_id == "REC-INVESTIGATE-PEER"


def test_ike_info_001_vendor_fingerprint(default_engine: RuleEngine) -> None:
    """IKE-INFO-001 triggers on has_vendor_ids=True with override_severity 'Info'."""
    vid_session = _make_dummy_session(has_vendor_ids=True)
    facts = build_facts(sessions=[vid_session])
    findings = default_engine.evaluate(facts)
    f_vid = next((f for f in findings if f.rule_id == "IKE-INFO-001"), None)
    assert f_vid is not None
    assert f_vid.override_severity == "Info"
    assert calculate_severity(10.0, f_vid.impact, override=f_vid.override_severity) == "Info"
    assert f_vid.recommendation_id == "REC-PATCH-HYGIENE"


def test_ike_info_002_natt_active(default_engine: RuleEngine) -> None:
    """IKE-INFO-002 triggers on natt=True with override_severity 'Info'."""
    natt_session = _make_dummy_session(natt=True)
    facts = build_facts(sessions=[natt_session])
    findings = default_engine.evaluate(facts)
    f_natt = next((f for f in findings if f.rule_id == "IKE-INFO-002"), None)
    assert f_natt is not None
    assert f_natt.override_severity == "Info"
    assert calculate_severity(10.0, f_natt.impact, override=f_natt.override_severity) == "Info"
