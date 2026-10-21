"""Phase 4 Verification Suite: Understandable Output, Plain English, and Glossary Validation.

Tests:
1. glossary.yaml has >= 70 terms with required schema (id, name, expansion, simple <= 25 words, why_it_matters, technical).
2. Every rule in nist_default.yaml contains plain_summary, plain_impact, plain_fix.
3. Readability: average sentence length <= 20 words across all plain fields and report cards.
4. Deterministic 5-point report card generation.
5. Handshake and ESP flow story generators produce short, factual sentences.
6. API endpoint GET /api/v1/glossary and GET /api/v1/glossary/{id} respond correctly.
7. All technical terms in reports and rules exist in the glossary.
"""

from __future__ import annotations

import json
import os
import urllib.request

import pytest
import yaml

from analyzer.explain.engine import (
    compute_plain_readability,
    generate_esp_flow_story,
    generate_ike_story,
    generate_report_card,
    load_glossary,
)

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")


def test_glossary_term_count_and_schema():
    """Verify glossary.yaml contains >= 70 valid terms with required fields."""
    glossary = load_glossary()
    assert len(glossary) >= 70, f"Expected >= 70 terms, got {len(glossary)}"

    for term_id, term in glossary.items():
        assert "id" in term, f"Term {term_id} missing 'id'"
        assert "name" in term, f"Term {term_id} missing 'name'"
        assert "simple" in term, f"Term {term_id} missing 'simple'"
        assert "why_it_matters" in term, f"Term {term_id} missing 'why_it_matters'"
        assert "technical" in term, f"Term {term_id} missing 'technical'"

        # Check simple definition length <= 25 words
        simple_words = term["simple"].split()
        assert len(simple_words) <= 25, (
            f"Term '{term_id}' simple explanation exceeds 25 words: {len(simple_words)} words -> '{term['simple']}'"
        )


def test_rules_have_plain_language_fields():
    """Ensure every rule in nist_default.yaml has plain_summary, plain_impact, plain_fix."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "analyzer", "rules", "policies", "nist_default.yaml"
    )
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    rules = policy.get("rules", [])
    assert len(rules) > 0, "No rules found in nist_default.yaml"

    for rule in rules:
        rule_id = rule.get("id")
        assert "plain_summary" in rule, f"Rule {rule_id} missing 'plain_summary'"
        assert "plain_impact" in rule, f"Rule {rule_id} missing 'plain_impact'"
        assert "plain_fix" in rule, f"Rule {rule_id} missing 'plain_fix'"

        # Verify average sentence length <= 20 words
        for field in ("plain_summary", "plain_impact", "plain_fix"):
            text = rule[field]
            assert text and len(text.strip()) > 0, f"Rule {rule_id} has empty {field}"
            readability = compute_plain_readability(text)
            assert readability["avg_sentence_words"] <= 20.0, (
                f"Rule {rule_id} {field} exceeds 20 words/sentence: {readability['avg_sentence_words']} in '{text}'"
            )


def test_report_card_generation_and_readability():
    """Verify deterministic 5-point report card has average sentence length <= 20 words."""
    card = generate_report_card(
        total_packets=500,
        ipsec_packets=450,
        ike_sessions=1,
        esp_flows=2,
        findings=[
            {"rule_id": "SEC-CRY-001", "severity": "High", "title": "Weak cipher 3DES used"}
        ],
        grade="C",
        score=65.0,
    )

    required_keys = ["what_we_saw", "what_we_found", "how_worried", "what_to_do_first", "limitations"]
    for key in required_keys:
        assert key in card, f"Report card missing '{key}'"
        text = card[key]
        readability = compute_plain_readability(text)
        assert readability["avg_sentence_words"] <= 20.0, (
            f"Report card '{key}' sentence too long: {readability['avg_sentence_words']} words/sentence -> '{text}'"
        )


def test_handshake_and_flow_story_readability():
    """Verify IKE handshake story and ESP flow stories are concise (<= 20 words/sentence)."""
    mock_session = {
        "version": 2,
        "initiator_ip": "10.0.0.1",
        "initiator_port": 500,
        "responder_ip": "10.0.0.2",
        "responder_port": 500,
        "outcome": "established",
        "proposals": [{"number": 1}],
        "selected": {
            "encryption": "AES-CBC",
            "prf": "HMAC-SHA256",
            "dh_group": 14,
        },
    }

    ike_story = generate_ike_story(mock_session)
    assert len(ike_story) >= 3, "Expected at least 3 story steps"
    for step in ike_story:
        readability = compute_plain_readability(step)
        assert readability["avg_sentence_words"] <= 20.0, (
            f"IKE story step too long: {readability['avg_sentence_words']} words -> '{step}'"
        )

    mock_flow = {
        "proto": "ESP",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "packets": 50,
        "seq": {"min_seq": 1, "max_seq": 50, "gaps": []},
    }
    esp_story = generate_esp_flow_story(mock_flow)
    assert len(esp_story) > 0
    readability = compute_plain_readability(esp_story)
    assert readability["avg_sentence_words"] <= 20.0, (
        f"ESP flow story too long: {readability['avg_sentence_words']} words -> '{esp_story}'"
    )


def test_glossary_api_endpoints():
    """Verify /api/v1/glossary and /api/v1/glossary/{id} return expected data."""
    req = urllib.request.Request(f"{API_BASE}/api/v1/glossary")
    with urllib.request.urlopen(req, timeout=5) as res:
        assert res.status == 200, f"Expected 200, got {res.status}"
        data = json.loads(res.read().decode())
        assert "items" in data
        assert data["total"] >= 70

    # Test single term
    req_term = urllib.request.Request(f"{API_BASE}/api/v1/glossary/ike")
    with urllib.request.urlopen(req_term, timeout=5) as res_term:
        assert res_term.status == 200
        term = json.loads(res_term.read().decode())
        assert term["id"] == "ike"
        assert "Internet Key Exchange" in term.get("expansion", "")


def test_technical_terms_in_glossary():
    """Verify that key technical terms present in the UI and reports exist in glossary."""
    glossary = load_glossary()
    required_terms = [
        "ipsec", "vpn", "ike", "ikev1", "ikev2", "esp", "ah", "natt",
        "sa", "spi", "dh", "pfs", "prf", "integrity", "aead", "aes_gcm",
        "3des", "des", "md5", "sha1", "sha2", "psk", "main_mode",
        "aggressive_mode", "nonce", "notify", "vendor_id", "cookie",
        "sequence_number", "replay", "anti_replay", "esp_null", "handshake",
        "initiator", "responder", "rekey", "tunnel_mode", "transport_mode",
        "fragmentation", "not_observable", "pcap", "pcapng", "packet",
        "flow", "session", "risk_score", "impact", "likelihood",
        "confidence", "severity", "posture_grade", "evidence", "heuristic",
        "false_positive", "fingerprint", "ecp", "modp", "certificate",
        "mitre_attck", "ioc",
    ]

    missing = [t for t in required_terms if t not in glossary]
    assert len(missing) == 0, f"Missing required terms in glossary.yaml: {missing}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
