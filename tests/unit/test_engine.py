"""Tests for Condition evaluator and Declarative Rule Engine — TASK-024."""

from __future__ import annotations

import pytest
from analyzer.models import Facts, IkeProposal, IkeSession, IkeTransform, Observation
from analyzer.features.facts import build_observations_from_sessions
from analyzer.rules.conditions import evaluate_condition, get_field_value
from analyzer.rules.engine import RuleEngine
from analyzer.rules.loader import load_policy_from_str


def test_condition_operators() -> None:
    data = {
        "kind": "dh",
        "id": 2,
        "name": "MODP-1024",
        "key_len": 128,
        "nested": {"val": 42},
        "tags": ["weak", "legacy"],
    }

    # eq / ne
    assert evaluate_condition({"field": "kind", "op": "eq", "value": "dh"}, data) is True
    assert evaluate_condition({"field": "kind", "op": "eq", "value": "encr"}, data) is False
    assert evaluate_condition({"field": "kind", "op": "ne", "value": "encr"}, data) is True

    # in / not_in
    assert evaluate_condition({"field": "id", "op": "in", "value": [1, 2, 5]}, data) is True
    assert evaluate_condition({"field": "id", "op": "in", "value": [14, 19]}, data) is False
    assert evaluate_condition({"field": "id", "op": "not_in", "value": [14, 19]}, data) is True

    # gt, gte, lt, lte
    assert evaluate_condition({"field": "key_len", "op": "gt", "value": 100}, data) is True
    assert evaluate_condition({"field": "key_len", "op": "gte", "value": 128}, data) is True
    assert evaluate_condition({"field": "key_len", "op": "lt", "value": 200}, data) is True
    assert evaluate_condition({"field": "key_len", "op": "lte", "value": 128}, data) is True

    # exists
    assert evaluate_condition({"field": "nested.val", "op": "exists", "value": True}, data) is True
    assert evaluate_condition({"field": "missing_key", "op": "exists", "value": True}, data) is False

    # contains
    assert evaluate_condition({"field": "tags", "op": "contains", "value": "weak"}, data) is True
    assert evaluate_condition({"field": "tags", "op": "contains", "value": "strong"}, data) is False

    # missing fields never raise
    assert evaluate_condition({"field": "nonexistent.field", "op": "eq", "value": "x"}, data) is False


def test_condition_combinators() -> None:
    data = {"kind": "dh", "id": 2}

    # all
    c_all = {
        "all": [
            {"field": "kind", "op": "eq", "value": "dh"},
            {"field": "id", "op": "eq", "value": 2},
        ]
    }
    assert evaluate_condition(c_all, data) is True

    # any
    c_any = {
        "any": [
            {"field": "kind", "op": "eq", "value": "encr"},
            {"field": "id", "op": "eq", "value": 2},
        ]
    }
    assert evaluate_condition(c_any, data) is True

    # not
    c_not = {"not": {"field": "kind", "op": "eq", "value": "encr"}}
    assert evaluate_condition(c_not, data) is True


def test_deduplication_offered_vs_selected() -> None:
    """If same (session_id, kind, id) appears in offered and selected, emit 1 selected finding."""
    policy_yaml = """
policy_id: "test"
tables:
  dh_impact:
    "2": 4
rules:
  - id: "CRY-DH-001"
    target: "observation"
    category: "Crypto"
    title: "Weak DH {name} (group {id})"
    explanation: "Group {id} is weak"
    condition:
      all:
        - field: "kind"
          op: "eq"
          value: "dh"
        - field: "id"
          op: "eq"
          value: 2
    impact:
      table: "dh_impact"
      default: 3
    likelihood:
      from: "role"
    confidence: 1.0
    group_by: ["session_id", "kind", "id"]
"""
    policy = load_policy_from_str(policy_yaml)
    engine = RuleEngine(policy)

    # Session with DH 2 offered and DH 2 selected
    t_dh = IkeTransform(kind="DH", id=2, name="MODP-1024")
    prop = IkeProposal(num=1, protocol="IKE", transforms=[t_dh])
    session = IkeSession(
        id="sess1",
        version=2,
        spi_i="11111111",
        spi_r="22222222",
        initiator={"ip": "10.0.0.1", "port": 500},  # type: ignore[arg-type]
        responder={"ip": "10.0.0.2", "port": 500},  # type: ignore[arg-type]
        natt=False,
        first_ts=1.0,
        last_ts=2.0,
        offered=[prop],
        selected=prop,
        outcome="established_observed",
    )

    observations = build_observations_from_sessions([session])
    facts = Facts(
        capture={},
        protocol_stats={},
        sessions=[session],
        observations=observations,
        flows=[],
    )

    findings = engine.evaluate(facts)
    # Exactly one finding emitted
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CRY-DH-001"
    assert f.impact == 4
    assert f.likelihood == 5  # Promoted to selected!
    # Both offered and selected evidence attached
    assert len(f.evidence) == 2


def test_evidence_cap_at_five() -> None:
    policy_yaml = """
policy_id: "test"
rules:
  - id: "TEST-001"
    target: "observation"
    category: "Test"
    title: "Rule"
    explanation: "Rule"
    condition:
      field: "kind"
      op: "eq"
      value: "encr"
    impact: 3
    likelihood: 3
    group_by: ["kind"]
"""
    policy = load_policy_from_str(policy_yaml)
    engine = RuleEngine(policy)

    # 10 observations of same kind
    obs_list = [
        Observation(
            session_id=f"s{i}",
            kind="encr",
            id=12,
            name="AES-CBC",
            role="offered",
            pkt_no=i,
            field_path="",
            raw_hex="",
            ike_version=2,
        )
        for i in range(10)
    ]
    facts = Facts(capture={}, protocol_stats={}, sessions=[], observations=obs_list, flows=[])
    findings = engine.evaluate(facts)

    assert len(findings) == 1
    assert findings[0].count == 10
    assert len(findings[0].evidence) == 5  # Capped at 5
