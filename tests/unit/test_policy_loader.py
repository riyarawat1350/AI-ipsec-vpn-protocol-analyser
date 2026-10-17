"""Tests for Policy schema and loader — TASK-023."""

from __future__ import annotations

import pytest
from analyzer.rules.loader import (
    PolicyLoadError,
    compute_policy_hash,
    load_policy,
    load_policy_from_str,
)


def test_load_valid_policy() -> None:
    yaml_text = """
policy_id: "test_policy"
version: "1.0"
description: "A test policy"
tables:
  dh_impact:
    "1": 5
rules:
  - id: "CRY-TEST-001"
    target: "observation"
    category: "Crypto"
    title: "Test rule {name}"
    explanation: "Just testing"
    condition:
      field: "kind"
      op: "eq"
      value: "dh"
    impact:
      default: 3
    likelihood:
      fixed: 5
    confidence: 1.0
"""
    policy = load_policy_from_str(yaml_text)
    assert policy.policy_id == "test_policy"
    assert len(policy.rules) == 1
    assert policy.rules[0].id == "CRY-TEST-001"
    assert len(policy.policy_hash) == 64  # SHA-256 hex


def test_reject_insecure_python_tag() -> None:
    yaml_text = """
policy_id: "evil"
rules: !!python/object/apply:os.system ["calc.exe"]
"""
    with pytest.raises(PolicyLoadError, match="tag rejected|Insecure"):
        load_policy_from_str(yaml_text)


def test_reject_unknown_fields() -> None:
    yaml_text = """
policy_id: "test"
unknown_extra_field: "not allowed"
rules: []
"""
    with pytest.raises(PolicyLoadError, match="Extra inputs are not permitted"):
        load_policy_from_str(yaml_text)


def test_reject_malformed_yaml() -> None:
    yaml_text = """
policy_id: [broken yaml :::
"""
    with pytest.raises(PolicyLoadError, match="Invalid YAML syntax"):
        load_policy_from_str(yaml_text)


def test_load_default_policy() -> None:
    policy = load_policy("nist_default")
    assert policy.policy_id == "nist_default"
    assert len(policy.rules) >= 1
    assert "dh_impact" in policy.tables
    assert len(policy.policy_hash) == 64


def test_policy_hash_stability() -> None:
    d = {"policy_id": "test", "version": "1.0", "rules": []}
    h1 = compute_policy_hash(d)
    h2 = compute_policy_hash(d)
    assert h1 == h2
    assert len(h1) == 64
