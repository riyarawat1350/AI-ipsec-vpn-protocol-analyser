"""Policy loader with safe YAML parsing and hash computation — TASK-023.

FR-44, NFR-08:
- Uses yaml.safe_load ONLY (rejects arbitrary Python objects / tags).
- Rejects invalid YAML, missing fields, unknown fields.
- Calculates deterministic SHA-256 hash of policy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import yaml
from pydantic import ValidationError

from analyzer.rules.schema import PolicyDef

DEFAULT_POLICIES_DIR = Path(__file__).parent / "policies"
ROOT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "policies"


class PolicyLoadError(Exception):
    """Raised when policy YAML cannot be loaded or validated."""


def compute_policy_hash(policy_dict: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of a policy dictionary."""
    # Exclude policy_hash itself if present
    d = {k: v for k, v in policy_dict.items() if k != "policy_hash"}
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy_from_str(yaml_content: str) -> PolicyDef:
    """Parse and validate policy from YAML string.

    Never uses unsafe loader.
    """
    if "!!python" in yaml_content:
        raise PolicyLoadError("Insecure YAML: !!python tag rejected")

    try:
        raw = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyLoadError("Policy root must be a YAML dictionary")

    # Compute stable hash
    h = compute_policy_hash(raw)

    try:
        policy = PolicyDef.model_validate(raw)
    except ValidationError as exc:
        raise PolicyLoadError(f"Policy validation failed: {exc}") from exc

    policy.policy_hash = h
    return policy


def load_policy_from_file(file_path: Path | str) -> PolicyDef:
    """Load policy from a YAML file path."""
    p = Path(file_path)
    if not p.exists():
        raise PolicyLoadError(f"Policy file not found: {p}")
    content = p.read_text(encoding="utf-8")
    return load_policy_from_str(content)


def load_policy(policy_id: str = "nist_default") -> PolicyDef:
    """Find and load policy by ID from policy directories."""
    # Try analyzer/rules/policies first, then root policies/
    candidate1 = DEFAULT_POLICIES_DIR / f"{policy_id}.yaml"
    candidate2 = ROOT_POLICIES_DIR / f"{policy_id}.yaml"

    if candidate1.exists():
        return load_policy_from_file(candidate1)
    if candidate2.exists():
        return load_policy_from_file(candidate2)

    raise PolicyLoadError(f"Unknown policy '{policy_id}'. Searched {candidate1} and {candidate2}")
