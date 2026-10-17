"""Condition evaluator for declarative security policies — TASK-024.

Grammar:
cond := {all: [cond...]} | {any: [cond...]} | {not: cond} | {field: str, op: str, value: any}
ops: eq, ne, in, not_in, gt, gte, lt, lte, exists, contains

Never raises on missing fields, incompatible types, or malformed conditions.
"""

from __future__ import annotations

from typing import Any


def get_field_value(target: dict[str, Any], field_path: str) -> Any:
    """Retrieve value from a nested dictionary using a dotted field path."""
    current: Any = target
    for part in field_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return None
        if current is None:
            return None
    return current


def evaluate_condition(cond: dict[str, Any], target: dict[str, Any]) -> bool:
    """Evaluate a condition against a target dictionary.

    Returns False if any field is missing or comparison fails. Never raises.
    """
    if not isinstance(cond, dict) or not cond:
        return False

    try:
        # Boolean combinators
        if "all" in cond:
            sub_conds = cond["all"]
            if not isinstance(sub_conds, list) or not sub_conds:
                return False
            return all(evaluate_condition(sub, target) for sub in sub_conds)

        if "any" in cond:
            sub_conds = cond["any"]
            if not isinstance(sub_conds, list) or not sub_conds:
                return False
            return any(evaluate_condition(sub, target) for sub in sub_conds)

        if "not" in cond:
            sub_cond = cond["not"]
            return not evaluate_condition(sub_cond, target)

        # Field comparison
        field_path = cond.get("field")
        op = cond.get("op")
        expected = cond.get("value")

        if not field_path or not op:
            return False

        actual = get_field_value(target, field_path)

        if op == "exists":
            return (actual is not None) if expected else (actual is None)

        if actual is None:
            return False

        if op == "eq":
            # Compare str to str or int to int; convert string numbers if needed
            if isinstance(actual, int) and isinstance(expected, str) and expected.isdigit():
                return actual == int(expected)
            if isinstance(actual, str) and isinstance(expected, int):
                return actual == str(expected)
            return actual == expected

        if op == "ne":
            return actual != expected

        if op == "in":
            if isinstance(expected, (list, tuple, set)):
                # Handle int/str mismatch in collections
                if actual in expected:
                    return True
                if isinstance(actual, int) and str(actual) in expected:
                    return True
                if isinstance(actual, str) and actual.isdigit() and int(actual) in expected:
                    return True
                return False
            return False

        if op == "not_in":
            if isinstance(expected, (list, tuple, set)):
                return actual not in expected
            return True

        if op == "gt":
            return float(actual) > float(expected)

        if op == "gte":
            return float(actual) >= float(expected)

        if op == "lt":
            return float(actual) < float(expected)

        if op == "lte":
            return float(actual) <= float(expected)

        if op == "contains":
            if isinstance(actual, (list, tuple, set, str)):
                return expected in actual
            return False

        return False

    except (ValueError, TypeError, KeyError):
        return False
