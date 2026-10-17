"""Declarative rule engine — TASK-024.

SPEC §5.10:
- Evaluates policy rules against Observations, Sessions, and Flows.
- Resolves impact and likelihood dynamically from tables and roles.
- Safe string formatting without exceptions.
- Deduplication: merges offered and selected findings for same (session, kind, id),
  promoting to selected (likelihood 5).
- Groups findings and caps evidence at 5 items.
"""

from __future__ import annotations

from typing import Any
from analyzer.models import Evidence, Facts, IkeSession, IpsecFlow, Observation, RawFinding
from analyzer.rules.conditions import evaluate_condition, get_field_value
from analyzer.rules.schema import PolicyDef, RuleDef


class SafeDict(dict):
    """Fallback dict that returns empty string for missing format keys."""

    def __missing__(self, key: str) -> str:
        return ""


def resolve_impact(
    impact_def: Any,
    target_dict: dict[str, Any],
    tables: dict[str, dict[str, int]],
) -> int:
    """Resolve impact value (1-5) using tables, defaults, or fixed numbers."""
    if isinstance(impact_def, int):
        return max(1, min(5, impact_def))

    if isinstance(impact_def, dict):
        # Table lookup
        table_name = impact_def.get("table")
        if table_name and table_name in tables:
            tbl = tables[table_name]
            item_id = str(target_dict.get("id", ""))
            item_name = str(target_dict.get("name", ""))
            if item_id in tbl:
                return tbl[item_id]
            if item_name in tbl:
                return tbl[item_name]

        if "fixed" in impact_def and impact_def["fixed"] is not None:
            return max(1, min(5, int(impact_def["fixed"])))

        if "default" in impact_def and impact_def["default"] is not None:
            return max(1, min(5, int(impact_def["default"])))

    if hasattr(impact_def, "table") and impact_def.table and impact_def.table in tables:
        tbl = tables[impact_def.table]
        item_id = str(target_dict.get("id", ""))
        item_name = str(target_dict.get("name", ""))
        if item_id in tbl:
            return tbl[item_id]
        if item_name in tbl:
            return tbl[item_name]

    if hasattr(impact_def, "fixed") and impact_def.fixed is not None:
        return max(1, min(5, int(impact_def.fixed)))

    if hasattr(impact_def, "default") and impact_def.default is not None:
        return max(1, min(5, int(impact_def.default)))

    return 3


def resolve_likelihood(likelihood_def: Any, target_dict: dict[str, Any]) -> int:
    """Resolve likelihood (1-5). If from: role, selected=5, offered=3."""
    if isinstance(likelihood_def, int):
        return max(1, min(5, likelihood_def))

    from_role = None
    fixed_val = None
    if isinstance(likelihood_def, dict):
        from_role = likelihood_def.get("from") or likelihood_def.get("from_role")
        fixed_val = likelihood_def.get("fixed")
    elif hasattr(likelihood_def, "from_role"):
        from_role = likelihood_def.from_role
        fixed_val = likelihood_def.fixed

    if from_role == "role":
        role = target_dict.get("role", "offered")
        return 5 if role == "selected" else 3

    if fixed_val is not None:
        return max(1, min(5, int(fixed_val)))

    return 3


def _observation_to_evidence(obs: dict[str, Any]) -> Evidence:
    return Evidence(
        packet_no=obs.get("pkt_no", 1),
        ts=0.0,
        message=f"{obs.get('kind', '').upper()} {obs.get('name', '')} (id {obs.get('id', '')})",
        field_path=obs.get("field_path", ""),
        raw_value=obs.get("id"),
        decoded=obs.get("name"),
        hex_excerpt=obs.get("raw_hex", ""),
        note=f"Role: {obs.get('role')}, IKEv{obs.get('ike_version')}",
    )


def _session_to_evidence(sess: dict[str, Any]) -> Evidence:
    msgs = sess.get("messages", [])
    first_pkt = msgs[0].get("pkt_no", 1) if msgs else 1
    return Evidence(
        packet_no=first_pkt,
        ts=sess.get("first_ts", 0.0),
        message=f"IKEv{sess.get('version')} Session {sess.get('id')} outcome: {sess.get('outcome')}",
        field_path="session.outcome",
        raw_value=sess.get("outcome"),
        decoded=sess.get("id"),
        hex_excerpt="",
        note=f"Retransmissions: {sess.get('retransmissions')}",
    )


def _flow_to_evidence(flow: dict[str, Any]) -> Evidence:
    sample_pkts = flow.get("sample_pkt_nos", [])
    first_pkt = sample_pkts[0] if sample_pkts else 1
    return Evidence(
        packet_no=first_pkt,
        ts=flow.get("first_ts", 0.0),
        message=f"IPsec Flow {flow.get('proto', '').upper()} SPI {flow.get('spi')}",
        field_path="flow.seq",
        raw_value=flow.get("spi"),
        decoded=flow.get("id"),
        hex_excerpt="",
        note=f"Packets: {flow.get('packets')}, encap: {flow.get('encap')}",
    )


class RuleEngine:
    """Evaluates declarative policies against Facts."""

    def __init__(self, policy: PolicyDef) -> None:
        self.policy = policy

    def evaluate(self, facts: Facts) -> list[RawFinding]:
        """Evaluate policy rules and return consolidated RawFindings."""
        raw_matches: list[dict[str, Any]] = []

        # Target pools
        obs_dicts = [o.model_dump() for o in facts.observations]
        sess_dicts = [s.model_dump() for s in facts.sessions]
        flow_dicts = [f.model_dump() for f in facts.flows]

        # 1. Evaluate rules
        for rule in self.policy.rules:
            if rule.target == "observation":
                pool = obs_dicts
            elif rule.target == "session":
                pool = sess_dicts
            else:
                pool = flow_dicts

            for item in pool:
                if evaluate_condition(rule.condition, item):
                    impact = resolve_impact(rule.impact, item, self.policy.tables)
                    likelihood = resolve_likelihood(rule.likelihood, item)

                    fmt_dict = SafeDict(item)
                    if "initiator" in item and isinstance(item["initiator"], dict):
                        fmt_dict["initiator_ip"] = item["initiator"].get("ip", "")
                    if "responder" in item and isinstance(item["responder"], dict):
                        fmt_dict["responder_ip"] = item["responder"].get("ip", "")

                    title = rule.title.format_map(fmt_dict)
                    explanation = rule.explanation.format_map(fmt_dict)

                    # Build evidence
                    if rule.target == "observation":
                        ev = _observation_to_evidence(item)
                        sess_id = item.get("session_id", "")
                    elif rule.target == "session":
                        ev = _session_to_evidence(item)
                        sess_id = item.get("id", "")
                    else:
                        ev = _flow_to_evidence(item)
                        sess_id = item.get("linked_ike_session_id") or ""

                    raw_matches.append({
                        "rule": rule,
                        "item": item,
                        "impact": impact,
                        "likelihood": likelihood,
                        "title": title,
                        "explanation": explanation,
                        "evidence": ev,
                        "session_id": sess_id,
                    })

        # 2. Deduplicate offered vs selected (SPEC §5.10)
        # Key: (rule_id, session_id, kind, id)
        deduped_matches: dict[tuple, dict[str, Any]] = {}
        for m in raw_matches:
            item = m["item"]
            rule = m["rule"]
            if rule.target == "observation":
                dedupe_key = (
                    rule.id,
                    m["session_id"],
                    item.get("kind"),
                    item.get("id"),
                )
                role = item.get("role")
                if dedupe_key in deduped_matches:
                    existing = deduped_matches[dedupe_key]
                    existing_role = existing["item"].get("role")
                    if existing_role == "offered" and role == "selected":
                        # Promote to selected
                        m["additional_evidence"] = existing["evidence"]
                        deduped_matches[dedupe_key] = m
                    else:
                        existing["additional_evidence"] = m["evidence"]
                else:
                    deduped_matches[dedupe_key] = m
            else:
                generic_key = (rule.id, id(m))
                deduped_matches[generic_key] = m

        # 3. Group by group_by keys
        # Grouping key -> consolidated RawFinding
        grouped_findings: dict[tuple, RawFinding] = {}

        for m in deduped_matches.values():
            rule: RuleDef = m["rule"]
            item = m["item"]

            if rule.group_by:
                group_vals = [rule.id] + [str(get_field_value(item, k)) for k in rule.group_by]
                group_key = tuple(group_vals)
            else:
                group_key = (rule.id, m["session_id"], str(item.get("id", "")))

            ev_list = [m["evidence"]]
            if "additional_evidence" in m:
                ev_list.append(m["additional_evidence"])

            sess_list = [m["session_id"]] if m["session_id"] else []

            if group_key in grouped_findings:
                existing_f = grouped_findings[group_key]
                existing_f.count += 1
                for ev in ev_list:
                    if len(existing_f.evidence) < 5:
                        existing_f.evidence.append(ev)
                for s in sess_list:
                    if s not in existing_f.affected_sessions:
                        existing_f.affected_sessions.append(s)
                # Keep highest impact/likelihood
                if m["impact"] > existing_f.impact:
                    existing_f.impact = m["impact"]
                if m["likelihood"] > existing_f.likelihood:
                    existing_f.likelihood = m["likelihood"]
            else:
                grouped_findings[group_key] = RawFinding(
                    rule_id=rule.id,
                    origin="rule",
                    category=rule.category,
                    title=m["title"],
                    explanation=m["explanation"],
                    why_this_matters=rule.why_this_matters,
                    impact=m["impact"],
                    likelihood=m["likelihood"],
                    confidence=rule.confidence,
                    evidence=ev_list[:5],
                    affected_sessions=sess_list,
                    count=1,
                    references=list(rule.references),
                    mitre=list(rule.mitre),
                    recommendation_id=rule.recommendation_id,
                    params=dict(rule.params),
                    override_severity=rule.override_severity,
                )

        return list(grouped_findings.values())
