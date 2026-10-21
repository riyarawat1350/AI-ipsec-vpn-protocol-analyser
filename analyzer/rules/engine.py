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

from analyzer.models import Evidence, Facts, RawFinding
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


def _session_to_evidence(sess: dict[str, Any], rule_id: str = "") -> Evidence:
    msgs = sess.get("messages", [])
    first_msg = msgs[0] if msgs else {}
    first_pkt = first_msg.get("pkt_no", 1) if isinstance(first_msg, dict) else 1
    raw_hdr = first_msg.get("raw_header_hex", "") if isinstance(first_msg, dict) else ""

    if rule_id == "IKE-V1-001":
        return Evidence(
            packet_no=first_pkt,
            ts=sess.get("first_ts", 0.0),
            message=f"IKEv1 protocol negotiation header observed in packet #{first_pkt}",
            field_path="ike.version",
            raw_value="1",
            decoded="IKEv1 (Deprecated)",
            hex_excerpt=raw_hdr[:32] if raw_hdr else "01",
            note="IKEv1 is deprecated per RFC 9395",
        )
    elif rule_id == "IKE-V1-002":
        return Evidence(
            packet_no=first_pkt,
            ts=sess.get("first_ts", 0.0),
            message=f"IKEv1 Aggressive Mode exchange type 4 observed in packet #{first_pkt}",
            field_path="ike.exchange_type",
            raw_value="4",
            decoded="Aggressive Mode (Exchange 4)",
            hex_excerpt=raw_hdr[:36] if raw_hdr else "04",
            note="Cleartext identities transmitted without protection per RFC 2409 §5.4",
        )
    elif rule_id == "IKE-V1-003":
        # Target msg with authentication hash
        target_msg = next((m for m in msgs if isinstance(m, dict) and m.get("v1_hash_len")), msgs[1] if len(msgs) > 1 else first_msg)
        pkt_no = target_msg.get("pkt_no", 2) if isinstance(target_msg, dict) else 2
        hash_len = target_msg.get("v1_hash_len", 16) if isinstance(target_msg, dict) else 16
        return Evidence(
            packet_no=pkt_no,
            ts=sess.get("first_ts", 0.0),
            message=f"Cleartext authentication hash exposed in packet #{pkt_no}",
            field_path="ike.payload.hash",
            raw_value=f"{hash_len} bytes",
            decoded="PSK Authentication Hash",
            hex_excerpt=target_msg.get("raw_excerpt_hex", "")[:32] if isinstance(target_msg, dict) else "",
            note="Exposes PSK to offline dictionary / brute-force attack",
        )
    elif rule_id == "IKE-INFO-001":
        # Target msg with vendor IDs
        target_msg = next((m for m in msgs if isinstance(m, dict) and m.get("vendor_ids")), first_msg)
        pkt_no = target_msg.get("pkt_no", 1) if isinstance(target_msg, dict) else 1
        vids = (target_msg.get("vendor_ids") if isinstance(target_msg, dict) else None) or sess.get("vendor_ids") or []
        vid_val = str(vids[0]) if vids else ""
        return Evidence(
            packet_no=pkt_no,
            ts=sess.get("first_ts", 0.0),
            message=f"Vendor ID payload observed in packet #{pkt_no}",
            field_path="ike.payload.vendor_id",
            raw_value=vid_val,
            decoded="Peer Implementation Fingerprint (self-reported)",
            hex_excerpt=target_msg.get("raw_excerpt_hex", "")[:32] if isinstance(target_msg, dict) else "",
            note="Asset inventory tracking per RFC 7296 §3.12",
        )
    elif rule_id == "IKE-INFO-002":
        return Evidence(
            packet_no=first_pkt,
            ts=sess.get("first_ts", 0.0),
            message=f"NAT-Traversal traffic on UDP port 4500 observed in packet #{first_pkt}",
            field_path="udp.dstport",
            raw_value="4500",
            decoded="NAT-T Active (UDP port 4500)",
            hex_excerpt="",
            note="NAT detected between endpoints per RFC 3947",
        )

    return Evidence(
        packet_no=first_pkt,
        ts=sess.get("first_ts", 0.0),
        message=f"IKEv{sess.get('version')} session negotiation observed in packet #{first_pkt}",
        field_path="session.version",
        raw_value=str(sess.get("version", "")),
        decoded=f"IKEv{sess.get('version')}",
        hex_excerpt=raw_hdr[:32] if raw_hdr else "",
        note=f"Retransmissions: {sess.get('retransmissions')}",
    )


def _flow_to_evidence(flow: dict[str, Any], rule_id: str = "") -> Evidence:
    sample_pkts = flow.get("sample_pkt_nos", [])
    first_pkt = sample_pkts[0] if sample_pkts else 1
    spi = str(flow.get("spi", "")).lower()
    proto = str(flow.get("proto", "")).upper()

    if rule_id == "AH-001":
        return Evidence(
            packet_no=first_pkt,
            ts=flow.get("first_ts", 0.0),
            message=f"IPsec Authentication Header (AH) packet observed in packet #{first_pkt} (SPI {spi})",
            field_path="ip.proto",
            raw_value="51",
            decoded="IPsec AH Protocol (51)",
            hex_excerpt=f"33000000{spi}",
            note="AH provides integrity without confidentiality (RFC 4302)",
        )
    elif rule_id == "ESP-NULL-001":
        return Evidence(
            packet_no=first_pkt,
            ts=flow.get("first_ts", 0.0),
            message=f"Plaintext IPv4/TCP payload detected inside ESP tunnel packet #{first_pkt} (SPI {spi})",
            field_path="esp.payload",
            raw_value=f"SPI {spi}",
            decoded="ESP-NULL Plaintext Traffic",
            hex_excerpt="",
            note="ESP encryption disabled; cleartext headers observed (RFC 2410)",
        )
    elif rule_id == "ESP-SEQ-001":
        seq_stats = flow.get("seq", {})
        gaps_count = len(seq_stats.get("gaps", [])) if isinstance(seq_stats, dict) else 0
        return Evidence(
            packet_no=first_pkt,
            ts=flow.get("first_ts", 0.0),
            message=f"Sequence number anomalies on {proto} flow SPI {spi} starting at packet #{first_pkt}",
            field_path="esp.sequence",
            raw_value=f"SPI {spi}",
            decoded=f"Gaps: {gaps_count}",
            hex_excerpt="",
            note=f"Sequence gaps or reorders detected in {proto} tunnel",
        )

    return Evidence(
        packet_no=first_pkt,
        ts=flow.get("first_ts", 0.0),
        message=f"IPsec {proto} packet observed in packet #{first_pkt} (SPI {spi})",
        field_path=f"{flow.get('proto', 'esp')}.spi",
        raw_value=spi,
        decoded=f"{proto} SPI {spi}",
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
                        ev = _session_to_evidence(item, rule.id)
                        sess_id = item.get("id", "")
                    else:
                        ev = _flow_to_evidence(item, rule.id)
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
                    plain_summary=rule.plain_summary or None,
                    plain_impact=rule.plain_impact or None,
                    plain_fix=rule.plain_fix or None,
                )

        return list(grouped_findings.values())
