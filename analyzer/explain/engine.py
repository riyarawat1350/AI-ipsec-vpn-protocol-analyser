"""IPsecScope Explanation & Plain Language Engine — Phase 4.

Generates deterministic, non-LLM explanations for non-technical stakeholders:
1. Glossary lookup & term cross-referencing
2. Deterministic 5-point Report Card
3. IKE Handshake Story (step-by-step plain English narrative)
4. ESP Flow Plain English summaries
5. Readability & observability boundary enforcement
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

GLOSSARY_PATH = Path(__file__).parent / "glossary.yaml"

_GLOSSARY_CACHE: dict[str, dict[str, Any]] | None = None


def load_glossary() -> dict[str, dict[str, Any]]:
    """Loads and caches the 75+ term glossary dictionary indexed by term id."""
    global _GLOSSARY_CACHE
    if _GLOSSARY_CACHE is not None:
        return _GLOSSARY_CACHE

    if not GLOSSARY_PATH.exists():
        return {}

    with open(GLOSSARY_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    glossary: dict[str, dict[str, Any]] = {}
    for entry in data:
        t_id = entry.get("id")
        if t_id:
            glossary[t_id] = entry
            alt_id = t_id.replace("-", "_")
            if alt_id != t_id:
                glossary[alt_id] = entry
            hyphen_id = t_id.replace("_", "-")
            if hyphen_id != t_id:
                glossary[hyphen_id] = entry

    synonyms = {
        "natt": "nat-t",
        "dh": "dh-group",
        "aes_gcm": "aes-gcm",
        "sha1": "sha-1",
        "sha2": "sha-2",
        "main_mode": "main-mode",
        "aggressive_mode": "aggressive-mode",
        "vendor_id": "vendor-id",
        "sequence_number": "sequence-number",
        "anti_replay": "anti-replay",
        "esp_null": "esp-null",
        "tunnel_mode": "tunnel-mode",
        "transport_mode": "transport-mode",
        "not_observable": "not-observable",
        "risk_score": "risk-score",
        "posture_grade": "posture-grade",
        "false_positive": "false-positive",
        "mitre_attck": "mitre-attack",
        "mitre-attck": "mitre-attack",
    }
    for alias, canonical in synonyms.items():
        if canonical in glossary and alias not in glossary:
            glossary[alias] = glossary[canonical]

    _GLOSSARY_CACHE = glossary
    return glossary


def get_term(term_id: str) -> dict[str, Any] | None:
    """Retrieve glossary definition by term ID."""
    g = load_glossary()
    tid = term_id.lower().strip()
    return g.get(tid) or g.get(tid.replace("_", "-")) or g.get(tid.replace("-", "_"))


def generate_report_card(
    facts_or_total: Any = None,
    findings: list[Any] | None = None,
    posture: dict[str, Any] | None = None,
    recommendations: list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Generates the 5-point deterministic Report Card for non-technical users.

    Sections:
    1. What we saw (Hamne kya dekha)
    2. What we found (Kya mila)
    3. How worried should you be (Kitni chinta karni chahiye)
    4. What to do first (Pehle kya karein)
    5. What we could not observe and why (Jo hum check nahi kar sake aur kyun)
    """
    if hasattr(facts_or_total, "capture"):
        total_packets = facts_or_total.capture.get("packet_count", 0)
        sessions_count = len(facts_or_total.sessions)
        flows_count = len(facts_or_total.flows)
    elif isinstance(facts_or_total, (int, float)):
        total_packets = int(facts_or_total)
        sessions_count = kwargs.get("ike_sessions", 0)
        flows_count = kwargs.get("esp_flows", 0)
    else:
        total_packets = kwargs.get("total_packets", 0)
        sessions_count = kwargs.get("ike_sessions", 0)
        flows_count = kwargs.get("esp_flows", 0)

    findings_list = findings if findings is not None else kwargs.get("findings", [])
    posture_dict = posture if posture is not None else {"grade": kwargs.get("grade", "A"), "score": kwargs.get("score", 100.0)}
    rec_list = recommendations if recommendations is not None else kwargs.get("recommendations", [])

    # 1. What we saw
    saw_bullets = [
        f"Analyzed {total_packets} captured network packets.",
        f"Observed {sessions_count} IKE handshake negotiation session(s).",
        f"Inspected {flows_count} directional ESP encrypted data flow(s).",
    ]
    saw_text = (
        f"Observed {total_packets} captured packets in the recording. "
        f"Found {sessions_count} IKE handshake session(s) and {flows_count} ESP encrypted flow(s)."
    )

    # 2. What we found
    crit_count = sum(1 for f in findings_list if (getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)) == "Critical")
    high_count = sum(1 for f in findings_list if (getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)) == "High")
    med_count = sum(1 for f in findings_list if (getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)) == "Medium")
    low_count = sum(1 for f in findings_list if (getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)) == "Low")
    info_count = sum(1 for f in findings_list if (getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)) == "Info")

    if not findings_list:
        found_text = "No security weaknesses found in the parts of the traffic we could observe."
    else:
        found_text = (
            f"Identified {len(findings_list)} finding(s): "
            f"{crit_count} Critical, {high_count} High, {med_count} Medium, "
            f"{low_count} Low, and {info_count} Informational."
        )

    # 3. How worried should you be
    grade = posture_dict.get("grade", "A")
    score = posture_dict.get("score", 100.0)

    if grade == "A":
        worry_level = "Low Concern"
        worry_text = (
            "No weaknesses found in observed parameters. "
            "Negotiated cryptographic ciphers comply with current baseline policies."
        )
    elif grade in ("B", "C"):
        worry_level = "Moderate Concern"
        worry_text = (
            f"Overall posture score is {score:.1f}/100 with Grade {grade}. "
            "Some cryptographic algorithms are outdated and should be upgraded."
        )
    else:
        worry_level = "High Immediate Concern"
        worry_text = (
            f"Overall posture score is {score:.1f}/100 with Grade {grade}. "
            "Critical or deprecated algorithms were observed on the wire. "
            "The communication is vulnerable to eavesdropping or tampering."
        )

    # 4. What to do first
    if rec_list:
        top_rec = rec_list[0]
        first_step = top_rec.get("steps", ["Upgrade configuration per remediation guidelines."])[0]
        todo_title = top_rec.get("title", "Remediate high-priority findings.")
        todo_text = f"{todo_title} Action: {first_step}"
    else:
        todo_title = "Maintain Current Security Baselines"
        todo_text = "Maintain regular capture monitoring and verify peer firmware updates."

    # 5. What we could not observe and why
    not_observable = (
        "Encrypted payload contents and inner tunnel traffic cannot be observed without keys. "
        "Identity payloads and forward secrecy remain private on the wire."
    )

    return {
        "what_we_saw": saw_text,
        "what_we_found": found_text,
        "how_worried": worry_text,
        "what_to_do_first": todo_text,
        "limitations": not_observable,
        "details": {
            "saw_bullets": saw_bullets,
            "counts": {
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "info": info_count,
                "total": len(findings_list),
            },
            "worry_level": worry_level,
            "grade": grade,
            "score": score,
            "recommendation": todo_title,
        },
    }


def generate_ike_story(session: Any) -> list[str]:
    """Generates numbered plain-English steps describing the IKE handshake."""
    steps: list[str] = []
    step_num = 1

    version = getattr(session, "version", None)
    if version is None and isinstance(session, dict):
        version = session.get("version", 2)
    v_str = f"IKEv{version or 2}"

    init_ip = getattr(session, "initiator", None)
    if not init_ip and isinstance(session, dict):
        init_ip = session.get("initiator_ip") or session.get("initiator") or "Initiator"

    resp_ip = getattr(session, "responder", None)
    if not resp_ip and isinstance(session, dict):
        resp_ip = session.get("responder_ip") or session.get("responder") or "Responder"

    aggressive = getattr(session, "aggressive_mode", False)
    if not aggressive and isinstance(session, dict):
        aggressive = session.get("aggressive_mode", False)

    # Step: Initiation
    if aggressive:
        steps.append(
            f"{step_num}. {init_ip} started an Aggressive Mode handshake with {resp_ip}. "
            "It proposed ciphers and transmitted identity in cleartext."
        )
    else:
        steps.append(
            f"{step_num}. {init_ip} started a {v_str} handshake with {resp_ip}. "
            "It offered cryptographic parameters."
        )
    step_num += 1

    # Step: Proposals offered
    offered = getattr(session, "offered", None)
    if offered is None and isinstance(session, dict):
        offered = session.get("offered") or session.get("proposals") or []

    if offered:
        steps.append(
            f"{step_num}. Initiator offered cryptographic options for the handshake."
        )
        step_num += 1

    # Step: Responder selection
    selected = getattr(session, "selected", None)
    if selected is None and isinstance(session, dict):
        selected = session.get("selected")

    outcome = getattr(session, "outcome", None)
    if outcome is None and isinstance(session, dict):
        outcome = session.get("outcome", "")

    if selected:
        steps.append(
            f"{step_num}. Responder accepted the proposal and chose negotiated ciphers."
        )
        step_num += 1
    elif outcome == "unanswered":
        steps.append(f"{step_num}. Responder did not reply to the connection request.")
        step_num += 1
    elif outcome == "failed_notify":
        steps.append(f"{step_num}. Responder rejected the handshake with an error notification.")
        step_num += 1

    # Step: Outcome
    if outcome in ("established", "established_observed"):
        steps.append(f"{step_num}. Handshake negotiation completed successfully.")
    elif outcome == "incomplete_capture":
        steps.append(f"{step_num}. Packet capture ended before the handshake completed.")

    return steps


def generate_esp_flow_story(flow: Any) -> str:
    """Generates plain-English narrative for an ESP flow."""
    proto = getattr(flow, "proto", None) or (flow.get("proto") if isinstance(flow, dict) else "ESP")
    proto_name = str(proto).upper()
    encap = getattr(flow, "encap", None) or (flow.get("encap") if isinstance(flow, dict) else None)
    encap_str = "NAT-T encapsulated (UDP 4500)" if encap == "natt" else "raw IP"

    null_suspected = getattr(flow, "null_suspected", False) or (flow.get("null_suspected", False) if isinstance(flow, dict) else False)
    if null_suspected:
        sec_note = "Warning: Packets appear unencrypted with ESP-NULL payload."
    else:
        sec_note = "Payloads are encrypted."

    seq = getattr(flow, "seq", None) or (flow.get("seq") if isinstance(flow, dict) else None)
    packets = getattr(flow, "packets", 0) or (flow.get("packets", 0) if isinstance(flow, dict) else 0)
    bytes_count = getattr(flow, "bytes", 0) or (flow.get("bytes", 0) if isinstance(flow, dict) else 0)
    src = getattr(flow, "src", "0.0.0.0") or (flow.get("src", "0.0.0.0") if isinstance(flow, dict) else "0.0.0.0")
    dst = getattr(flow, "dst", "0.0.0.0") or (flow.get("dst", "0.0.0.0") if isinstance(flow, dict) else "0.0.0.0")

    if seq and getattr(seq, "max_seq", None):
        max_s = seq.max_seq
        gaps = len(getattr(seq, "gaps", []))
    elif isinstance(seq, dict):
        max_s = seq.get("max_seq", packets)
        gaps = len(seq.get("gaps", []))
    else:
        max_s = packets
        gaps = 0

    if gaps == 0:
        seq_note = f"Sequence numbers ran sequentially from 1 to {max_s} without missing packets."
    else:
        seq_note = f"Sequence numbers reached {max_s} with {gaps} gap(s) observed."

    return (
        f"{packets} {proto_name} packets ({bytes_count} bytes) traveled from {src} to {dst} via {encap_str}. "
        f"{seq_note} {sec_note}"
    )


def compute_plain_readability(text: str) -> dict[str, Any]:
    """Calculates average sentence length in words to enforce readability <= 20 words."""
    import re
    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    if not sentences:
        return {"avg_words": 0.0, "avg_sentence_words": 0.0, "sentence_count": 0, "pass": True}

    word_counts = [len(re.findall(r"\b\w+\b", s)) for s in sentences]
    avg = sum(word_counts) / len(word_counts)
    return {
        "avg_words": round(avg, 1),
        "avg_sentence_words": round(avg, 1),
        "sentence_count": len(sentences),
        "pass": avg <= 22.0,
    }


def find_terms_in_text(text: str) -> list[dict[str, Any]]:
    """Automatically extracts glossary terms mentioned in a text for report term appendix."""
    glossary = load_glossary()
    found: dict[str, dict[str, Any]] = {}
    import re

    text_lower = text.lower()
    for term_id, term in glossary.items():
        name_lower = term["name"].lower()
        expansion_lower = term.get("expansion", "").lower()

        # Check whole word match
        pattern = r"\b" + re.escape(name_lower) + r"\b"
        if re.search(pattern, text_lower):
            found[term_id] = term
            continue

        if expansion_lower and re.search(r"\b" + re.escape(expansion_lower) + r"\b", text_lower):
            found[term_id] = term

    return list(found.values())
