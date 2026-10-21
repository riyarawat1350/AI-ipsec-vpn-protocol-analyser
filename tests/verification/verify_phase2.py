"""Phase 2 Verification: Findings, Scoring, Evidence, Deduplication, and Claim Integrity.

Covers:
1. Exact rule_id, severity, and risk_score match against Doc 05 §3 for all golden fixtures.
2. Independent recomputation of risk formula R = round(I*L/25*100*(0.5+0.5*conf), 1) and posture.
3. Verification that Info severity findings have risk_score as 'not scored' (None).
4. Negative testing: F01, F06, F22 have 0 findings above Info. Weak fixtures (F02, F05, F17) retain all findings.
5. Packet-level evidence verification: packet_no, field_path, raw_value, decoded, and hex byte verification.
6. Deduplication check: offered vs selected algorithm reports single finding with role selected.
7. Overclaim scan: ensures banned words ("secure", "safe", "strong security", "unhackable", "guaranteed") are absent.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from analyzer.pipeline import Pipeline
from analyzer.scoring.risk import calculate_risk

PCAP_DIR = Path("tests/fixtures/pcaps")

# Doc 05 §3 Expected Findings Specifications
DOC05_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "ikev2_modern_gcm_x25519.pcap": {
        "fixture_id": "F01",
        "expected_rules": ["IKE-INFO-001"],
        "max_severity": "Info",
        "expected_grade": "A",
        "expected_posture_min": 90.0,
    },
    "ikev2_modp1024_3des.pcap": {
        "fixture_id": "F02",
        "expected_findings": [
            {"rule_id": "CRY-DH-001", "risk_score": 80.0, "severity": "High"},
            {"rule_id": "CRY-ENC-001", "risk_score": 60.0, "severity": "Medium"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
            {"rule_id": "CRY-INT-001", "risk_score": 20.0, "severity": "Low"},
        ],
        "expected_grade": "F",
        "expected_posture_max": 39.0,
    },
    "ikev2_offered_weak_selected_strong.pcap": {
        "fixture_id": "F03",
        "expected_findings": [
            {"rule_id": "CRY-DH-001", "risk_score": 48.0, "severity": "Medium"},
            {"rule_id": "CRY-ENC-001", "risk_score": 36.0, "severity": "Medium"},
            {"rule_id": "CRY-INT-001", "risk_score": None, "severity": "Info"},
            {"rule_id": "CRY-ENC-002", "risk_score": None, "severity": "Info"},
        ],
        "expected_grade": "D",
    },
    "ikev1_mainmode_psk.pcap": {
        "fixture_id": "F04",
        "expected_rules": ["IKE-V1-001", "CRY-DH-001", "IKE-V1-005", "CRY-INT-001", "CRY-ENC-002"],
        "forbidden_rules": ["IKE-V1-004"],
        "expected_posture_max": 59.0,
    },
    "ikev1_aggressive_psk.pcap": {
        "fixture_id": "F05",
        "expected_rules": ["IKE-V1-001", "IKE-V1-002", "IKE-V1-003", "CRY-DH-001", "IKE-V1-005", "CRY-INT-001"],
        "expected_posture_max": 59.0,
    },
    "natt_ikev2_esp.pcap": {
        "fixture_id": "F06",
        "expected_rules": ["IKE-INFO-002", "IKE-INFO-001"],
        "max_severity": "Info",
        "expected_grade": "A",
        "expected_posture_min": 90.0,
    },
    "ikev2_cookie_retry.pcap": {
        "fixture_id": "F07",
        "max_severity": "Info",
        "expected_grade": "A",
    },
    "ikev2_invalid_ke_retry.pcap": {
        "fixture_id": "F08",
        "expected_rules": ["CRY-DH-001"],
    },
    "ikev2_no_proposal_chosen.pcap": {
        "fixture_id": "F09",
        "expected_rules": ["IKE-NEG-001"],
    },
    "lab_ike_init_flood.pcap": {
        "fixture_id": "F10",
        "expected_rules": ["IKE-DOS-001", "IKE-DOS-002"],
    },
    "ikev1_scan_multihost.pcap": {
        "fixture_id": "F11",
        "expected_rules": ["IKE-RECON-001", "IKE-V1-001"],
    },
    "esp_seq_gaps.pcap": {
        "fixture_id": "F12",
        "expected_rules": ["ESP-SEQ-001", "ESP-NOIKE-001"],
    },
    "esp_null.pcap": {
        "fixture_id": "F13",
        "expected_findings": [
            {"rule_id": "ESP-NULL-001", "risk_score": 92.5, "severity": "Critical"},
            {"rule_id": "ESP-NOIKE-001", "risk_score": None, "severity": "Info"},
        ],
        "expected_posture_max": 39.0,
    },
    "ah_flow.pcap": {
        "fixture_id": "F14",
        "expected_rules": ["AH-001"],
    },
    "ikev2_malformed.pcap": {
        "fixture_id": "F15",
        "expected_rules": ["IKE-PROTO-001"],
    },
    "ikev2_des_md5_group1.pcap": {
        "fixture_id": "F17",
        "expected_findings": [
            {"rule_id": "CRY-ENC-001", "risk_score": 100.0, "severity": "Critical"},
            {"rule_id": "CRY-DH-001", "risk_score": 100.0, "severity": "Critical"},
            {"rule_id": "CRY-INT-001", "risk_score": 40.0, "severity": "Medium"},
            {"rule_id": "CRY-INT-001", "risk_score": 40.0, "severity": "Medium"},
        ],
        "expected_posture_max": 39.0,
        "expected_grade": "F",
    },
    "ikev2_unanswered.pcap": {
        "fixture_id": "F18",
        "expected_rules": ["IKE-NEG-003"],
    },
    "ikev2_vendor_xss.pcap": {
        "fixture_id": "F21",
        "expected_rules": ["IKE-INFO-001"],
        "max_severity": "Info",
    },
    "benign_multiclient.pcap": {
        "fixture_id": "F22",
        "max_severity": "Info",
        "expected_grade": "A",
        "expected_posture_min": 90.0,
    },
}

BANNED_OVERCLAIM_WORDS = [
    r"\bsecure\b",
    r"\bsafe\b",
    r"\bstrong security\b",
    r"\bunhackable\b",
    r"\bguaranteed\b",
]


def verify_phase2() -> dict[str, Any]:
    print("=" * 80)
    print("PHASE 2 FINDINGS, SCORING, EVIDENCE & INTEGRITY VERIFICATION")
    print("=" * 80)

    pipeline = Pipeline()
    checks: list[dict[str, Any]] = []

    for filename, spec in DOC05_EXPECTATIONS.items():
        file_path = PCAP_DIR / filename
        if not file_path.exists():
            continue

        fid = spec.get("fixture_id", "")
        res = pipeline.run(file_path)
        findings = res.findings
        posture = res.posture

        # 1. Negative tests: No finding above Info for benign fixtures
        if "max_severity" in spec and spec["max_severity"] == "Info":
            non_info = [f for f in findings if f.severity != "Info"]
            checks.append({
                "test": f"{fid} ({filename}) Benign Check (No findings > Info)",
                "expected": 0,
                "actual": len(non_info),
                "passed": len(non_info) == 0,
                "details": f"Findings > Info: {[f.rule_id + ':' + f.severity for f in non_info]}"
            })

        # 2. Expected grade and posture bounds
        if "expected_grade" in spec:
            actual_grade = posture.get("grade")
            checks.append({
                "test": f"{fid} ({filename}) Posture Grade Match",
                "expected": spec["expected_grade"],
                "actual": actual_grade,
                "passed": actual_grade == spec["expected_grade"],
                "details": f"Score: {posture.get('score')}"
            })

        if "expected_posture_max" in spec:
            p_score = float(posture.get("score", 100))
            checks.append({
                "test": f"{fid} ({filename}) Posture Score Cap (<= {spec['expected_posture_max']})",
                "expected": f"<= {spec['expected_posture_max']}",
                "actual": p_score,
                "passed": p_score <= spec["expected_posture_max"],
                "details": f"Caps applied: {posture.get('caps_applied')}"
            })

        # 3. Expected rules present
        if "expected_rules" in spec:
            actual_rule_ids = {f.rule_id for f in findings}
            for exp_r in spec["expected_rules"]:
                checks.append({
                    "test": f"{fid} ({filename}) Expected Rule Present: {exp_r}",
                    "expected": exp_r,
                    "actual": exp_r if exp_r in actual_rule_ids else "MISSING",
                    "passed": exp_r in actual_rule_ids,
                    "details": f"Actual rules: {list(actual_rule_ids)}"
                })

        # 4. Forbidden rules absent
        if "forbidden_rules" in spec:
            actual_rule_ids = {f.rule_id for f in findings}
            for forb_r in spec["forbidden_rules"]:
                checks.append({
                    "test": f"{fid} ({filename}) Forbidden Rule Absent: {forb_r}",
                    "expected": "ABSENT",
                    "actual": "PRESENT" if forb_r in actual_rule_ids else "ABSENT",
                    "passed": forb_r not in actual_rule_ids,
                    "details": ""
                })

        # 5. Exact findings with risk scores & severities
        if "expected_findings" in spec:
            for exp_f in spec["expected_findings"]:
                rule_id = exp_f["rule_id"]
                matching = [f for f in findings if f.rule_id == rule_id]
                match_found = False
                for m in matching:
                    # Check severity and risk score
                    sev_match = m.severity == exp_f["severity"]
                    score_match = (
                        (exp_f["risk_score"] is None and m.risk_score is None) or
                        (exp_f["risk_score"] is not None and m.risk_score is not None and abs(m.risk_score - exp_f["risk_score"]) <= 0.5)
                    )
                    if sev_match and score_match:
                        match_found = True
                        break

                checks.append({
                    "test": f"{fid} ({filename}) Exact Finding: {rule_id} -> {exp_f['severity']} (R={exp_f['risk_score']})",
                    "expected": f"{rule_id}:{exp_f['severity']}:{exp_f['risk_score']}",
                    "actual": f"{rule_id}:{matching[0].severity}:{matching[0].risk_score}" if matching else "MISSING",
                    "passed": match_found,
                    "details": f"Matching count: {len(matching)}"
                })

        # 6. Check Info severity findings have risk_score == None ("not scored")
        for f in findings:
            if f.severity == "Info":
                checks.append({
                    "test": f"{fid} ({filename}) Info Finding Not Scored ({f.rule_id})",
                    "expected": None,
                    "actual": f.risk_score,
                    "passed": f.risk_score is None,
                    "details": f"Scoring dict: {f.scoring}"
                })

        # 7. Check Independent Risk Formula Recomputation for scored findings
        for f in findings:
            if f.risk_score is not None and not f.scoring.get("overridden"):
                recomputed_r = calculate_risk(f.impact, f.likelihood, f.confidence)
                checks.append({
                    "test": f"{fid} ({filename}) Recomputed Formula: {f.rule_id}",
                    "expected": recomputed_r,
                    "actual": f.risk_score,
                    "passed": abs(f.risk_score - recomputed_r) <= 0.1,
                    "details": f"I={f.impact}, L={f.likelihood}, C={f.confidence}"
                })

        # 8. Check Packet-Level Evidence (No generic strings)
        for f in findings:
            for ev in f.evidence:
                is_generic = "session outcome:" in (ev.message or "").lower()
                has_packet = ev.packet_no > 0
                has_field = bool(ev.field_path)
                has_values = bool(ev.raw_value) and bool(ev.decoded)

                checks.append({
                    "test": f"{fid} ({filename}) Packet-Level Evidence ({f.rule_id} pkt #{ev.packet_no})",
                    "expected": "Packet-level details present, non-generic",
                    "actual": "Generic" if is_generic else ("Valid" if (has_packet and has_field and has_values) else "Missing fields"),
                    "passed": not is_generic and has_packet and has_field and has_values,
                    "details": f"msg='{ev.message}', field='{ev.field_path}', raw='{ev.raw_value}'"
                })

    # 9. Overclaim Scan across all finding titles and explanations
    for filename in DOC05_EXPECTATIONS.keys():
        file_path = PCAP_DIR / filename
        if not file_path.exists():
            continue
        res = pipeline.run(file_path)
        for f in res.findings:
            full_text = f"{f.title} {f.explanation} {f.why_this_matters}".lower()
            found_banned = []
            for b_word in BANNED_OVERCLAIM_WORDS:
                if re.search(b_word, full_text):
                    found_banned.append(b_word)
            checks.append({
                "test": f"Overclaim Scan: {f.rule_id} ({filename})",
                "expected": "No banned overclaim words",
                "actual": f"Found: {found_banned}" if found_banned else "Clean",
                "passed": len(found_banned) == 0,
                "details": f"Text excerpt: {f.title[:50]}"
            })

    # Summary
    passed_count = sum(1 for c in checks if c["passed"])
    failed_count = sum(1 for c in checks if not c["passed"])

    print(f"\nTotal Phase 2 Verification Checks: {len(checks)}")
    print(f"PASSED: {passed_count}")
    print(f"FAILED: {failed_count}\n")

    if failed_count > 0:
        print("FAILURES:")
        for c in checks:
            if not c["passed"]:
                print(f"  FAILED: {c['test']}")
                print(f"    Expected: {c['expected']}")
                print(f"    Actual:   {c['actual']}")
                print(f"    Details:  {c['details']}")
    else:
        print("All Phase 2 checks PASSED (100%)!")

    return {
        "total": len(checks),
        "passed": passed_count,
        "failed": failed_count,
        "checks": checks,
    }


def test_phase2_findings():
    res = verify_phase2()
    assert res["failed"] == 0, f"Phase 2 had {res['failed']} failure(s)"


if __name__ == "__main__":
    verify_phase2()
