"""Task 4/5: Upload fixture PCAPs via API, poll, and print sanitized findings."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, cast
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
PCAP_DIR = Path("tests/fixtures/pcap")


def upload_and_poll(
    pcap_path: Path, label: str, timeout_s: int = 120
) -> tuple[str | None, dict[str, Any] | None]:
    """Upload a PCAP, poll until done, return (analysis_id, status_data)."""
    with open(pcap_path, "rb") as f:
        data = f.read()

    boundary = "----IPsecScopeTestBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{pcap_path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        BASE + "/api/v1/analyses",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            resp_data: dict[str, Any] = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        print(f"[{label}] POST error HTTP {e.code}: {err_body[:500]}")
        return None, None

    analysis_id: str | None = resp_data.get("analysis_id") or resp_data.get("id")
    print(f"[{label}] POST -> analysis_id={analysis_id}")
    if not analysis_id:
        return None, None

    # Poll
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        time.sleep(3)
        try:
            with urllib.request.urlopen(BASE + f"/api/v1/analyses/{analysis_id}") as r:
                status_data: dict[str, Any] = json.loads(r.read().decode())
        except Exception as poll_err:
            print(f"  [{attempt}] poll error: {poll_err}")
            continue
        status = str(status_data.get("status", "unknown"))
        progress = str(status_data.get("progress", ""))
        print(f"  [{attempt}] status={status} progress={progress}")
        if status in ("completed", "failed", "error"):
            return analysis_id, status_data

    print(f"[{label}] TIMEOUT after {timeout_s}s")
    return analysis_id, None


def get_findings(analysis_id: str) -> dict[str, Any]:
    """Fetch findings for an analysis."""
    with urllib.request.urlopen(BASE + f"/api/v1/analyses/{analysis_id}/findings") as r:
        raw_result: Any = json.loads(r.read().decode())
        if isinstance(raw_result, dict):
            return cast(dict[str, Any], raw_result)
        if isinstance(raw_result, list):
            return {"items": raw_result}
        return {"items": []}


def run_fixture(fixture_file: str, label: str, expected: dict[str, Any]) -> dict[str, Any]:
    """Full lifecycle: upload, poll, get findings, compare."""
    print(f"\n{'='*60}")
    print(f"  {label}: {fixture_file}")
    print(f"{'='*60}")
    pcap_path = PCAP_DIR / fixture_file

    if not pcap_path.exists():
        print(f"  ERROR: {pcap_path} not found")
        return {"label": label, "status": "BLOCKED", "error": "fixture not found"}

    analysis_id, status_data = upload_and_poll(pcap_path, label)
    if status_data is None or analysis_id is None:
        return {"label": label, "status": "FAIL", "error": "did not complete"}

    final_status = status_data.get("status")
    if final_status != "completed":
        print(f"  Final status: {final_status}")
        print(f"  Error: {status_data.get('error_message')}")
        return {
            "label": label,
            "status": "FAIL",
            "final_status": final_status,
            "error": status_data.get("error_message"),
        }

    # Fetch findings
    try:
        findings_data: dict[str, Any] = get_findings(analysis_id)
    except Exception as e:
        print(f"  Findings fetch error: {e}")
        findings_data = {"items": [], "error": str(e)}

    raw_items = findings_data.get("items") or findings_data.get("findings") or []
    findings: list[dict[str, Any]] = [
        cast(dict[str, Any], f) for f in raw_items if isinstance(f, dict)
    ]

    raw_posture = status_data.get("posture") or (
        status_data.get("result", {}).get("posture")
        if isinstance(status_data.get("result"), dict)
        else None
    )
    posture: dict[str, Any] = (
        cast(dict[str, Any], raw_posture) if isinstance(raw_posture, dict) else {}
    )

    print(f"\n  Posture: score={posture.get('score')} grade={posture.get('grade')}")
    print(f"  Findings ({len(findings)}):")
    for f in findings:
        rule_id = str(f.get("rule_id", ""))
        severity = str(f.get("severity", ""))
        risk_score = f.get("risk_score")
        print(f"    rule_id={rule_id} severity={severity} risk_score={risk_score}")

    # Compare with expected
    raw_exp_posture = expected.get("expected_posture", {})
    exp_posture: dict[str, Any] = (
        cast(dict[str, Any], raw_exp_posture) if isinstance(raw_exp_posture, dict) else {}
    )
    exp_findings: list[Any] = expected.get("expected_findings", [])

    posture_match = True
    if exp_posture.get("grade"):
        actual_grade = posture.get("grade", "?")
        if actual_grade != exp_posture["grade"]:
            posture_match = False
            print(f"  POSTURE MISMATCH: expected grade={exp_posture['grade']} actual={actual_grade}")

    if isinstance(exp_findings, list) and len(exp_findings) > 0:
        actual_rule_ids: set[str] = {
            str(f.get("rule_id")) for f in findings if "rule_id" in f
        }
        expected_rule_ids: set[str] = set()
        for e in exp_findings:
            if isinstance(e, dict) and "rule_id" in e:
                expected_rule_ids.add(str(e["rule_id"]))
            elif isinstance(e, str):
                expected_rule_ids.add(e)

        missing = expected_rule_ids - actual_rule_ids
        extra = actual_rule_ids - expected_rule_ids
        if missing:
            print(f"  FINDINGS MISSING: {missing}")
        if extra:
            print(f"  EXTRA FINDINGS:   {extra}")
        findings_match = not missing and not extra
    else:
        findings_match = True

    overall = "PASS" if posture_match and findings_match else "FAIL"
    print(f"\n  Result: {overall}")

    actual_findings_summary: list[dict[str, Any]] = [
        {
            "rule_id": f.get("rule_id"),
            "severity": f.get("severity"),
            "risk_score": f.get("risk_score"),
        }
        for f in findings
    ]

    expected_findings_ids: list[str] = []
    if isinstance(exp_findings, list):
        for e in exp_findings:
            if isinstance(e, dict):
                expected_findings_ids.append(str(e.get("rule_id", "")))
            elif isinstance(e, str):
                expected_findings_ids.append(e)

    return {
        "label": label,
        "fixture": fixture_file,
        "status": overall,
        "analysis_id": analysis_id,
        "actual_posture": posture,
        "actual_findings": actual_findings_summary,
        "expected_posture": exp_posture,
        "expected_findings_ids": expected_findings_ids,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Task 4: F02
# ─────────────────────────────────────────────────────────────────────────────
results: list[dict[str, Any]] = []

r_f02 = run_fixture(
    "ikev2_modp1024_3des.pcap",
    "F02",
    {
        "expected_posture": {"score": 25.8, "grade": "F"},
        "expected_findings": [
            {"rule_id": "CRY-DH-001"},
            {"rule_id": "CRY-ENC-001"},
            {"rule_id": "CRY-INT-001"},
        ],
    },
)
results.append(r_f02)

# ─────────────────────────────────────────────────────────────────────────────
# Task 5: F01, F05, F10, F13
# ─────────────────────────────────────────────────────────────────────────────
r_f01 = run_fixture(
    "ikev2_modern_gcm_x25519.pcap",
    "F01",
    {
        "expected_posture": {"grade": "A"},
        "expected_findings": ["IKE-INFO-001"],
    },
)
results.append(r_f01)

r_f05 = run_fixture(
    "ikev1_aggressive_psk.pcap",
    "F05",
    {
        "expected_posture": {},
        "expected_findings": [
            {"rule_id": "IKE-V1-001"},
            {"rule_id": "IKE-V1-002"},
            {"rule_id": "IKE-V1-003"},
            {"rule_id": "CRY-DH-001"},
            {"rule_id": "IKE-V1-005"},
            {"rule_id": "CRY-INT-001"},
        ],
    },
)
results.append(r_f05)

r_f10 = run_fixture(
    "lab_ike_init_flood.pcap",
    "F10",
    {
        "expected_posture": {},
        "expected_findings": [
            {"rule_id": "IKE-DOS-001"},
            {"rule_id": "IKE-DOS-002"},
        ],
    },
)
results.append(r_f10)

r_f13 = run_fixture(
    "esp_null.pcap",
    "F13",
    {
        "expected_posture": {},
        "expected_findings": [
            {"rule_id": "ESP-NULL-001"},
            {"rule_id": "ESP-NOIKE-001"},
        ],
    },
)
results.append(r_f13)

# ─────────────────────────────────────────────────────────────────────────────
# Summary Table
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("TASK 4/5 SUMMARY TABLE")
print("=" * 70)
print(f"{'Fixture':<8} {'Expected Grade':<16} {'Actual Grade':<14} {'Match'}")
print("-" * 70)
for r in results:
    exp_g = (r.get("expected_posture") or {}).get("grade", "—")
    act_g = (r.get("actual_posture") or {}).get("grade", "—")
    match = r.get("status", "?")
    print(f"{r['label']:<8} {exp_g:<16} {act_g:<14} {match}")

print("\nFull JSON results saved to task45_results.json")
with open("task45_results.json", "w") as jf:
    json.dump(results, jf, indent=2, default=str)
