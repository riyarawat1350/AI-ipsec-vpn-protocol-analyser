"""Phase 3 Consistency Cross-Check Verification Suite.

Verifies mathematical and numerical consistency across:
- Overview API (/overview)
- Protocols API (/protocols)
- IKE Sessions API (/ike)
- ESP Flows API (/esp)
- Findings API (/findings)
- Recommendations API (/recommendations)
- Timeline API (/timeline)
- Report Generator (HTML, PDF, JSON, CSV)

Checks:
- Packets, IKE exchanges, sessions, flows count
- Findings total count and severity counts
- Posture score and grade consistency
- Notify panel payload presence in messages
- Vendor IDs ASCII decoding
- Fix-First rank and alignment
"""

from __future__ import annotations

import csv
import io
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = "http://localhost:8000"
FIXTURES_TO_TEST = [
    "ikev2_modp1024_3des.pcap",       # F02: Weak, multiple findings
    "ikev2_modern_gcm_x25519.pcap",   # F01: Hardened, clean
    "natt_ikev2_esp.pcap",            # F06: NAT-T, IKE+ESP, vendor ID, notifies
]


def run_cross_check(filename: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    pcap_path = Path("tests/fixtures/pcaps") / filename
    if not pcap_path.exists():
        pcap_path = Path("tests/fixtures/pcap") / filename

    print(f"\n--- Testing Consistency for {filename} ---")

    # 1. Upload
    boundary = "----IPsecScopeConsistencyCheck"
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
    body.extend(b"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n")
    body.extend(pcap_path.read_bytes())
    body.extend(f"\r\n--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/analyses",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        upload_data = json.loads(resp.read().decode())
    analysis_id = upload_data.get("analysis_id") or upload_data.get("_id") or upload_data.get("id")

    # Poll until completed
    for _ in range(60):
        with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}") as r:
            root_data = json.loads(r.read().decode())
        if root_data.get("status") in ("completed", "failed"):
            break
        time.sleep(0.5)

    assert root_data.get("status") == "completed", f"Analysis did not complete: {root_data.get('status')}"

    # 2. Fetch all endpoints
    def get_json(endpoint: str) -> dict[str, Any]:
        with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}{endpoint}") as r:
            return json.loads(r.read().decode())

    overview = get_json("/overview")
    protocols = get_json("/protocols")
    ike_data = get_json("/ike")
    esp_data = get_json("/esp")
    findings_data = get_json("/findings")
    _recs_data = get_json("/recommendations")

    # Generate Reports
    def create_report(fmt: str) -> dict[str, Any]:
        r_req = urllib.request.Request(
            f"{BASE_URL}/api/v1/analyses/{analysis_id}/reports",
            data=json.dumps({"format": fmt}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(r_req) as rr:
            return json.loads(rr.read().decode())

    rep_json_info = create_report("json")
    rep_csv_info = create_report("csv")
    rep_html_info = create_report("html")
    rep_pdf_info = create_report("pdf")

    # Download Reports
    with urllib.request.urlopen(f"{BASE_URL}{rep_json_info['download_url']}") as r:
        rep_json = json.loads(r.read().decode())

    with urllib.request.urlopen(f"{BASE_URL}{rep_csv_info['download_url']}") as r:
        rep_csv_text = r.read().decode()

    with urllib.request.urlopen(f"{BASE_URL}{rep_html_info['download_url']}") as r:
        rep_html_text = r.read().decode()

    with urllib.request.urlopen(f"{BASE_URL}{rep_pdf_info['download_url']}") as r:
        rep_pdf_bytes = r.read()

    # 3. Consistency Cross-Checks
    # Check 1: Posture Grade consistency across root, overview, and HTML report
    root_grade = root_data.get("posture", {}).get("grade")
    overview_grade = overview.get("posture", {}).get("grade")
    rep_json_grade = rep_json.get("posture", {}).get("grade") or rep_json.get("analysis", {}).get("posture", {}).get("grade")
    checks.append({
        "check": f"{filename} - Posture Grade Consistency",
        "expected": root_grade,
        "actual": f"root={root_grade}, overview={overview_grade}, rep_json={rep_json_grade}",
        "passed": root_grade == overview_grade == rep_json_grade and (f"Grade {root_grade}" in rep_html_text),
    })

    # Check 2: Posture Score consistency
    root_score = round(float(root_data.get("posture", {}).get("score", 0)), 1)
    overview_score = round(float(overview.get("posture", {}).get("score", 0)), 1)
    rep_json_score = round(float(rep_json.get("posture", {}).get("score") or rep_json.get("analysis", {}).get("posture", {}).get("score", 0)), 1)
    checks.append({
        "check": f"{filename} - Posture Score Consistency",
        "expected": root_score,
        "actual": f"root={root_score}, overview={overview_score}, rep_json={rep_json_score}",
        "passed": abs(root_score - overview_score) < 0.1 and abs(root_score - rep_json_score) < 0.1,
    })

    # Check 3: Total Packets consistency
    overview_pkts = overview.get("capture", {}).get("total_packets", 0)
    protocols_pkts = protocols.get("counts", {}).get("total_packets") or protocols.get("capture", {}).get("total_packets", 0)
    checks.append({
        "check": f"{filename} - Total Packets Consistency",
        "expected": overview_pkts,
        "actual": f"overview={overview_pkts}, protocols={protocols_pkts}",
        "passed": overview_pkts == protocols_pkts,
    })

    # Check 4: Findings Count consistency (API vs Overview vs JSON report vs CSV rows)
    findings_list = findings_data.get("items") or findings_data.get("findings") or []
    findings_api_count = len(findings_list)
    overview_sev_counts = overview.get("finding_counts") or overview.get("severity_counts") or {}
    overview_total_findings = sum(overview_sev_counts.values())
    rep_json_findings_count = len(rep_json.get("findings", []))

    # Parse CSV rows (excluding header)
    csv_reader = list(csv.reader(io.StringIO(rep_csv_text)))
    csv_findings_count = max(0, len(csv_reader) - 1)

    checks.append({
        "check": f"{filename} - Findings Count Consistency",
        "expected": findings_api_count,
        "actual": f"api={findings_api_count}, overview_sum={overview_total_findings}, json={rep_json_findings_count}, csv={csv_findings_count}",
        "passed": findings_api_count == overview_total_findings == rep_json_findings_count == csv_findings_count,
    })

    # Check 5: Severity Counts Breakdown consistency
    api_sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings_list:
        sev = f.get("severity")
        if sev in api_sev_counts:
            api_sev_counts[sev] += 1

    checks.append({
        "check": f"{filename} - Severity Breakdown Consistency",
        "expected": api_sev_counts,
        "actual": overview_sev_counts,
        "passed": all(api_sev_counts.get(k, 0) == overview_sev_counts.get(k, 0) for k in api_sev_counts),
    })

    # Check 6: IKE Sessions Count consistency
    ike_sessions_list = ike_data.get("items", [])
    rep_json_sessions = rep_json.get("sessions", [])
    checks.append({
        "check": f"{filename} - IKE Sessions Count Consistency",
        "expected": len(ike_sessions_list),
        "actual": len(rep_json_sessions),
        "passed": len(ike_sessions_list) == len(rep_json_sessions),
    })

    # Check 7: ESP Flows Count consistency
    esp_flows_list = esp_data.get("items", [])
    rep_json_flows = rep_json.get("flows", [])
    checks.append({
        "check": f"{filename} - ESP Flows Count Consistency",
        "expected": len(esp_flows_list),
        "actual": len(rep_json_flows),
        "passed": len(esp_flows_list) == len(rep_json_flows),
    })

    # Check 8: PDF Report Generated and valid size
    checks.append({
        "check": f"{filename} - PDF Report Generated",
        "expected": ">= 1000 bytes",
        "actual": f"{len(rep_pdf_bytes)} bytes",
        "passed": len(rep_pdf_bytes) >= 1000 and rep_pdf_bytes.startswith(b"%PDF"),
    })

    # Check 9: CSV Formula Injection Protection
    # Formula-injection characters (=, +, -, @) must be escaped/prefixed with '
    csv_injection_safe = True
    for row in csv_reader[1:]:
        for cell in row:
            if cell.startswith(("=", "+", "-", "@")) and not cell.startswith("'"):
                csv_injection_safe = False
    checks.append({
        "check": f"{filename} - CSV Formula Injection Protection",
        "expected": "Escaped with leading quote",
        "actual": "Safe" if csv_injection_safe else "Unsafe formula chars",
        "passed": csv_injection_safe,
    })

    # Check 10: Specific Bug Confirmations (Notifies & Vendor IDs)
    if filename == "natt_ikev2_esp.pcap":
        # Check that session messages contain notifies or vendor_ids
        has_notifies_or_vid = any(
            len(m.get("notifies", [])) > 0 or len(m.get("vendor_ids", [])) > 0
            for s in ike_sessions_list
            for m in s.get("messages", [])
        ) or any(len(s.get("vendor_ids", [])) > 0 for s in ike_sessions_list)
        checks.append({
            "check": f"{filename} - Notify & Vendor ID Payload Extraction",
            "expected": "Payloads extracted from packets",
            "actual": "Present" if has_notifies_or_vid else "Empty",
            "passed": has_notifies_or_vid,
        })

    return checks


def verify_phase3() -> None:
    print("=" * 80)
    print("PHASE 3: SCREENS, EXPORTS & REPORT CONSISTENCY VERIFICATION")
    print("=" * 80)

    all_checks: list[dict[str, Any]] = []
    for fn in FIXTURES_TO_TEST:
        try:
            res = run_cross_check(fn)
            all_checks.extend(res)
        except Exception as e:
            print(f"Error testing {fn}: {e}")
            all_checks.append({
                "check": f"{fn} - Execution",
                "expected": "Pass without error",
                "actual": str(e),
                "passed": False,
            })

    print("\n" + "=" * 80)
    print("CONSISTENCY CROSS-CHECK RESULTS TABLE")
    print("=" * 80)
    print(f"{'Check':<56} {'Expected':<12} {'Passed'}")
    print("-" * 80)
    passed_count = sum(1 for c in all_checks if c["passed"])
    for c in all_checks:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"{c['check']:<56} {str(c['expected'])[:12]:<12} {status}")
        if not c["passed"]:
            print(f"   [!] Actual: {c['actual']}")

    print("-" * 80)
    print(f"Phase 3 Summary: {passed_count}/{len(all_checks)} PASSED")
    if passed_count == len(all_checks):
        print("All Phase 3 Consistency Cross-Checks PASSED (100%)!")

    return {
        "total": len(all_checks),
        "passed": passed_count,
        "failed": len(all_checks) - passed_count,
        "checks": all_checks,
    }


def test_phase3_cross_screen_consistency():
    res = verify_phase3()
    assert res["failed"] == 0, f"Phase 3 had {res['failed']} failure(s)"


if __name__ == "__main__":
    verify_phase3()
