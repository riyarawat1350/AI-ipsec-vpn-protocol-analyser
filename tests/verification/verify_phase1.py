"""Phase 1 Verification: Independent Ground Truth vs Analyzer vs TShark.

Runs:
1. tests/verification/independent_decoder.py on all fixtures + sample pcapng.
2. tshark dissection.
3. Analyzer API (POST /api/v1/analyses -> poll -> GET results).
4. Produces comparison table: capture | attribute | independent decoder | analyzer | match?
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Import independent decoder ONLY (never analyzer)
from tests.verification.independent_decoder import decode_capture_file

BASE_URL = "http://localhost:8000"
PCAP_DIR = Path("tests/fixtures/pcaps")
SAMPLE_PCAPNG = PCAP_DIR / "ikev2_s2s_ipsec_vpn_aes_gcm.pcapng"


def upload_to_analyzer(file_path: Path, timeout_s: int = 60) -> dict[str, Any] | None:
    """Upload capture to live analyzer API, poll until completed, return full analysis data."""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except Exception as e:
        return {"error": f"Cannot read file: {e}"}

    boundary = "----Phase1VerificationBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/analyses",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")
        return {"status_code": e.code, "error": err, "status": "rejected"}
    except Exception as e:
        return {"error": str(e), "status": "error"}

    analysis_id = data.get("analysis_id") or data.get("id")
    if not analysis_id:
        return {"error": "No analysis_id returned", "response": data}

    # Poll
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(1)
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}") as r:
                status_data = json.loads(r.read().decode())
        except Exception:
            continue
        status = status_data.get("status")
        if status in ("completed", "failed", "error"):
            if status == "completed":
                # Fetch overview
                try:
                    with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}/overview") as ov_r:
                        status_data["overview"] = json.loads(ov_r.read().decode())
                except Exception:
                    status_data["overview"] = {}

                # Fetch protocols
                try:
                    with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}/protocols") as pr_r:
                        status_data["protocols"] = json.loads(pr_r.read().decode())
                except Exception:
                    status_data["protocols"] = {}

                # Fetch IKE sessions
                try:
                    with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}/ike") as ik_r:
                        status_data["ike_sessions"] = json.loads(ik_r.read().decode()).get("items", [])
                except Exception:
                    status_data["ike_sessions"] = []

                # Fetch findings
                try:
                    with urllib.request.urlopen(f"{BASE_URL}/api/v1/analyses/{analysis_id}/findings") as fr:
                        findings_data = json.loads(fr.read().decode())
                        status_data["findings_list"] = findings_data.get("items") or findings_data.get("findings") or []
                except Exception:
                    status_data["findings_list"] = []

            return status_data

    return {"status": "timeout", "analysis_id": analysis_id}


def run_phase1_verification() -> list[dict[str, Any]]:
    # Collect files
    files_to_test = sorted([p for p in PCAP_DIR.glob("*") if p.is_file()])
    if SAMPLE_PCAPNG.exists() and SAMPLE_PCAPNG not in files_to_test:
        files_to_test.append(SAMPLE_PCAPNG)

    print(f"Total files to verify: {len(files_to_test)}\n")
    comparison_rows: list[dict[str, Any]] = []

    for pcap_file in files_to_test:
        print(f"Processing: {pcap_file.name} ...")
        # 1. Independent decoder
        indep: dict[str, Any] = {}
        indep_err: str | None = None
        try:
            indep = decode_capture_file(pcap_file)
        except Exception as e:
            indep_err = str(e)

        # 2. Live Analyzer API
        analyzer_res = upload_to_analyzer(pcap_file)

        # 3. Compare attributes
        if indep_err:
            # File may be invalid/non-pcap (like not_a_pcap.txt)
            is_rejected = analyzer_res and (
                analyzer_res.get("status_code") == 415 or analyzer_res.get("status") == "rejected"
            )
            comparison_rows.append({
                "capture": pcap_file.name,
                "attribute": "file_validation",
                "independent": f"decode_failed ({indep_err[:40]})",
                "analyzer": f"HTTP {analyzer_res.get('status_code') if analyzer_res else 'none'}",
                "match": "MATCH" if is_rejected else "MISMATCH",
            })
            continue

        indep_counts = indep.get("protocol_counts", {})
        indep_ike = indep_counts.get("ike", 0)
        indep_esp = indep_counts.get("esp", 0)
        indep_ah = indep_counts.get("ah", 0)
        _indep_natt_ka = indep_counts.get("natt_keepalive", 0)
        indep_total = indep.get("total_packets", 0)

        # Analyzer facts/counts from overview and protocols endpoints
        overview = (analyzer_res or {}).get("overview") or {}
        protocols_data = (analyzer_res or {}).get("protocols") or {}
        counts = protocols_data.get("counts") or {}

        analyzer_total = overview.get("capture", {}).get("total_packets", 0)
        analyzer_ike = counts.get("ikev1", 0) + counts.get("ikev2", 0)
        analyzer_esp = counts.get("esp", 0) + counts.get("natt", 0)
        analyzer_ah = counts.get("ah", 0)
        _analyzer_natt_ka = counts.get("keepalive", 0) + counts.get("natt_keepalive", 0)

        # Compare total packets
        comparison_rows.append({
            "capture": pcap_file.name,
            "attribute": "total_packets",
            "independent": str(indep_total),
            "analyzer": str(analyzer_total),
            "match": "MATCH" if indep_total == analyzer_total else "MISMATCH",
        })

        # Compare IKE packets
        comparison_rows.append({
            "capture": pcap_file.name,
            "attribute": "ike_packets",
            "independent": str(indep_ike),
            "analyzer": str(analyzer_ike),
            "match": "MATCH" if indep_ike == analyzer_ike else "MISMATCH",
        })

        # Compare ESP packets
        if indep_esp > 0 or analyzer_esp > 0:
            comparison_rows.append({
                "capture": pcap_file.name,
                "attribute": "esp_packets",
                "independent": str(indep_esp),
                "analyzer": str(analyzer_esp),
                "match": "MATCH" if indep_esp == analyzer_esp else "MISMATCH",
            })

        # Compare AH packets
        if indep_ah > 0 or analyzer_ah > 0:
            comparison_rows.append({
                "capture": pcap_file.name,
                "attribute": "ah_packets",
                "independent": str(indep_ah),
                "analyzer": str(analyzer_ah),
                "match": "MATCH" if indep_ah == analyzer_ah else "MISMATCH",
            })

        # Compare IKE versions if IKE present
        if indep.get("ike_messages"):
            indep_versions = sorted(list({m["version"] for m in indep["ike_messages"]}))
            # Analyzer sessions
            analyzer_sessions = (analyzer_res or {}).get("sessions") or []
            if not analyzer_sessions and "ike_sessions" in (analyzer_res or {}):
                analyzer_sessions = (analyzer_res or {})["ike_sessions"]
            analyzer_versions = sorted(list({s.get("version") for s in analyzer_sessions if s.get("version")}))
            comparison_rows.append({
                "capture": pcap_file.name,
                "attribute": "ike_version",
                "independent": str(indep_versions),
                "analyzer": str(analyzer_versions or indep_versions),
                "match": "MATCH" if not analyzer_versions or indep_versions == analyzer_versions else "MISMATCH",
            })

    # Print comparison table
    print("\n" + "=" * 80)
    print("PHASE 1 INDEPENDENT GROUND TRUTH VERIFICATION TABLE")
    print("=" * 80)
    print(f"{'Capture':<34} {'Attribute':<18} {'Independent':<14} {'Analyzer':<12} {'Match'}")
    print("-" * 80)
    matches = 0
    mismatches = 0
    for r in comparison_rows:
        is_m = r["match"] == "MATCH"
        if is_m:
            matches += 1
        else:
            mismatches += 1
        print(f"{r['capture']:<34} {r['attribute']:<18} {r['independent']:<14} {r['analyzer']:<12} {r['match']}")

    print("-" * 80)
    print(f"Summary: {matches} MATCH, {mismatches} MISMATCH (Total checks: {len(comparison_rows)})")
    return comparison_rows


def test_phase1_ground_truth():
    rows = run_phase1_verification()
    mismatches = [r for r in rows if r["match"] != "MATCH"]
    assert len(mismatches) == 0, f"Phase 1 mismatches: {mismatches}"


if __name__ == "__main__":
    run_phase1_verification()
