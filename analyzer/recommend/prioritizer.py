"""Prioritized recommendations engine (Fix-First) — TASK-030 per SRS §12.5.

Ranks remediation actions by risk reduction impact and operational effort.
"""

from __future__ import annotations

from typing import Any

from analyzer.models import Finding

RECOMMENDATION_CATALOG: dict[str, dict[str, Any]] = {
    "REC-CRY-DH-001": {
        "title": "Upgrade to Diffie-Hellman Group 14 (MODP-2048) or Modern Elliptic Curves (ECP-256/Curve25519)",
        "effort": "Low",
        "steps": [
            "Configure VPN gateways to offer only DH Group 14 (2048-bit MODP), Group 19 (256-bit ECP), or Group 31 (Curve25519).",
            "Disable legacy MODP groups 1 (768-bit), 2 (1024-bit), and 5 (1536-bit) in phase 1 proposals.",
            "Verify both initiator and responder configurations are committed and active.",
        ],
        "verification": "Initiate negotiation and capture packets. Ensure selected DH group ID is >= 14 or in {19, 20, 21, 31}.",
    },
    "REC-CRY-ENC-001": {
        "title": "Migrate to AEAD Ciphers (AES-GCM-256 or ChaCha20-Poly1305) and Deprecate DES/3DES",
        "effort": "Medium",
        "steps": [
            "Update IKE and ESP proposal configurations to specify AES-GCM (128 or 256 bit) or ChaCha20-Poly1305.",
            "Remove DES, 3DES, CAST, Blowfish, and NULL encryption transforms from active crypto profiles.",
            "Confirm both peers support AEAD hardware acceleration if available.",
        ],
        "verification": "Perform packet capture; verify no offered or selected proposals contain 64-bit block ciphers.",
    },
    "REC-CRY-ENC-002": {
        "title": "Adopt Authenticated Encryption (AEAD) for IKE Phase 1/2",
        "effort": "Low",
        "steps": [
            "Replace AES-CBC + HMAC combinations with AES-GCM or AES-CCM.",
            "Ensure encryption key length is at least 128 bits (preferably 256 bits).",
        ],
        "verification": "Check SA_INIT and child SA transforms for AEAD transform IDs (e.g. 18, 19, 20).",
    },
    "REC-CRY-INT-001": {
        "title": "Enforce SHA-2 (SHA-256, SHA-384, or SHA-512) for Integrity and PRF",
        "effort": "Low",
        "steps": [
            "Remove MD5 and SHA-1 from PRF and integrity algorithms in IKE and ESP configurations.",
            "Configure HMAC-SHA2-256-128 or HMAC-SHA2-512-256.",
        ],
        "verification": "Confirm in packet capture that PRF ID is >= 5 and integrity transform is >= 12.",
    },
    "REC-IKE-V1-001": {
        "title": "Upgrade IPsec VPN Tunnels from IKEv1 to IKEv2 (RFC 7296)",
        "effort": "Medium",
        "steps": [
            "Schedule maintenance window to migrate gateway configuration from IKEv1 to IKEv2.",
            "Align peer identity identifiers (FQDN or IP) and auth credentials under IKEv2 profiles.",
            "Decommission legacy IKEv1 daemons and policy definitions.",
        ],
        "verification": "Verify captures show IKE version 2 (exchange types 34, 35) exclusively.",
    },
    "REC-IKE-V1-002": {
        "title": "Disable IKEv1 Aggressive Mode",
        "effort": "Low",
        "steps": [
            "Change phase 1 negotiation mode from Aggressive Mode to Main Mode on both peers.",
            "If dynamic IP road-warrior support is needed, migrate to IKEv2 with EAP/MOBIKE.",
        ],
        "verification": "Confirm packet capture contains no exchange type 4 (Aggressive Mode).",
    },
    "REC-IKE-V1-003": {
        "title": "Eliminate Pre-Shared Key (PSK) Cleartext Hash Exposure in Aggressive Mode",
        "effort": "Low",
        "steps": [
            "Immediately disable Aggressive Mode when using pre-shared keys.",
            "Rotate the existing pre-shared key immediately as it may have been compromised via capture.",
            "Adopt RSA or ECDSA digital certificates for mutual peer authentication.",
        ],
        "verification": "Validate that no unencrypted HASH payloads are transmitted in handshake messages.",
    },
    "REC-IKE-V1-004": {
        "title": "Restrict IKEv1 Security Association Lifetimes to Policy Bounds",
        "effort": "Low",
        "steps": [
            "Configure IKE SA lifetime to <= 86400 seconds (24 hours).",
            "Configure IPsec child SA lifetime to <= 28800 seconds (8 hours) or 1 GB traffic volume.",
        ],
        "verification": "Inspect transform lifetime attributes in SA proposals.",
    },
    "REC-IKE-V1-005": {
        "title": "Transition from PSK to Public Key Infrastructure (PKI) Certificates",
        "effort": "High",
        "steps": [
            "Establish or integrate enterprise CA infrastructure for gateway machine certificates.",
            "Enroll certificates on both VPN gateways and configure trust anchors.",
            "Switch authentication method from pre-shared key to RSA-SIG or ECDSA-SIG.",
        ],
        "verification": "Verify AUTH payloads or certificates are exchanged rather than shared secrets.",
    },
    "REC-IKE-DOS-001": {
        "title": "Implement IKEv2 Cookie Challenge and SA_INIT Rate Limiting",
        "effort": "Medium",
        "steps": [
            "Enable half-open SA rate-limiting and statutory cookie validation on the VPN gateway.",
            "Restrict UDP 500/4500 access using border ACLs to authorized peer IP ranges.",
            "Monitor gateway connection tables for SA_INIT exhaustion.",
        ],
        "verification": "Verify that high connection volumes trigger COOKIE notifications (type 16390).",
    },
    "REC-IKE-RECON-001": {
        "title": "Restrict Public Gateway Exposure and Filter Scanning Activity",
        "effort": "Low",
        "steps": [
            "Add edge firewall ACLs restricting UDP 500 and 4500 to known peer endpoints.",
            "Disable unnecessary VPN endpoints on unmonitored public IP addresses.",
        ],
        "verification": "Verify external scan traffic is dropped before reaching the IKE daemon.",
    },
    "REC-ESP-NULL-001": {
        "title": "Enforce ESP Payload Encryption to Prevent Cleartext Traffic Exposure",
        "effort": "Low",
        "steps": [
            "Audit IPsec transform sets and remove ESP-NULL / NULL encryption options immediately.",
            "Require AES-GCM or AES-CBC for all phase 2 child SAs.",
        ],
        "verification": "Inspect ESP packet payloads; confirm high entropy and no plaintext IPv4 headers.",
    },
    "REC-ESP-SEQ-001": {
        "title": "Investigate Network Packet Loss and Path Flapping on ESP Tunnel",
        "effort": "Medium",
        "steps": [
            "Check intermediate switches and routers for MTU clamping and packet fragmentation.",
            "Review gateway anti-replay window settings and interface error counters.",
        ],
        "verification": "Check sequence tracking; confirm gap ratio drops below 0.1%.",
    },
}

# Generic fallback metadata
DEFAULT_REC = {
    "title": "Investigate Security Finding and Apply Hardened Profile",
    "effort": "Medium",
    "steps": [
        "Review affected VPN gateway configuration against organizational security baselines.",
        "Update cryptographic proposals to modern standards and verify peer alignment.",
    ],
    "verification": "Re-run capture and analysis to confirm resolution of finding.",
}


def prioritize_recommendations(findings: list[Finding]) -> list[dict[str, Any]]:
    """Group findings by recommendation_id and rank them by risk reduction."""
    groups: dict[str, list[Finding]] = {}

    for f in findings:
        rec_id = f.recommendation_id or f"REC-{f.rule_id}"
        groups.setdefault(rec_id, []).append(f)

    ranked_recs: list[dict[str, Any]] = []

    for rec_id, f_list in groups.items():
        meta = RECOMMENDATION_CATALOG.get(rec_id, DEFAULT_REC)
        # Total risk reduction = sum of risk scores of associated findings
        total_risk = round(sum(f.risk_score for f in f_list if f.risk_score is not None), 1)
        max_risk = max((f.risk_score for f in f_list if f.risk_score is not None), default=0.0)

        # Effort ranking weight: Low = 1, Medium = 2, High = 3
        effort_str = meta.get("effort", "Medium")
        effort_weight = {"Low": 1, "Medium": 2, "High": 3}.get(effort_str, 2)

        ranked_recs.append({
            "recommendation_id": rec_id,
            "title": meta.get("title", f"Remediate {rec_id}"),
            "effort": effort_str,
            "steps": meta.get("steps", []),
            "verification": meta.get("verification", "Re-run capture to verify."),
            "risk_reduction": total_risk,
            "max_risk": max_risk,
            "effort_weight": effort_weight,
            "finding_ids": [f.id for f in f_list],
            "rule_ids": sorted(list({f.rule_id for f in f_list})),
            "findings_count": len(f_list),
        })

    # Sort by total_risk descending, then effort_weight ascending (quick wins first)
    ranked_recs.sort(key=lambda r: (-r["risk_reduction"], r["effort_weight"]))

    # Assign sequential rank 1..N
    for i, rec in enumerate(ranked_recs, start=1):
        rec["rank"] = i

    return ranked_recs
