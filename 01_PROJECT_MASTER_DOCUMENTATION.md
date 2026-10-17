# DOCUMENT 1 — PROJECT MASTER DOCUMENTATION

**Project:** IPsecScope — AI-Assisted IPsec VPN Protocol Analyzer and Security Assessment Framework
**SIH Problem:** SIH26160 · Category: Software · **Version 1.0 · 2026-10-04**

> **Source note.** The official SIH26160 statement was not retrieved; this document is based on the problem title and the team brief. Technical claims come from the cited RFCs/NIST documents as known to the authors; items marked **(verify)** must be checked against the primary source before submission.

## 0. The chain (how every document connects)

```
SIH problem ─▶ problem analysis ─▶ existing solutions ─▶ gaps ─▶ proposed solution
   ─▶ architecture ─▶ SRS (Doc 2) ─▶ technical design ─▶ tasks (Doc 4)
   ─▶ Antigravity build (Doc 3) ─▶ testing (Doc 5) ─▶ final working project
```

| Document | File | Use |
|---|---|---|
| 1 Master documentation | `01_PROJECT_MASTER_DOCUMENTATION.md` | Understand and present the project |
| 2 SRS | `02_SRS_IPsecScope.md` | Requirements, API, DB, rules, UI, reports (single source of truth) |
| 3 Antigravity spec | `03_ANTIGRAVITY_IMPLEMENTATION_SPEC.md` | Build instructions, data contracts, algorithms |
| 4 Task list | `04_DEVELOPMENT_TASK_LIST.md` | TASK-001…054 with acceptance criteria |
| 5 Testing plan | `05_TESTING_AND_VALIDATION_PLAN.md` | Fixtures, test cases, demo, security checklist |

**Hand to Antigravity:** Doc 3 + Doc 2 (and Docs 4–5 for task order and tests).

---

## 1. Project title
**IPsecScope — a passive, evidence-based IPsec VPN protocol analyzer and security assessment framework.**

## 2. Problem statement and analysis
IPsec VPNs (IKEv1/IKEv2 for negotiation, ESP/AH for data, NAT-T for NAT traversal) protect government and enterprise links. Today their security is assessed by hand in Wireshark: slow, inconsistent, expert-dependent. SIH asks for an automated analyzer that ingests captures, identifies IPsec traffic, extracts parameters, assesses security, and reports.

**Why IPsec analysis is hard:**
1. A protocol suite with two incompatible IKE versions, many exchange types, NAT-T encapsulation (UDP/4500 with a 4-byte non-ESP marker), fragmentation.
2. **Most interesting content is encrypted.** Without keys, IKEv2 IKE_AUTH, IKEv1 Quick Mode and all ESP payloads are opaque. A trustworthy tool must state what it cannot know.
3. Misconfiguration (weak DH groups, 3DES, MD5/SHA-1, Aggressive Mode with PSK) is common, but there is no passive checker comparable to `testssl.sh` for TLS.

**Observability boundary (drives the whole design):**

| Can be determined from a keyless PCAP | Cannot be determined |
|---|---|
| IKEv2 IKE_SA_INIT: offered/selected ENCR, PRF, INTEG, DH group; nonces; NAT detection; vendor IDs; cookies | IKE_AUTH identities/auth method/child SA proposals/traffic selectors |
| IKEv1 Main Mode msgs 1–4; Aggressive Mode msgs 1–2 including cleartext ID and HASH | IKEv1 Main Mode msgs 5–6, Quick Mode, **PFS** |
| Exchange types, retransmissions, error notifies, timing, cookies | ESP cipher/integrity algorithm and key length |
| ESP/AH SPIs, sequence numbers, sizes, timing, NAT-T usage | Tunnel vs transport mode (heuristic only in the ESP-NULL case) |
| IKEv1 SA lifetimes | Whether the tunnel is "secure" overall |

**Users:** SOC analysts, network/VPN administrators, security auditors, enterprise and government security teams.

## 3. Existing solutions and limitations (summary; detail in SRS §3)

| Solution | Strength | Limitation | Our relation |
|---|---|---|---|
| Wireshark/tshark | Gold-standard dissection; decryption with keys | No judgement/scoring/report | Validation oracle in tests only |
| Scapy | Flexible packet library | Limited IKEv2 coverage (verify) | PCAP reading, not parsing |
| Zeek | Scalable logging | Limited IPsec coverage (verify), no assessment | Not integrated |
| Suricata | IDS, IKE parser in recent versions (verify) | Alerts, not posture | Out of scope |
| ike-scan | Active IKEv1 enumeration, fingerprinting | Active, IKEv1-centric, no scoring | Used to generate *authorised lab* test traffic |
| strongSwan/libreswan | Real implementations, key logs | Not analyzers | Lab ground truth |
| Config scanners (Nessus/CIS) | Policy audit | Need device access, no traffic evidence | Complementary |
| Commercial NDR | Mature encrypted-traffic analytics | Closed, costly, not IPsec-posture-specific | Differentiated |

**Gap:** nothing mainstream offers *passive, evidence-linked, policy-driven IPsec security assessment from captures with transparent scoring, prioritised fixes and a report*.

## 4. Proposed solution
A Python analysis library with its **own IKE/ESP parser**, session reconstruction, YAML policy engine (declarative rules + behavioural detectors), deterministic risk scoring, a lightweight unsupervised anomaly model, optional LLM narrative, a FastAPI backend, a React dashboard and a report generator (HTML/PDF/JSON/CSV).

**Objectives:** parse and identify IPsec correctly; extract all observable parameters; detect weak configuration and suspicious behaviour; score and prioritise; give packet-level evidence; generate reports; state limits honestly.

**Novelty:** policy-as-code posture assessment; offered-vs-selected-aware likelihood; ESP-NULL (unencrypted payload) heuristic with IPv4 checksum validation; hand-recomputable scoring; capture comparison; mandatory "limits & coverage" section; ML and LLM confined to roles where they add value.

## 5. Key features by priority

| Tier | Features |
|---|---|
| **A. Must (MVP)** | Upload/validation; pcap/pcapng streaming; link/L3/L4 decode + IPv4 defrag; IKE/ESP/AH/NAT-T classification; own IKEv1/v2 parser; session reconstruction + timeline; ESP flow/seq tracking; YAML rules (crypto, IKEv1/AM, negotiation failures, protocol anomalies); detectors (flood, scan, ESP seq/NULL); evidence-linked findings; severity/risk/posture; recommendations; dashboard; HTML/PDF/JSON report; REST API; CLI; capabilities page |
| **B. Should** | Policy profiles; vendor-ID fingerprint (peer-reported); KE-length consistency check; fix-first prioritisation; non-standard-port IKE heuristic; IKE↔ESP linking (heuristic); timeline/ladder views; CSV exports; optional bearer auth |
| **C. Advanced** | Isolation Forest behavioural anomaly scoring (lab-trained); IOC extraction; MITRE ATT&CK *related* mapping (3 rules only); capture comparison; optional validated LLM narrative; ESP-NULL heuristic |
| **D. Future** | Key-assisted decryption (authorised lab keys); live capture agent; SIEM export (CEF/STIX); config reconstruction (strongSwan/Cisco syntax); post-quantum IKE readiness (RFC 9370 **(verify)**); TCP-encapsulated IKE/ESP; IPv6 fragment reassembly; fleet view; GeoIP |

## 6. Critical review log (changes made after self-review)

| # | Issue found | Decision |
|---|---|---|
| 1 | Earlier idea listed "PFS detection" among rules | **Removed.** Child SA proposals are encrypted; PFS is unobservable from keyless captures. Reported only as a coverage note |
| 2 | "ESP cipher identification" implied | **Removed.** Only SPI/seq/size/timing are visible; ESP-NULL is a narrow checksum-validated heuristic |
| 3 | Upload and analyze as separate APIs | **Merged** into `POST /analyses` to avoid orphan uploads |
| 4 | Severity bands: earlier draft had Critical ≥ 80, which made "MODP-1024 selected" Critical | **Refined:** Critical ≥ 85, High ≥ 65; MODP-1024 selected = 80.0 High; DES/NULL overrides remain Critical |
| 5 | Posture formula was harsh (one High → grade F) | **Dampened** with 0.6 weight and explicit caps (SRS §12.3) |
| 6 | ML claims at risk of overreach | ML restricted to behavioural windows; evaluated on lab data only; severity capped at Medium; model absent ⇒ `unavailable`, never fabricated |
| 7 | Dependence on tshark/PyShark | Own parser; tshark only as test oracle |
| 8 | Dedupe ambiguity (same algorithm offered and selected) | One finding with role `selected` (SPEC §5.10) |
| 9 | Golden tests risk being self-referential | Expected scores derived by hand from formulas (Doc 5 §3) |
| 10 | Vendor ID could be over-trusted | Labelled "peer-reported"; informational only |
| 11 | MITRE mapping could be forced | Only 3 rules mapped, as "related technique" |
| 12 | GeoIP/threat-intel in MVP | Moved to Future (cosmetic, external data) |
| 13 | Heavy infra (Celery/Redis/Kafka) tempting | Process pool + SQLite; Postgres optional |
| 14 | Hosting on free PaaS with sensitive captures | Documented as demo-only; local/Docker recommended |

**Remaining expert criticisms to prepare for:** (a) most conclusions depend on handshake presence — a capture starting mid-session yields little; (b) scoring weights are design choices, not an industry standard; (c) the ML model is a lab baseline, not production-grade; (d) vendor fingerprints can be spoofed; (e) ESP sequence gaps can be capture loss (hence confidence ≤ 0.6).

## 7. Architecture (summary; detail in SRS §7)

```
Upload → validate → stream/decode/defrag → classify (IKE|ESP|AH|NAT-T)
  → IKE parse (v1/v2) | ESP/AH track → sessions + flows → facts
  → rules + detectors ┐
  → ML windows        ├→ findings → scoring → posture → recommendations/IOC/MITRE
  → narrative (template or validated LLM) ┘
  → DB → API → React dashboard → report (HTML/PDF/JSON/CSV)
```

## 8. Technology choices and why

| Layer | Choice | Reason / alternatives rejected |
|---|---|---|
| Backend | FastAPI | Python ecosystem for packets+ML; typed schemas. Flask lacks validation; Node weaker packet libs |
| Parsing | Own `struct` parser; Scapy for reading | Avoids wrapper criticism; tshark/PyShark slow/fragile as core |
| ML | scikit-learn Isolation Forest | Small tabular unlabelled data; PyTorch/TF overkill |
| LLM | Optional (Ollama/API) with template fallback | Prose only; privacy-safe default |
| DB | SQLite → PostgreSQL | Relational findings/sessions; MongoDB unnecessary |
| Frontend | React+Vite+TS+Tailwind+Recharts | Rich tables/timelines; plain HTML slower to build well |
| Reports | Jinja2 + WeasyPrint | Same template for HTML/PDF |
| Deploy | Docker Compose | One-command demo; tshark needs not hosted |

## 9. AI/ML methodology (summary; SRS §11)
Rule-based: all weakness/protocol/ESP checks and scoring. ML: Isolation Forest on per-initiator 10 s IKE behaviour windows, trained on lab-generated benign captures, evaluated on held-out lab runs with injected floods/scans (authorised, own lab). LLM: executive summary only, from sanitised structured findings, validated against real finding IDs/numbers. No AI for parsing, scoring or recommendations.

## 10. Security assessment methodology (summary; SRS §12.3)
`R = Impact×Likelihood/25×100×(0.5+0.5×Confidence)`; bands Critical ≥ 85, High ≥ 65, Medium ≥ 35, Low ≥ 15, Info below; overrides for NULL/DES; posture `100×Π(1−0.6·R/100)` with caps; likelihood depends on whether a parameter was *selected* (5), *offered* (3) or only seen in failed negotiation (2). Example: MODP-1024 selected ⇒ 80.0 High.

## 11. Real-world use
- **SOC:** triage a suspicious capture — flood/scan patterns with evidence.
- **Network admin:** verify a new tunnel negotiates modern crypto; compare before/after hardening.
- **Auditor/government:** repeatable evidence-backed VPN posture reports.

**Worked example:** upload `site-b.pcap` → IKEv2 between 10.1.0.1 and 203.0.113.9 identified → SA_INIT response (packet 4) selects MODP-1024 + 3DES + SHA-1 → findings CRY-DH-001 (80.0 High), CRY-ENC-001 (60.0 Medium), two SHA-1 Low → posture ≈ 25.8 (F) → each finding shows packet evidence and standards references → fix-first: "use group 14+/19/20/31, AES-GCM, SHA-256+" → PDF report with limits section.

## 12. Demo plan
See Doc 5 §6 (5-minute script: upload weak capture → findings with evidence and formula → session detail with "not observable" panel → flood capture with ML panel → compare vs hardened → PDF → capabilities page). Data: authorised fixtures or own strongSwan lab; Wireshark public samples for functional demos only.

## 13. Advantages, limitations, future scope
**Advantages:** passive and safe; explainable; reproducible; policy-tunable; honest about limits; testable against an independent oracle.
**Limitations:** keyless captures expose only handshakes' cleartext parts; incomplete captures limit conclusions; heuristics labelled; ML is lab-baseline; scoring weights are design decisions; no TCP-encapsulated IKE/ESP, limited IPv6 fragments.
**Future scope:** see tier D.

## 14. Expected results
A working application that, given a PCAP/PCAPNG, produces correct IPsec inventory, evidence-linked findings with recomputable scores, prioritised remediation, anomaly insight (when a lab-trained model is present) and downloadable reports — with a capabilities page showing exactly what is and is not implemented.

## 15. References to verify and cite
RFC 7296 (IKEv2); RFC 2408/2409 (ISAKMP/IKEv1); RFC 4303 (ESP); RFC 4302 (AH); RFC 3947/3948 (NAT-T); RFC 7383 (IKEv2 fragmentation); RFC 8247 (IKEv2 algorithm guidance); RFC 8221 (ESP/AH algorithm guidance); RFC 9370 (multiple key exchanges); NIST SP 800-77 Rev. 1; NIST SP 800-131A; IANA IKEv2 and IKE/ISAKMP parameter registries; Wireshark ISAKMP/ESP documentation and sample captures; strongSwan documentation; ike-scan documentation; Suricata IKE documentation; MITRE ATT&CK (T1046, T1498, T1110.002).
