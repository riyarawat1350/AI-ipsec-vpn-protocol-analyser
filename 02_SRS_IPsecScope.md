# DOCUMENT 2 — SOFTWARE REQUIREMENTS SPECIFICATION (SRS)

**Project:** IPsecScope — AI-Assisted IPsec VPN Protocol Analyzer and Security Assessment Framework
**SIH Problem ID:** SIH26160 (category: Software)
**Version:** 1.0 · **Date:** 2026-10-04 · **Status:** Baseline for implementation

> **Source note.** The official SIH26160 statement text was not retrieved; requirements are derived from the problem title and the team brief. Items marked **(verify)** must be checked against the cited RFC/IANA registry before being hard-coded. Priority tags: **M** = Must (MVP), **S** = Should, **A** = Advanced, **F** = Future Scope (do not implement; list as Not Implemented).

---

## 1. Introduction

### 1.1 Purpose
This SRS defines the functional and non-functional requirements, architecture, data model, APIs, rule engine, ML scope, UI and test requirements for IPsecScope. It is the single source of truth for development.

### 1.2 Scope
IPsecScope is a **passive, offline** analyzer. It ingests PCAP/PCAPNG files, identifies IPsec traffic (IKEv1, IKEv2, ESP, AH, NAT-T), reconstructs IKE sessions and ESP flows, extracts every parameter that is observable **without decrypting anything**, evaluates them against a policy-as-code rule set, detects behavioural anomalies, scores risk, explains each finding with packet-level evidence, recommends fixes in priority order, and generates reports.

**In scope:** offline analysis of uploaded captures; web dashboard; REST API; CLI; reports; lab tooling to produce authorised test captures.
**Out of scope:** decrypting traffic (except Future Scope key-assisted mode on user-supplied keys for authorised lab captures), live capture, active probing of gateways, exploitation, config pushing, TCP-encapsulated IKE/ESP (RFC 8229), other VPN families (OpenVPN, WireGuard, SSL VPN).

### 1.3 Project overview
Wireshark dissects but does not judge; Suricata/Zeek alert but do not assess configuration; ike-scan probes actively. IPsecScope fills the gap: **evidence-linked, explainable, passive IPsec posture assessment from captures**.

### 1.4 Intended users
SOC analysts (triage), network/VPN administrators (verify tunnels), security auditors (repeatable evidence), government/enterprise security teams (policy compliance), students/researchers (learning IKE).

### 1.5 Definitions and abbreviations

| Term | Meaning |
|---|---|
| IPsec | Suite securing IP traffic (IKE + ESP/AH) |
| IKE / IKEv1 / IKEv2 | Internet Key Exchange; negotiates keys and algorithms (RFC 2409/2408, RFC 7296) |
| SA | Security Association (negotiated parameter set + keys) |
| ESP / AH | Encapsulating Security Payload (RFC 4303) / Authentication Header (RFC 4302) |
| NAT-T | NAT traversal; ESP over UDP/4500 with IKE preceded by a 4-byte zero "non-ESP marker" (RFC 3947/3948, RFC 7296 §2.23) |
| DH / MODP / ECP | Diffie-Hellman; modular-exponent group / elliptic-curve group |
| PFS | Perfect forward secrecy |
| PSK | Pre-shared key |
| AEAD | Authenticated encryption (AES-GCM, ChaCha20-Poly1305) |
| SPI | Security Parameter Index (identifies ESP/AH SA) |
| Observation | One cryptographic parameter seen in a packet (offered or selected) |
| Finding | A rule/model result with evidence, severity, confidence and risk |
| Evidence | Packet numbers, parsed field values, hex excerpt supporting a finding |
| IOC | Indicator of compromise/interest (peer IP, SPI, vendor ID, etc.) |

---

## 2. Problem Description

**2.1 SIH problem statement.** Develop an AI-powered IPsec VPN protocol analyzer and security assessment framework that analyses captured IPsec VPN traffic and assesses its security.

**2.2 Current problem.** Analysts inspect PCAPs manually in Wireshark: filter by `isakmp`/`esp`, read transform payloads, compare against standards from memory, and write reports by hand. This is slow, inconsistent and not repeatable.

**2.3 Real-world challenges.**
- IPsec is a suite (IKE on UDP 500/4500, ESP proto 50, AH proto 51, NAT-T encapsulation) with two incompatible IKE versions.
- Most useful data is encrypted: IKEv2 IKE_AUTH, IKEv1 Quick Mode, and all ESP payloads are opaque without keys. Tools must say clearly what they *cannot* determine.
- Misconfiguration (weak DH groups, 3DES, MD5, IKEv1 Aggressive Mode with PSK) is common and has no automated, passive checker.
- IKE responders are exposed to scanning and floods.

**2.4 Why needed.** Automate the repeatable 80% (parse, judge, score, report) so analysts spend time on the 20% needing human judgement.

### 2.5 Observability boundary (normative)

| Observable from keyless PCAP | NOT observable (system must never claim) |
|---|---|
| IKEv2 IKE_SA_INIT: offered/selected ENCR, PRF, INTEG, DH group; nonces; KE length; NAT-detection and other notifies; vendor IDs; COOKIE exchange | IKE_AUTH content: identities, auth method, certificates, child-SA proposals, traffic selectors (encrypted in SK payload) |
| IKEv1 Main Mode msgs 1–4 (SA transforms, KE, nonce); Aggressive Mode msgs 1–2 (incl. **ID and HASH in clear**) | IKEv1 Main Mode msgs 5–6 identities/hash, Quick Mode, PFS usage (encrypted) |
| IKE exchange types, message IDs, retransmissions, error notifies, timing | ESP cipher/integrity algorithm, key length, PFS, lifetimes (IKEv2) |
| ESP/AH SPI, sequence number (low 32 bits), size, timing, direction, encapsulation (raw/NAT-T) | Tunnel vs transport mode (only heuristically inferable in one case: ESP-NULL, see FR-39) |
| IKEv1 SA lifetimes (visible as transform attributes) | Whether a tunnel is actually "secure" end-to-end |

---

## 3. Existing System

| Tool | Capability | Limitation | Identified gap |
|---|---|---|---|
| Wireshark/tshark | Complete ISAKMP/IKEv2/ESP/AH dissection; optional decryption with supplied keys | No judgement, scoring, cross-packet session reasoning, or reporting; manual | Automated assessment layer |
| Scapy | Packet library; ESP/AH/ISAKMP layers | Limited IKEv2 payload coverage (verify); no analysis logic | Used only for reading/crafting test packets |
| Zeek | Scalable protocol logging | IPsec/IKE coverage limited (verify); logs not assessments | Per-session posture analysis |
| Suricata | IDS; IKE app-layer parser in recent versions (verify) | Event alerts, not configuration weakness; no reporting | Config-quality assessment with evidence |
| ike-scan | Active IKEv1 transform enumeration, vendor fingerprint, PSK hash capture | Active (touches live gateways); IKEv1-centric; no scoring | Passive, PCAP-based, IKEv2-aware |
| strongSwan/libreswan | IPsec implementations; key logging | Not analyzers | Used as lab ground truth |
| Config scanners (Nessus, CIS tools) | Audit device configuration | Need device access; no traffic evidence | Evidence from captures |
| Commercial NDR (e.g., ExtraHop, Corelight, Darktrace) | Encrypted-traffic analytics | Closed, costly, not IPsec-posture-specific | Transparent, explainable, IPsec-specific |
| Academic VPN traffic classification | VPN vs non-VPN ML | Not misconfiguration/posture; datasets dated | ML only for behavioural anomaly |

**Gap:** no mainstream tool performs passive, evidence-linked, policy-driven IPsec security assessment from a capture with scoring, prioritised remediation and a report ("testssl.sh for IPsec captures").

---

## 4. Proposed System

**4.1 Solution.** A Python analysis library (`analyzer`) with its **own IKE/ESP parser**, session reconstructor, YAML policy engine, deterministic risk scorer, a small unsupervised anomaly model, optional LLM narrator, wrapped by a FastAPI backend, React dashboard and report generator.

**4.2 Objectives.**
1. Correctly identify and parse IPsec traffic in PCAP/PCAPNG.
2. Extract all observable security parameters.
3. Detect weak/deprecated configuration and suspicious behaviour with reproducible rules.
4. Score and prioritise risk using a documented methodology.
5. Show packet-level evidence for every finding.
6. Generate professional reports.
7. State limits honestly (what cannot be known from encrypted traffic).

**4.3 Core capabilities.** Upload → parse → classify → IKE/ESP analysis → rules → ML anomaly → scoring → findings/recommendations → dashboard → report.

**4.4 Innovation.**
- Policy-as-code (YAML) IPsec posture assessment, offered-vs-selected-aware likelihood.
- Own IKE parser cross-validated against tshark in CI.
- ESP-NULL (unencrypted payload) detection heuristic with IPv4 checksum validation.
- Transparent scoring formula a reviewer can recompute by hand.
- Capture-to-capture comparison ("did the change weaken the VPN?").
- Observability-boundary reporting: every report lists what could *not* be assessed.
- ML restricted to behaviour that rules cannot enumerate; LLM restricted to prose.

---

## 5. Functional Requirements

Format: **ID | Requirement | Pri**. "Shall" = mandatory for the stated priority.

### 5.1 File upload and validation
| ID | Requirement | Pri |
|---|---|---|
| FR-01 | The system shall allow users to upload PCAP/PCAPNG files via the UI and `POST /api/v1/analyses`. | M |
| FR-02 | The system shall validate files by magic bytes (pcap: `A1B2C3D4`, `D4C3B2A1`, `A1B23C4D`, `4D3CB2A1`; pcapng: `0A0D0D0A`), not by extension, and reject others with HTTP 415. | M |
| FR-03 | The system shall compute SHA-256 and store filename, size, hash, timestamp. | M |
| FR-04 | The system shall store uploads under server-generated UUID names outside any served directory and never execute or render their content as markup. | M |
| FR-05 | The system shall run analysis asynchronously and expose status (`queued/running/completed/failed`) and progress percentage. | M |
| FR-06 | The system shall allow deleting an analysis and its stored file and artifacts. | M |
| FR-07 | The system shall enforce configurable limits (default 200 MB file, 2,000,000 packets, 300 s analysis timeout) and fail gracefully with a clear error. | M |

### 5.2 PCAP parsing
| ID | Requirement | Pri |
|---|---|---|
| FR-08 | The system shall stream packets (no full-file load) from pcap (µs/ns) and pcapng. | M |
| FR-09 | The system shall support link types Ethernet(1), raw IP(101), Linux SLL(113), Linux SLL2(276), loopback/null (0, 108) and report unsupported link types. | M |
| FR-10 | The system shall decode 802.1Q/QinQ VLAN tags, IPv4, and IPv6 (including skipping common extension headers). | M |
| FR-11 | The system shall reassemble IPv4 fragments (keyed by src, dst, id, proto) with memory and timeout bounds. IPv6 fragment reassembly is Partial. | M |
| FR-12 | The system shall tolerate truncated/corrupt packets and files: skip, count, warn, continue. | M |
| FR-13 | The system shall compute capture statistics: packet/byte counts, time span, protocol distribution, top talkers. | M |

### 5.3 Protocol detection
| ID | Requirement | Pri |
|---|---|---|
| FR-14 | The system shall identify IKE on UDP/500 and UDP/4500 (after stripping the 4-byte non-ESP marker), validating version, length and exchange type before accepting. | M |
| FR-15 | The system shall identify ESP on IP proto 50 and ESP-in-UDP on UDP/4500 (first 4 bytes non-zero SPI ≥ 256). | M |
| FR-16 | The system shall identify AH on IP proto 51. | M |
| FR-17 | The system shall identify NAT-T keepalives (UDP/4500, 1 byte `0xFF`). | M |
| FR-18 | The system shall attempt IKE detection on non-standard UDP ports by header validation and label results with confidence ≤ 0.6. | S |
| FR-19 | The system shall report detected-but-unsupported encapsulations (e.g., IKE over TCP/4500 per RFC 8229, IPv6 fragments) in the limitations list instead of ignoring them silently. | M |

### 5.4 IKE analysis
| ID | Requirement | Pri |
|---|---|---|
| FR-20 | The system shall parse the 28-byte IKE header: SPIs, next payload, version, exchange type, flags, message ID, length. | M |
| FR-21 | The system shall parse the IKEv2 payload chain (SA, KE, Ni/Nr, Notify, Vendor ID, Delete, CERTREQ, SK/SKF opaque) with bounds checking. | M |
| FR-22 | The system shall parse the IKEv1 payload chain (SA, Proposal, Transform, KE, ID, HASH, Nonce, Notification, Vendor ID, NAT-D, CERT/CERTREQ) with bounds checking. | M |
| FR-23 | The system shall extract IKEv2 proposals and transforms (ENCR with key length, PRF, INTEG, DH, ESN) and distinguish *offered* (initiator) from *selected* (responder). | M |
| FR-24 | The system shall extract IKEv1 SA transform attributes (encryption, hash, auth method, group, lifetime type/duration, key length), handling TV and TLV attribute encoding. | M |
| FR-25 | The system shall verify that KE payload length is consistent with the DH group and flag mismatches. | S |
| FR-26 | The system shall extract Notify payloads (type, name, data summary) including NO_PROPOSAL_CHOSEN, INVALID_KE_PAYLOAD, COOKIE, NAT_DETECTION_*, IKEV2_FRAGMENTATION_SUPPORTED, SIGNATURE_HASH_ALGORITHMS, REDIRECT_SUPPORTED. | M |
| FR-27 | The system shall extract Vendor ID payloads and match them against a fingerprint table. | S |
| FR-28 | The system shall infer NAT presence from NAT_DETECTION notifies/NAT-D payloads and UDP/4500 float. | S |
| FR-29 | The system shall extract IKEv1 Aggressive Mode cleartext ID type/value and presence of HASH payload, with optional redaction of ID values in stored output. | M |
| FR-30 | The system shall reconstruct IKE sessions keyed by initiator SPI (+ initiator IP) and responder SPI, handling the zero responder SPI of first messages and COOKIE/INVALID_KE retries. | M |
| FR-31 | The system shall detect retransmissions (same SPI, message ID, exchange, direction, near-identical content) and count them. | M |
| FR-32 | The system shall classify session outcome: `established_observed`, `failed_notify`, `unanswered`, `incomplete_capture`, `unknown`. | M |
| FR-33 | The system shall build a per-session handshake timeline with message order, direction, delay. | M |
| FR-34 | The system shall mark encrypted portions (IKEv2 SK/SKF, IKEv1 encryption flag) as `not_observable` rather than inventing content. | M |

### 5.5 ESP/AH analysis
| ID | Requirement | Pri |
|---|---|---|
| FR-35 | The system shall track ESP and AH flows keyed by (src, dst, SPI, encapsulation). | M |
| FR-36 | The system shall analyse sequence numbers per flow: gaps, duplicates, reordering, wraparound proximity. | M |
| FR-37 | The system shall pair opposite-direction flows into candidate SA pairs by endpoint and timing and label as heuristic. | S |
| FR-38 | The system shall link ESP flows to IKE sessions by endpoint pair and time proximity with confidence ≤ 0.7. | S |
| FR-39 | The system shall run an ESP-NULL heuristic: after the 8-byte ESP header, test whether bytes form a valid IPv4 header (version 4, IHL ≥ 5, header checksum valid, total length ≤ packet remainder) in ≥ 90% of sampled packets of a flow; if so, flag "payload appears unencrypted" with confidence 0.85 and mode "tunnel (inferred)". | A |
| FR-40 | The system shall compute flow statistics: packets, bytes, duration, packet-size distribution, inter-arrival, rate. | M |
| FR-41 | The system shall report AH usage as an informational/low finding (no confidentiality; NAT-incompatible). | S |

### 5.6 Feature extraction
| ID | Requirement | Pri |
|---|---|---|
| FR-42 | The system shall produce a normalized "facts" document (sessions, observations, flows, notifies) as the sole input to rules and ML. | M |
| FR-43 | The system shall compute windowed behavioural features (default 10 s windows per initiator IP) per §11.2. | A |

### 5.7 Security rules
| ID | Requirement | Pri |
|---|---|---|
| FR-44 | The system shall load policy files (YAML), validate them against a schema, and refuse to start analysis with an invalid policy. | M |
| FR-45 | The system shall evaluate declarative rules (structured conditions, no `eval`) against observations/sessions. | M |
| FR-46 | The system shall evaluate detector rules (flood, scan, ESP sequence, ESP-NULL, negotiation-failure storm) implemented as Python plug-ins with configurable thresholds. | M |
| FR-47 | The system shall provide policy profiles: `nist_default`, `strict`, `legacy_tolerant`; users shall be able to select one per analysis. | S |
| FR-48 | Every finding shall carry ≥ 1 evidence record (packet number, field path, raw value, hex excerpt up to 64 bytes). | M |
| FR-49 | The system shall emit "coverage" notes listing assessments that could not be performed because data was encrypted or missing. | M |

### 5.8 Risk scoring
| ID | Requirement | Pri |
|---|---|---|
| FR-50 | Each finding shall have impact (1–5), likelihood (1–5), confidence (0.5–1.0) determined per §12.3. | M |
| FR-51 | Risk = impact×likelihood/25×100×(0.5+0.5×confidence); severity bands per §12.3. | M |
| FR-52 | Hard overrides: NULL encryption or DES selected ⇒ Critical regardless of formula. | M |
| FR-53 | The system shall compute an overall posture score (0–100) and grade (A–F) per §12.3. | M |
| FR-54 | The system shall deduplicate findings: one finding per (rule, session, parameter value) with a `count` and list of affected sessions. | M |

### 5.9 AI/ML and LLM
| ID | Requirement | Pri |
|---|---|---|
| FR-55 | The repository shall contain a reproducible training pipeline (feature extraction, scaling, Isolation Forest, evaluation report) that works on lab-generated captures. | A |
| FR-56 | The system shall score windows with the trained model and emit anomaly findings (max severity Medium; confidence ≤ 0.6). | A |
| FR-57 | Each anomaly finding shall list the top-3 features deviating from the baseline (z-score vs. training distribution). | A |
| FR-58 | If no model is present or windows < 20, the ML module shall report `unavailable`/`insufficient_data`; it shall never fabricate scores. | A |
| FR-59 | The model artifact shall carry metadata (version, training capture hashes, feature schema, metrics) and the schema shall be validated at load. | A |
| FR-60 | The system shall optionally generate an executive-summary narrative through an LLM provider (`none/ollama/openai_compat/anthropic`). | A |
| FR-61 | LLM input shall be sanitized structured findings only (no raw packets; IPs pseudonymized unless user opts in); output shall be schema-validated and cross-checked against finding IDs and numbers; invalid output is discarded. | A |
| FR-62 | When LLM is disabled/fails, a deterministic template summary shall be used. Narrative origin (`template`/`llm`) shall be displayed. | M |

### 5.10 Findings and recommendations
| ID | Requirement | Pri |
|---|---|---|
| FR-63 | Findings shall contain: id, rule/model id, title, severity, risk, impact, likelihood, confidence, explanation (why risky), evidence[], affected sessions, references, MITRE mapping (if defined), recommendation id. | M |
| FR-64 | The system shall provide recommendations from a catalogue (§12.5) with concrete target settings and a verification step. | M |
| FR-65 | The system shall produce a "fix first" ordering: sort by risk desc, then effort asc, then number of affected sessions desc; group findings fixed by the same recommendation. | S |
| FR-66 | The system shall map selected findings to MITRE ATT&CK techniques as *related techniques* where §12.4 defines a mapping. | A |
| FR-67 | The system shall extract IOCs (peer IPs, SPIs, vendor IDs, aggressive-mode IDs) with export. | A |
| FR-68 | The system shall present implementation fingerprint (from Vendor IDs) as informational and clearly labelled "self-reported by peer". | S |

### 5.11 Dashboard, search, compare
| ID | Requirement | Pri |
|---|---|---|
| FR-69 | The UI shall implement the screens in §13. | M |
| FR-70 | Tables shall support search, filter (severity, rule, protocol, IP, SPI) and sort, server-side paginated. | M |
| FR-71 | The finding detail view shall show evidence, hex excerpt and the standards reference. | M |
| FR-72 | The UI shall show an IKE handshake ladder diagram and a capture-wide timeline. | S |
| FR-73 | The UI shall show charts: severity distribution, protocol mix, ESP packets/time, risk by category. | M |
| FR-74 | The system shall compare two analyses (new/resolved/changed findings, posture delta). | A |

### 5.12 Reports and export
| ID | Requirement | Pri |
|---|---|---|
| FR-75 | The system shall generate an HTML report (self-contained, no external assets). | M |
| FR-76 | The system shall generate a PDF report from the same template. | M |
| FR-77 | The system shall export full results as JSON (documented schema, versioned). | M |
| FR-78 | The system shall export findings and IOCs as CSV. | S |
| FR-79 | Every report shall include methodology, observability limits and coverage notes. | M |
| FR-80 | Report generation shall be deterministic for identical inputs (excluding generation timestamp). | S |

### 5.13 Platform
| ID | Requirement | Pri |
|---|---|---|
| FR-81 | All results shall persist in the database (§10). | M |
| FR-82 | Authentication: optional static bearer token (`API_TOKEN` env). If set, all `/api/v1` calls except `/health` require it. Multi-user accounts are out of scope. | S |
| FR-83 | Errors shall use the standard envelope (§9.1) with stable machine-readable codes. | M |
| FR-84 | The system shall log structured events (upload, start, finish, failure) without logging packet payloads or identities. | M |
| FR-85 | `GET /api/v1/capabilities` shall return the implementation status (`implemented/partial/not_implemented`) of each feature, and the UI shall display it on an "About / Capabilities" panel. | M |
| FR-86 | The analyzer shall be usable standalone: `python -m analyzer analyze <file> --out result.json`. | M |
| FR-87 | Key-assisted decryption using user-supplied IKE/ESP keys (authorised lab captures only). | F |

---

## 6. Non-Functional Requirements

| ID | Category | Requirement (measurable) |
|---|---|---|
| NFR-01 | Performance | A 100 MB capture (≈ 150k packets mostly non-IPsec) shall complete analysis in ≤ 60 s on a 4-core/8 GB laptop *(target; measure and record in docs/benchmarks.md)*. |
| NFR-02 | Performance | API read endpoints p95 ≤ 500 ms for ≤ 10,000 findings/sessions with pagination. |
| NFR-03 | Scalability | Streaming parse: peak RSS ≤ 1 GB for a 500 MB capture; only IPsec-related packet metadata is retained. |
| NFR-04 | Scalability | Concurrent analyses limited by worker pool (default 2); extra jobs queue. Stateless API allows horizontal scaling later (Postgres + external queue = Future). |
| NFR-05 | Reliability | Malformed input must never crash the process: fuzz test of 10,000 mutated IKE packets with 0 unhandled exceptions. |
| NFR-06 | Reliability | Failed job records a failure reason; partial results are not presented as complete. |
| NFR-07 | Security | Upload hardening: size limit, magic-byte check, UUID storage, no shell-outs with user-controlled strings, parser bounds checks, CORS allow-list, security headers, rate limit on upload (default 10/min/IP). |
| NFR-08 | Security | Rule/policy files parsed with `yaml.safe_load`; no `eval/exec`. |
| NFR-09 | Security | Dependencies pinned; `pip-audit` and `npm audit` run in CI with no known critical vulnerabilities at release. |
| NFR-10 | Privacy | Captures may contain sensitive IPs/identities: stored locally only; LLM disabled by default; pseudonymization before any external LLM call; retention default 7 days, configurable; delete endpoint purges file + data. |
| NFR-11 | Usability | A new user shall go from upload to first finding in ≤ 3 clicks; every finding has a plain-language "why this matters". |
| NFR-12 | Explainability | 100% of findings reference evidence + rule/model id + formula inputs; ML findings show top deviating features. |
| NFR-13 | Maintainability | ≥ 80% line coverage on `analyzer/` (parsers, rules, scoring ≥ 90%); `ruff` + `mypy` clean; modules ≤ 500 lines. |
| NFR-14 | Availability | Single-node deployment; `/health` endpoint; restart-safe (jobs in `running` state on boot marked `failed: interrupted`). |
| NFR-15 | Compatibility | Python 3.11+; Chrome/Firefox/Edge latest two versions; Linux/macOS/Windows (via Docker) hosts. |
| NFR-16 | Correctness | Parser agreement with tshark on ≥ 99% of IKE header fields and transform IDs across the fixture corpus (CI gate when tshark is available). |
| NFR-17 | Accessibility | UI colour is never the sole severity indicator (icon + text label); keyboard navigable tables. |

---

## 7. System Architecture

### 7.1 High-level architecture
```
┌───────────────┐  HTTPS/JSON   ┌────────────────────────── backend (FastAPI) ───────────────────────┐
│ React SPA     │◀────────────▶│ API layer ─ Job orchestrator ─ Persistence (SQLAlchemy)              │
│ (dashboard)   │               │      │            │                                                │
└───────────────┘               │      │            ▼                                                │
                                │      │   ┌──────────── analyzer (library) ────────────┐            │
                                │      │   │ capture → classify → ike/esp → sessions    │            │
                                │      │   │ → features → rules+detectors → ML → scoring │            │
                                │      │   │ → recommend → enrich → (LLM narrative)     │            │
                                │      │   └────────────────────────────────────────────┘            │
                                │      ▼                                                             │
                                │  Report generator (Jinja2 + WeasyPrint) ── file store (uploads/)   │
                                └─────────────────────────────────────────────────────────────────────┘
                                        SQLite (MVP) / PostgreSQL (prod)
```

### 7.2 Component communication
- **Frontend ↔ Backend:** REST/JSON over HTTP; polling `GET /analyses/{id}` every 1 s for progress (no WebSocket needed).
- **Backend ↔ Analyzer:** in-process Python call `analyzer.pipeline.run(path, policy, options, progress_cb) -> AnalysisResult` executed in a worker thread/process pool (`concurrent.futures.ProcessPoolExecutor`, size = `WORKERS`). The analyzer has **no** dependency on FastAPI/SQLAlchemy.
- **Backend ↔ DB:** SQLAlchemy 2.0; results are written in one transaction after the analyzer returns (bulk insert) so partial results never appear complete.
- **Backend ↔ ML engine:** inside analyzer (`analyzer.ml.infer`) loading a joblib model once per worker.
- **Backend ↔ Report generator:** `reports.generator.render(analysis_id, fmt)` reads results from DB, renders Jinja2 HTML, optionally WeasyPrint PDF, stores file path in `reports`.
- **Backend ↔ LLM:** optional HTTP client in `analyzer.llm`, invoked after scoring.

### 7.3 Processing pipeline
```
 1 validate file
 2 stream packets (capture.reader)                          progress 0–40%
 3 decode L2/L3/L4, defragment IPv4                          
 4 classify: IKE | ESP | AH | NAT-T keepalive | other
 5 parse IKE messages (v1/v2) ; track ESP/AH packets
 6 reconstruct IKE sessions ; build ESP/AH flows             progress 40–60%
 7 build facts document (observations, sessions, flows)
 8 evaluate declarative rules + detectors                    progress 60–75%
 9 ML window scoring (if model)                              progress 75–85%
10 score findings → posture → recommendations → fix-first    progress 85–92%
11 enrich (vendor fingerprint, IOC, MITRE) ; narrative       progress 92–97%
12 persist ; mark completed                                  progress 100%
```

### 7.4 Security-analysis pipeline
`facts → (declarative rules → observation findings) + (detectors → behaviour findings) + (ML → anomaly findings) → dedupe → impact/likelihood/confidence → risk → severity (+overrides) → recommendation join → posture/grade → fix-first order`.

### 7.5 AI/ML pipeline
Offline: `lab captures → analyzer facts → windowed features → StandardScaler → IsolationForest → evaluation → joblib + metadata`.
Online: `facts → windows → scale → decision_function → normalized anomaly score → threshold → finding`.

---

## 8. Module Specifications

Common error handling: every module raises typed exceptions (`AnalyzerError` subclasses) carrying `code`, `message`, `context`; the orchestrator converts them to job failure or warnings (see FR-12, FR-83).

**M01 Upload & Validation (backend/app/services/uploads.py)**
- Purpose: accept and vet files. Input: multipart file, options. Processing: stream to temp file with size cap, read first 4–8 bytes for magic, SHA-256, move to `uploads/{uuid}.cap`. Output: `uploads` row. Deps: M17. APIs: `POST /analyses`. Errors: `FILE_TOO_LARGE`(413), `UNSUPPORTED_FILE_TYPE`(415), `EMPTY_FILE`(400).

**M02 Job Orchestrator (backend/app/services/jobs.py)**
- Purpose: run analyses without blocking the API. Input: analysis id. Processing: submit to process pool; progress callback updates `analyses.progress`; on exception set `failed` with reason; on boot mark stale `running` as `failed:interrupted`. Output: persisted result. Deps: analyzer, M17. Errors: `ANALYSIS_TIMEOUT`, `ANALYSIS_FAILED`.

**M03 Capture Reader (analyzer/capture/reader.py)**
- Purpose: iterate raw frames. Input: path. Processing: detect pcap/pcapng via magic; use Scapy `RawPcapReader`/`RawPcapNgReader` (raw bytes, no dissection); yield `(pkt_no, ts, linktype, bytes)`; handle per-interface linktype in pcapng; count truncated packets. Output: frame iterator + `CaptureMeta`. Errors: `CAPTURE_CORRUPT` (fatal only if no frame readable).

**M04 Decoder & Defragmenter (analyzer/capture/decode.py, defrag.py)**
- Purpose: L2→L4 decoding. Input: frame. Processing: strip L2 by linktype, VLAN tags; parse IPv4/IPv6 headers by hand with `struct` (or dpkt); IPv4 reassembly buffer (max 1,000 flows, 30 s timeout, 64 KB per datagram); UDP header parse. Output: `DecodedPacket{pkt_no, ts, src, dst, proto, sport, dport, ip_id, payload, frag_info}`. Errors: `DECODE_SKIPPED` (counted, not fatal).

**M05 Protocol Classifier (analyzer/classify/classifier.py)**
- Purpose: route packets. Processing: proto 50→ESP; 51→AH; UDP dport/sport in {500,4500}: on 4500, if first 4 bytes == 0 → strip marker → IKE; elif payload len==1 and byte==0xFF → keepalive; else if first 4 bytes != 0 → ESP-in-UDP; port 500 → IKE (a leading non-ESP marker on 500 is tolerated, flagged). IKE candidates validated: len ≥ 28, header length ≤ payload length (allow equal; if less, mark `trailing_data`), major version ∈ {1,2}, exchange type known. Optional (FR-18) non-standard port heuristic. Output: tagged packets + `ProtocolStats`.

**M06 IKE Parser (analyzer/ike/parser_v1.py, parser_v2.py, common.py, constants.py)**
- Purpose: bytes → typed `IkeMessage`. Processing: header; walk payload chain using next-payload/length with strict bounds; reject payload length < 4 or beyond message; critical bit handling; v2: SA→Proposals→Transforms (+ key length attribute type 14), KE(group, length), Nonce(length), Notify(protocol, SPI size, type, data), VendorID, Delete, CERTREQ(type), SK/SKF (opaque, mark encrypted), others opaque; v1: SA→Proposal→Transform→attributes (TV/TLV), KE, ID (type, value), HASH(length), Nonce, Notification, VID, NAT-D, CERT/CERTREQ; when v1 encryption flag set, remaining payloads opaque. Constants loaded from `constants.py` mirroring the IANA IKEv2 and IKE (v1) registries **(verify against IANA)**. Output: `IkeMessage`. Errors: `IKE_MALFORMED` (recorded as parse anomaly with offset; analysis continues).

**M07 IKE Session Reconstructor (analyzer/ike/sessions.py)**
- Purpose: group messages into sessions. Processing: v2 session key = (initiator_ip, SPI_i) where initiator is the sender with I-flag set; bind SPI_r when first response with non-zero SPI_r seen; v1 key = (cookie_i, cookie_r) with initiator = sender of first message; COOKIE retry: same SPI_i, new SA_INIT with COOKIE notify data → same session; INVALID_KE_PAYLOAD retry: same SPI_i → same session, record `ke_retries`. Retransmission detection by (direction, msg_id, exchange, hash(payload)). Compute `offered_proposals`, `selected_proposal`, `outcome`, `nat_detected`, `vendor_ids`, `notifies`, timeline. CREATE_CHILD_SA/INFORMATIONAL (encrypted) counted as `rekey_or_info_messages` (rekey cannot be distinguished from other CREATE_CHILD_SA — label accordingly). Output: `IkeSession[]`.

**M08 ESP/AH Tracker (analyzer/esp/tracker.py, ah.py, null_heuristic.py)**
- Purpose: flow metrics. Processing: per flow key maintain first/last ts, packets, bytes, seq stats (`max_seq`, gaps list [(from, to, pkt_no)], duplicates, reorders, wrap_near), size histogram, inter-arrival stats; pair reverse flows; link to IKE sessions by endpoint pair & overlap in time (if IKE session first_ts ≤ flow first_ts + tolerance); ESP-NULL heuristic per FR-39 on up to 50 packets per flow (retain first 50 payload prefixes of 64 bytes only). Output: `EspFlow[]`, `AhFlow[]`.

**M09 Feature Extractor (analyzer/features/)**
- Purpose: build `Facts` and ML windows. Processing: flatten sessions into `Observation[]`; compute window features (§11.2). Output: `Facts`, `WindowFeatures[]`.

**M10 Rule Engine (analyzer/rules/engine.py, conditions.py)**
- Purpose: evaluate declarative rules. Processing: load policy YAML (safe_load) → validate with pydantic schema → for each rule select targets (`observation|session|flow`), evaluate `when` condition tree (`all/any/not`, operators `eq,ne,in,not_in,gt,gte,lt,lte,exists,contains`), determine impact (default/by_value from policy tables), likelihood (from role mapping or explicit), group & dedupe, create `RawFinding` with evidence. Errors: `POLICY_INVALID` (fatal before analysis start).

**M11 Detectors (analyzer/rules/detectors/*.py)**
- Purpose: behavioural rules. Each detector: `def detect(facts, params) -> list[RawFinding]`. Detectors: `ike_init_flood`, `ike_scan`, `negotiation_failure_storm`, `cookie_absent_under_load`, `esp_sequence`, `esp_null`, `esp_without_ike`, `ah_usage`, `ike_protocol_anomaly`. Thresholds in policy YAML `params`.

**M12 ML Anomaly Engine (analyzer/ml/)**
- See §11. Input `WindowFeatures[]`; output anomaly `RawFinding[]` or `MlStatus{state: unavailable|insufficient_data|ok}`.

**M13 Scoring Engine (analyzer/scoring/risk.py, posture.py)**
- Pure functions per §12.3. Input `RawFinding[]`; output `Finding[]` + `Posture`. Deterministic; no I/O.

**M14 Recommendation Engine (analyzer/recommend/)**
- Join `recommendation_id` → catalogue entry; build fix-first list: group findings by recommendation, rank groups by max risk, then effort, then affected count. Output `Recommendation[]`.

**M15 Enrichment (analyzer/enrich/)**
- Vendor-ID fingerprint match; IOC extraction; MITRE mapping from `mitre.yaml`. Optional offline blocklist matching (user-supplied file; Future).

**M16 LLM Narrator (analyzer/llm/)**
- Template narrator always available; LLM narrator optional per FR-60/61. Output `Narrative{origin, text, key_points[]}`.

**M17 Persistence (backend/app/db/)**
- SQLAlchemy models/repositories; bulk insert; JSON columns for variable structures.

**M18 Report Generator (reports/generator.py)**
- Input: analysis id, format. Processing: load results → build context → render `report.html.j2` (charts as inline SVG generated by matplotlib `Agg` or hand-built SVG) → HTML or WeasyPrint PDF → store. Errors: `REPORT_RENDER_FAILED`, `ANALYSIS_NOT_COMPLETE`.

**M19 REST API (backend/app/api/v1/)** — §9.
**M20 Frontend (frontend/src/)** — §13.
**M21 Comparison Service (backend/app/services/compare.py)** — match findings by `fingerprint = hash(rule_id + normalized parameter)`; output new/resolved/unchanged/changed-severity and posture delta.
**M22 Lab & Fixtures (lab/, tests/fixtures/)** — Docker strongSwan topologies (hardened, weak), attack scripts for *own lab only*, byte-level IKE packet builders for fixtures (do not rely on Scapy's IKEv2 layer), dataset generator.

---

## 9. API Specification

Base path `/api/v1`. JSON UTF-8. Auth: `Authorization: Bearer <API_TOKEN>` if configured. Pagination: `?page=1&page_size=50` (max 200); list responses `{items, page, page_size, total}`.

### 9.1 Error envelope
```json
{"error": {"code": "UNSUPPORTED_FILE_TYPE", "message": "File is not a pcap/pcapng capture", "details": {}}}
```
Codes: `VALIDATION_ERROR`(422), `UNAUTHORIZED`(401), `NOT_FOUND`(404), `FILE_TOO_LARGE`(413), `UNSUPPORTED_FILE_TYPE`(415), `ANALYSIS_NOT_COMPLETE`(409), `ANALYSIS_FAILED`(500 on retrieval of failed), `RATE_LIMITED`(429), `INTERNAL_ERROR`(500).

> **Design change vs. the example list:** upload and analyze are one call (`POST /analyses`) because an upload without analysis has no use and two calls create orphan state.

| # | Method & endpoint | Purpose | Request | Success response | Errors |
|---|---|---|---|---|---|
| 1 | `POST /analyses` | Upload + start analysis | multipart: `file` (required), `policy` (`nist_default`\|`strict`\|`legacy_tolerant`, default `nist_default`), `enable_ml` (bool, default true), `enable_llm` (bool, default false), `redact_identities` (bool, default true) | **202** `{"analysis_id":"uuid","status":"queued"}` | 400, 413, 415, 422, 429 |
| 2 | `GET /analyses` | List analyses | `page,page_size,status` | 200 list of `{id, filename, status, created_at, posture_score, grade, finding_counts}` | 401 |
| 3 | `GET /analyses/{id}` | Status/progress/summary | — | 200 `{id,status,progress,stage,error?,filename,sha256,size,created_at,completed_at,policy,summary?}` | 404 |
| 4 | `DELETE /analyses/{id}` | Delete data+file | — | 204 | 404 |
| 5 | `GET /analyses/{id}/overview` | Dashboard summary | — | 200 `{capture:{packets,bytes,start,end,duration}, protocols:[{name,packets,bytes}], ipsec:{ike_v1_sessions,ike_v2_sessions,esp_flows,ah_flows,natt}, posture:{score,grade}, severity_counts, top_findings[5], narrative, coverage_notes[], warnings[]}` | 404, 409 |
| 6 | `GET /analyses/{id}/protocols` | Protocol/stat details | — | 200 `{distribution, top_talkers, ports, anomalies}` | 404, 409 |
| 7 | `GET /analyses/{id}/ike/sessions` | IKE session list | `version,outcome,ip,spi,q,page` | 200 list of session summaries (§10 `ike_sessions`) | 404, 409 |
| 8 | `GET /analyses/{id}/ike/sessions/{sid}` | Session detail | — | 200 `{session, messages[], observations[], notifies[], vendor_ids[], timeline[], findings[]}` | 404 |
| 9 | `GET /analyses/{id}/esp/flows` | ESP/AH flows | `ip,spi,proto,q,page` | 200 list with stats, seq gaps count, null_suspected, linked_ike_session | 404, 409 |
| 10 | `GET /analyses/{id}/esp/flows/{fid}` | Flow detail incl. seq/time series (downsampled ≤ 500 points) | — | 200 | 404 |
| 11 | `GET /analyses/{id}/timeline` | Capture-wide timeline events | `from,to` | 200 `[{ts,type,ref_id,label}]` | 404 |
| 12 | `GET /analyses/{id}/findings` | Findings list | `severity,rule_id,category,session_id,q,sort(risk\|severity\|rule),order,page` | 200 list (without full evidence) | 404, 409 |
| 13 | `GET /analyses/{id}/findings/{fid}` | Finding detail | — | 200 full finding with evidence (§9.2) | 404 |
| 14 | `GET /analyses/{id}/recommendations` | Fix-first list | — | 200 `[{rank, recommendation_id, title, steps[], verification, effort, risk_reduction, finding_ids[]}]` | 404, 409 |
| 15 | `GET /analyses/{id}/anomalies` | ML windows & scores | — | 200 `{ml_status, model:{version,metrics}, windows:[{start,end,src,score,flag,top_features[]}]}` | 404 |
| 16 | `GET /analyses/{id}/iocs` | IOCs | `format=json\|csv` | 200 | 404 |
| 17 | `POST /analyses/{id}/reports` | Generate report | `{"format":"pdf\|html\|json"}` | 201 `{report_id, format, created_at, download_url}` | 404, 409, 500 `REPORT_RENDER_FAILED` |
| 18 | `GET /reports/{report_id}/download` | Download | — | 200 file (`Content-Disposition: attachment`) | 404 |
| 19 | `GET /analyses/{id}/export` | Raw JSON results (schema-versioned) | `format=json\|findings_csv` | 200 | 404, 409 |
| 20 | `POST /compare` | Compare two analyses | `{"baseline_id","candidate_id"}` | 200 `{posture_delta, new[], resolved[], changed[], unchanged_count}` | 404, 409 |
| 21 | `GET /policies` | Policy profiles | — | 200 `[{id,name,description,rule_count}]` | — |
| 22 | `GET /rules` | Rule catalogue | `policy` | 200 rules with metadata | — |
| 23 | `GET /capabilities` | Implementation status (FR-85) | — | 200 `[{feature,status,notes}]` | — |
| 24 | `GET /health` | Liveness (no auth) | — | 200 `{status:"ok",version}` | — |

### 9.2 Finding detail response (normative example)
```json
{
  "id": "f_01H...",
  "rule_id": "CRY-DH-001",
  "title": "Weak Diffie-Hellman group negotiated: MODP-1024 (group 2)",
  "category": "cryptography",
  "severity": "high",
  "risk_score": 80.0,
  "impact": 4, "likelihood": 5, "confidence": 1.0,
  "scoring": {"formula": "4*5/25*100*(0.5+0.5*1.0)", "overridden": false},
  "explanation": "The responder selected a 1024-bit MODP group. Groups of this size are considered within reach of well-resourced attackers and are deprecated by current IPsec guidance.",
  "why_this_matters": "Session keys derived with this group may be recoverable by offline attacks on the recorded handshake.",
  "affected_sessions": ["s_01"],
  "count": 1,
  "evidence": [
    {"packet_no": 4, "ts": "2026-09-01T10:00:00.120Z", "message": "IKE_SA_INIT response", "field_path": "sa.selected_proposal.transforms[type=4].id", "raw_value": 2, "decoded": "MODP-1024", "hex_excerpt": "03 00 00 08 04 00 00 02", "note": "Selected by responder"}
  ],
  "references": ["RFC 7296", "RFC 8247 (verify current status of group 2)", "NIST SP 800-77r1"],
  "mitre": [],
  "recommendation_id": "REC-DH-STRONG",
  "origin": "rule"
}
```

---

## 10. Database Design

SQLite (MVP) via SQLAlchemy 2.0 with portable types so PostgreSQL works unchanged (`JSON` columns map to JSONB). UUID primary keys stored as `String(36)`. All tables have `created_at`. `ON DELETE CASCADE` from `analyses` down.

| Table | Fields (type) | Why stored |
|---|---|---|
| `uploads` | id PK; original_filename (str); stored_path (str); sha256 (str(64), idx); size_bytes (int); detected_format (str: pcap/pcapng); created_at | chain of custody; duplicate detection |
| `analyses` | id PK; upload_id FK; status (str idx); stage (str); progress (int); policy_id (str); policy_hash (str); options (JSON); error_code, error_message (str null); capture_meta (JSON: packets, bytes, start, end, linktypes, skipped); protocol_stats (JSON); posture_score (float null); grade (str null); severity_counts (JSON); narrative (JSON); coverage_notes (JSON); warnings (JSON); ml_status (JSON); analyzer_version (str); created_at, completed_at | job state + summary for list/dashboard |
| `ike_sessions` | id PK; analysis_id FK idx; version (int); spi_i, spi_r (str hex); initiator_ip, responder_ip (str); initiator_port, responder_port (int); natt (bool); first_ts, last_ts (datetime); outcome (str); exchange_types (JSON list); offered_proposals (JSON); selected_proposal (JSON); vendor_ids (JSON); notifies (JSON); retransmissions (int); ke_retries (int); message_count (int); parse_anomalies (JSON); aggressive_mode (bool); redacted_identity (JSON null) | session list/detail |
| `ike_messages` | id PK; session_id FK idx; analysis_id idx; packet_no (int); ts; direction (str i2r/r2i); exchange_type (int); flags (int); message_id (int); length (int); payload_types (JSON); encrypted (bool); parsed (JSON); is_retransmission (bool) | ladder diagram, evidence lookup |
| `ipsec_flows` | id PK; analysis_id FK idx; proto (str esp/ah); src_ip, dst_ip (str); spi (str hex); encap (str raw/natt); first_ts, last_ts; packets, bytes (int); seq_stats (JSON: max_seq, gaps[], duplicates, reorders, wrap_near); size_stats (JSON); iat_stats (JSON); series (JSON downsampled); null_suspected (bool); null_confidence (float); inferred_mode (str null); paired_flow_id (str null); linked_ike_session_id (str null); link_confidence (float null) | flow view, seq anomalies |
| `findings` | id PK; analysis_id FK idx; rule_id (str idx); origin (rule/detector/ml); category (str); title; severity (str idx); risk_score (float idx); impact (int); likelihood (int); confidence (float); scoring (JSON); explanation (text); why_this_matters (text); affected_sessions (JSON); count (int); references (JSON); mitre (JSON); recommendation_id (str); fingerprint (str idx) | core output; fingerprint enables comparison |
| `evidence` | id PK; finding_id FK idx; packet_no; ts; message (str); field_path; raw_value (JSON); decoded (str); hex_excerpt (str ≤ 192 chars); note | proof for each finding |
| `anomaly_windows` | id PK; analysis_id idx; window_start, window_end; src_ip; features (JSON); score (float); flagged (bool); top_features (JSON) | ML transparency |
| `iocs` | id PK; analysis_id idx; type (ip/spi/vendor_id/identity); value (str); context (str); first_seen | IOC export |
| `reports` | id PK; analysis_id idx; format; path; sha256; created_at | report registry |
| `timeline_events` | id PK; analysis_id idx; ts; type; ref_type; ref_id; label | timeline view |

**Indexes:** `findings(analysis_id, severity)`, `findings(analysis_id, risk_score DESC)`, `findings(fingerprint)`, `ike_sessions(analysis_id, outcome)`, `ipsec_flows(analysis_id, spi)`, `uploads(sha256)`.

**Example `ike_sessions` record**
```json
{"id":"s_01","analysis_id":"a_01","version":2,"spi_i":"a1b2c3d4e5f60718","spi_r":"0f1e2d3c4b5a6978","initiator_ip":"10.1.0.1","responder_ip":"203.0.113.9","natt":false,"outcome":"established_observed","exchange_types":[34,35],"offered_proposals":[{"num":1,"protocol":"IKE","transforms":[{"type":"ENCR","id":3,"name":"3DES","key_length":null},{"type":"PRF","id":2,"name":"HMAC_SHA1"},{"type":"INTEG","id":2,"name":"HMAC_SHA1_96"},{"type":"DH","id":2,"name":"MODP-1024"}]}],"selected_proposal":{"num":1,"transforms":[{"type":"ENCR","id":3,"name":"3DES"},{"type":"PRF","id":2},{"type":"INTEG","id":2},{"type":"DH","id":2}]},"vendor_ids":["strongSwan"],"retransmissions":0}
```

---

## 11. AI/ML Specification

### 11.1 Division of responsibility

| Task | Technique | Reason |
|---|---|---|
| Parsing, protocol identification, session reconstruction, scoring arithmetic | **Deterministic code** | Correctness required |
| Weak algorithms/groups, IKEv1, Aggressive Mode, protocol violations, ESP-NULL, sequence anomalies, flood/scan thresholds | **Rule-based** (declarative + detectors) | Standards-based, explainable, no training data needed |
| Unusual combinations of IKE behaviour rates in a time window | **ML (Isolation Forest, unsupervised)** | Not enumerable by rules; no labelled attack dataset exists |
| Executive summary prose | **LLM (optional)** over structured findings; template fallback | Language generation only; never decides severity |
| Recommendations text, MITRE mapping, remediation ordering | **Static catalogue + deterministic logic** | Must be accurate and auditable |

### 11.2 ML problem and features
**Problem:** unsupervised anomaly detection on IKE behaviour per (initiator_ip, 10 s window). **Features (all computed from facts):**
`init_req_count`, `init_resp_count`, `unanswered_ratio`, `distinct_dst_count`, `distinct_proposal_hash_count`, `notify_error_ratio`, `retransmit_ratio`, `cookie_notify_ratio`, `mean_msg_len`, `std_msg_len`, `v1_ratio`, `aggressive_mode_count`, `mean_inter_msg_gap_ms`, `session_count`.

### 11.3 Dataset (honest statement)
No labelled public IPsec-attack dataset is known to the authors. Therefore:
1. **Benign baseline:** generated in `lab/` with strongSwan (and optionally libreswan) containers: site-to-site and multi-client road-warrior, varied algorithms, short lifetimes to force rekeys, traffic via `ping`/`iperf3`/`curl`, NAT-T variant (iptables NAT between peers), restarts, DPD. Target ≥ 30 independent runs × ≥ 5 min.
2. **Misconfiguration runs:** mismatched proposals (produce NO_PROPOSAL_CHOSEN), wrong groups (INVALID_KE_PAYLOAD).
3. **Injected anomalies (authorised, own lab only):** `lab/attacks/ike_init_flood.py` (hand-built IKE_SA_INIT, spoofing disabled by default inside Docker network), `ike-scan` against the lab gateway (transform enumeration, multi-host sweep).
4. Wireshark SampleCaptures (ISAKMP/IPsec sections) used only as **functional fixtures**, never for training; check licence/availability **(verify)**.
5. All datasets documented in `docs/datasets.md` with capture SHA-256 and generation commands.

### 11.4 Preprocessing → model → training → evaluation
- Preprocessing: windowing, `StandardScaler` fitted on benign training windows only; windows with `init_req_count + init_resp_count == 0` skipped.
- Model: `sklearn.ensemble.IsolationForest(n_estimators=200, contamination="auto", random_state=42)`. Alternative baseline for comparison: robust z-score on key features (`median/MAD`).
- Training: benign windows only; threshold = 99th percentile of benign validation scores.
- Evaluation: **split by lab run** (not by window) to avoid leakage; report benign false-positive rate (held-out runs), recall on injected flood/scan windows, precision, ROC-AUC, and comparison against the rule detectors. Report must state: *evaluated on lab-generated data only; does not establish real-world accuracy*.
- Inference: windows ≥ 20 required for a capture, else `insufficient_data`. `anomaly_score = clip((threshold_score − raw_decision) / scale, 0, 1)`.
- Explanation: top-3 features by |z| versus the training mean/std, shown with values.
- Confidence: fixed cap 0.6 (0.5 if windows < 50).
- Risk: ML finding impact = 3, likelihood = `1 + round(4×anomaly_score)`, confidence as above ⇒ max risk 48 ⇒ **never above Medium**.

### 11.5 LLM specification
Provider interface `narrate(sanitized_findings) -> Narrative`. Prompt contains only: posture, counts, top-N findings (id, title, severity, plain explanation), recommendation titles. IPs replaced with `Peer-A/B…`. Output JSON schema `{executive_summary: str ≤ 250 words, key_points: [{finding_id, text}]}`; validation: all `finding_id` exist, any digits in text appear in source data, otherwise fallback to template. Disabled by default.

---

## 12. Security Rules Engine

### 12.1 Rule definition format (policy YAML)
```yaml
- id: CRY-DH-001
  name: Weak Diffie-Hellman group negotiated
  type: declarative                 # declarative | detector
  target: observation               # observation | session | flow
  when:
    all:
      - {field: kind, op: eq, value: dh}
      - {field: id, op: in, value: [1, 2, 5, 22, 25, 26]}
      - {field: role, op: in, value: [selected, offered]}
  impact: {table: dh_impact}        # lookup by observation.id from policy tables
  likelihood: {from: role}          # selected→5, offered→3, rejected→2
  confidence: 1.0
  group_by: [session_id, id, role]
  title: "Weak DH group {name} {role_phrase}"
  explanation: "…"
  why_this_matters: "…"
  evidence: [packet_no, field_path, raw_value, hex_excerpt]
  references: ["RFC 7296", "RFC 8247", "NIST SP 800-77r1"]
  recommendation_id: REC-DH-STRONG
  mitre: []
```

Policy tables (`default_nist.yaml`, impact 0 = acceptable): `dh_impact: {1:5, 2:4, 5:3, 22:3, 23:2, 24:2, 25:3, 26:3}`; `encr_impact: {DES:5, NULL:5, 3DES:3, RC5:3, IDEA:3, CAST:3, BLOWFISH:3}`; `prf_impact: {HMAC_MD5:2, HMAC_SHA1:1}`; `integ_impact: {HMAC_MD5_96:2, HMAC_MD5_128:2, HMAC_SHA1_96:1, HMAC_SHA1_160:1, DES_MAC:3, KPDK_MD5:3}`. Values are team design choices informed by RFC 8247/RFC 8221/NIST SP 800-131A/800-77r1 **(verify each against the current documents and record the citation in `docs/policy-rationale.md`)**. `strict` raises SHA-1 and AES-CBC-without-AEAD impacts; `legacy_tolerant` lowers 3DES/MODP-1536 impacts but never DES/NULL/MODP-768.

### 12.2 Rule catalogue (MVP set)

| Rule ID | Name | Condition | Impact | Likelihood | Conf. | Recommendation |
|---|---|---|---|---|---|---|
| CRY-DH-001 | Weak DH group | DH id in weak table; selected/offered | by table | role | 1.0 | REC-DH-STRONG |
| CRY-ENC-001 | Broken/obsolete cipher | ENCR DES/NULL/3DES/RC5/IDEA/CAST/Blowfish | by table | role | 1.0 | REC-ENC-AEAD |
| CRY-ENC-002 | Non-AEAD cipher in use (informational) | ENCR AES-CBC selected | 0→Info | 5 | 1.0 | REC-ENC-AEAD |
| CRY-INT-001 | Weak integrity/PRF/hash | kind ∈ {prf, hash, integ}: MD5/SHA-1/DES-MAC/KPDK | by table | role | 1.0 | REC-HASH-SHA2 |
| CRY-INT-002 | No integrity with non-AEAD cipher | IKEv2 proposal: INTEG none and ENCR not AEAD | 4 | role | 1.0 | REC-HASH-SHA2 |
| IKE-V1-001 | IKEv1 in use | any IKEv1 session | 2 | 5 | 1.0 | REC-IKEV2 |
| IKE-V1-002 | Aggressive Mode used | v1 exchange type 4 | 3 | 5 | 1.0 | REC-NO-AGGR |
| IKE-V1-003 | Aggressive Mode with PSK exposes hash | AM + auth method PSK(1) in transform + HASH payload in cleartext reply | 4 | 5 | 1.0 | REC-NO-AGGR |
| IKE-V1-004 | Excessive IKEv1 SA lifetime | lifetime attr > policy max (default 86400 s) | 2 | 5 | 1.0 | REC-LIFETIME |
| IKE-V1-005 | IKEv1 PSK authentication in use (hygiene; scores Low) | auth method PSK in selected transform | 1 | 5 | 1.0 | REC-CERT-AUTH |
| IKE-NEG-001 | Repeated NO_PROPOSAL_CHOSEN | ≥ 3 such notifies in 60 s per pair | 2 | 4 | 0.9 | REC-ALIGN-PROPOSALS |
| IKE-NEG-002 | Repeated INVALID_KE_PAYLOAD | ≥ 3 per pair | 2 | 4 | 0.9 | REC-ALIGN-PROPOSALS |
| IKE-NEG-003 | Unanswered handshakes | SA_INIT without response after retransmits ≥ 3 | 2 | 3 | 0.7 | REC-REACHABILITY |
| IKE-DOS-001 | SA_INIT flood | ≥ T init req/s from one source or ≥ T2 aggregate (defaults 50 / 200) sustained ≥ 3 s | 4 | 4 | 0.8 | REC-COOKIES-RATELIMIT |
| IKE-DOS-002 | No cookie challenge under load | during flood, responder sends full SA_INIT responses (KE present) and no COOKIE notify | 3 | 4 | 0.8 | REC-COOKIES-RATELIMIT |
| IKE-RECON-001 | IKE scanning pattern | one source → ≥ 5 distinct hosts on 500/4500 in 60 s, or ≥ 5 distinct single-transform proposals to one host without completion | 2 | 4 | 0.8 | REC-RESTRICT-EXPOSURE |
| IKE-PROTO-001 | Malformed IKE messages | parse anomalies ≥ 1 | 2 | 3 | 0.9 | REC-INVESTIGATE-PEER |
| IKE-PROTO-002 | KE length inconsistent with group | KE length ≠ expected for group | 3 | 4 | 0.9 | REC-INVESTIGATE-PEER |
| IKE-INFO-001 | Peer implementation fingerprint | Vendor ID match | Info | — | 0.8 | REC-PATCH-HYGIENE |
| IKE-INFO-002 | NAT-T in use | NAT detection / UDP 4500 | Info | — | 0.9 | — |
| ESP-NULL-001 | ESP payload appears unencrypted | FR-39 heuristic | 5 | 5 | 0.85 | REC-ENC-AEAD |
| ESP-SEQ-001 | Sequence gaps/duplicates | gap_ratio > 1% or any duplicate not explained by retransmit; reorders reported separately | 2 | 3 | 0.5–0.6 (capture loss possible) | REC-INVESTIGATE-PEER |
| ESP-SEQ-002 | Sequence near wrap without rekey | max_seq > 0xFFFFFF00 and no new SPI for same pair | 3 | 3 | 0.7 | REC-LIFETIME |
| ESP-NOIKE-001 | ESP without observed IKE | flow with ≥ 100 packets and no matching IKE session | 1 | 3 | 0.5 (capture may have started late; manual keying possible) | REC-CAPTURE-COMPLETE |
| AH-001 | AH in use | proto 51 seen | 1 | 5 | 1.0 | REC-ESP-ONLY |
| ML-ANOM-001 | Anomalous IKE behaviour window | ML flag | 3 | 1–5 | ≤ 0.6 | REC-INVESTIGATE-PEER |

**Removed from earlier idea:** PFS detection and ESP cipher identification — not observable without keys; reported only as coverage notes (FR-49).

### 12.3 Scoring methodology (normative)
1. **Impact (1–5):** 1 negligible, 2 minor/hygiene, 3 moderate (weakened but not practically broken), 4 serious (practically attackable by well-resourced adversary or exposes secrets for offline attack), 5 severe (no effective protection).
2. **Likelihood (1–5)** from exposure: `selected`=5 (in use), `observed behaviour`=4–5 (as per rule), `offered by initiator only`=3, `seen only in failed negotiation`=2.
3. **Confidence (0.5–1.0):** 1.0 = read directly from a complete cleartext field; 0.9 = aggregated across messages; 0.7 = cross-packet inference; 0.5–0.6 = heuristic/statistical.
4. **Risk** `R = impact × likelihood / 25 × 100 × (0.5 + 0.5 × confidence)` (0–100, one decimal).
5. **Severity bands:** Critical ≥ 85 · High 65–84.9 · Medium 35–64.9 · Low 15–34.9 · Info < 15 (or impact 0).
6. **Overrides:** NULL encryption or DES *selected* ⇒ Critical (R forced to 100); ESP-NULL heuristic ⇒ at least High.
7. **Posture score** `P = 100 × Π(1 − 0.6 × min(R_i, 95)/100)` over deduplicated findings with severity ≥ Low; caps: any Critical ⇒ P ≤ 39; any High ⇒ P ≤ 59. **Grade:** A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.
8. These weights are documented design decisions grounded in cited guidance, **not** a validated standard; they live in the policy file so organisations can tune them. Report states this.

Worked example: MODP-1024 selected: 4×5/25×100×(0.5+0.5×1.0) = **80.0 → High**. Offered only: 4×3/25×100 = 48 → Medium. 3DES selected: 3×5/25×100 = 60 → Medium. DES selected → Critical (override).

### 12.4 MITRE ATT&CK mapping (related techniques only, not observed attacks)
`IKE-RECON-001 → T1046 (Network Service Discovery)`; `IKE-DOS-001/002 → T1498 (Network Denial of Service)`; `IKE-V1-003 → T1110.002 (Password Cracking) — exposure enabling offline PSK attack`. No other rule is mapped; do not force mappings.

### 12.5 Recommendation catalogue (excerpt; full list in `analyzer/rules/policies/remediation.yaml`)

| ID | Recommendation | Effort | Verification |
|---|---|---|---|
| REC-DH-STRONG | Use DH group 14+ (MODP-2048 or larger) or ECP/Curve25519 groups 19/20/21/31; remove groups 1, 2, 5 | Low | Re-capture; selected DH id ∈ approved set |
| REC-ENC-AEAD | Use AES-GCM-128/256 or ChaCha20-Poly1305; remove DES/3DES/NULL | Low–Med | No weak ENCR in offered/selected |
| REC-HASH-SHA2 | Use SHA-256+ PRF/integrity; remove MD5/SHA-1 | Low | Same |
| REC-IKEV2 | Migrate IKEv1 peers to IKEv2 | Med | No IKEv1 sessions |
| REC-NO-AGGR | Disable Aggressive Mode; prefer certificates or IKEv2; if PSK unavoidable use long random PSK (≥ 20 chars) | Low | No exchange type 4 |
| REC-CERT-AUTH | Prefer certificate/EAP auth over PSK where operationally possible | High | (Config review; not verifiable from capture) |
| REC-LIFETIME | Set SA lifetimes per policy (e.g., IKE ≤ 24 h, child ≤ 1 h or volume-based) and ensure rekey | Low | Rekey observed |
| REC-COOKIES-RATELIMIT | Enable IKEv2 cookie challenge under load, rate-limit half-open SAs, restrict sources | Med | COOKIE notifies seen under load |
| REC-RESTRICT-EXPOSURE | Restrict UDP 500/4500 to known peers (ACL/firewall) | Low | Scan sources blocked |
| REC-ALIGN-PROPOSALS | Align proposals on both peers | Low | Handshake succeeds |
| REC-REACHABILITY | Check routing/firewall/NAT for UDP 500/4500 | Low | Responses observed |
| REC-INVESTIGATE-PEER | Investigate peer/implementation; collect logs | Med | — |
| REC-PATCH-HYGIENE | Confirm implementation version is supported and patched | Low | — |
| REC-ESP-ONLY | Prefer ESP with AEAD; avoid AH unless required | Low | No AH |
| REC-CAPTURE-COMPLETE | Capture from the beginning of the session including IKE | Low | IKE session present |

### 12.6 Example rules in full

**IKE-V1-003**
```yaml
- id: IKE-V1-003
  name: Aggressive Mode with pre-shared key exposes authentication hash
  type: declarative
  target: session
  when:
    all:
      - {field: version, op: eq, value: 1}
      - {field: exchange_types, op: contains, value: 4}
      - {field: selected.auth_method, op: eq, value: 1}       # PSK
      - {field: aggressive.hash_in_clear, op: eq, value: true}
  impact: {default: 4}
  likelihood: {fixed: 5}
  confidence: 1.0
  title: "IKEv1 Aggressive Mode with PSK between {initiator_ip} and {responder_ip}"
  explanation: "Aggressive Mode sends the peer identity and a hash derived from the pre-shared key unencrypted. An attacker who captured it can attempt offline guessing of the PSK."
  evidence: [ike.aggressive.reply_packet, ike.aggressive.id, ike.aggressive.hash_len]
  references: ["RFC 2409", "RFC 7296 (IKEv2 design rationale)", "NIST SP 800-77r1"]
  recommendation_id: REC-NO-AGGR
  mitre: [T1110.002]
```

**IKE-DOS-001 (detector)**
```yaml
- id: IKE-DOS-001
  name: IKE_SA_INIT flood
  type: detector
  detector: ike_init_flood
  params: {per_source_rps: 50, aggregate_rps: 200, min_duration_s: 3, window_s: 1}
  impact: {default: 4}
  likelihood: {fixed: 4}
  confidence: 0.8
  evidence: [first_packet, last_packet, peak_rate, source_count, response_ratio]
  recommendation_id: REC-COOKIES-RATELIMIT
  mitre: [T1498]
```

**ESP-NULL-001 (detector)** — see FR-39; evidence: three sample packets with parsed inner IPv4 header (src, dst, protocol, checksum valid) and the sampling ratio.

---

## 13. Frontend Specification

Stack: React 18 + TypeScript + Vite + Tailwind + Recharts + React Router + TanStack Query. All data from the API; **no mock data in production code paths** (a `?demo` fixture mode is forbidden). Empty/loading/error states required on every screen.

| # | Screen (route) | Components | Data displayed | User actions | API |
|---|---|---|---|---|---|
| 1 | Landing `/` | Hero, how-it-works, recent analyses table, capabilities panel link | Recent analyses, grade badges | Start new analysis, open analysis | 2, 23 |
| 2 | Upload `/new` | Drag-drop zone, policy select, options (ML on/off, LLM on/off, redact identities), size/type hints | — | Select file, choose options, submit | 1, 21 |
| 3 | Progress `/analyses/:id/progress` | Stepper (stages), progress bar, log of warnings | status, stage, progress | Wait (poll 1 s), cancel/delete | 3, 4 |
| 4 | Overview `/analyses/:id` | Posture gauge + grade, severity bar, protocol pie, IKE/ESP counters, top findings, narrative card (origin badge), coverage notes | overview | Click through to findings/sessions, generate report | 5 |
| 5 | Protocols `/analyses/:id/protocols` | Protocol distribution, top talkers table, ports, parse warnings | protocol data | Filter by IP/port | 6 |
| 6 | IKE `/analyses/:id/ike` | Session table (version, peers, outcome, DH/ENCR summary, vendor), filter bar | sessions | Search/filter/sort, open session | 7 |
| 7 | IKE session `/analyses/:id/ike/:sid` | Handshake ladder diagram, offered-vs-selected proposal comparison table (weak items highlighted with icon+text), notifies, vendor IDs, "not observable" panel listing encrypted parts, related findings | session detail | Click message → raw parsed fields/hex; click finding | 8 |
| 8 | ESP/AH `/analyses/:id/esp` | Flow table; flow detail drawer with seq-vs-time chart, size histogram, gap list, ESP-NULL indicator, linked IKE session (with confidence) | flows | Filter/sort, open | 9, 10 |
| 9 | Findings `/analyses/:id/findings` | Filterable table (severity chips, category, rule, text search), sort by risk | findings | Filter, sort, open | 12 |
| 10 | Finding detail `/analyses/:id/findings/:fid` | Header (severity, risk, impact×likelihood×confidence breakdown), explanation, why it matters, evidence list with hex viewer, references, MITRE chip (if any), recommendation card, affected sessions links | finding | Copy evidence, jump to packet info, open recommendation | 13 |
| 11 | Risk dashboard `/analyses/:id/risk` | Risk-by-category bar, severity distribution, scoring formula explainer, ML anomaly timeline (if ML ok) with threshold line and top features tooltip | findings agg, anomalies | Toggle categories | 12, 15 |
| 12 | Recommendations `/analyses/:id/fix-first` | Ranked list, effort/risk-reduction tags, steps, verification, linked findings | recommendations | Expand, export | 14 |
| 13 | Timeline `/analyses/:id/timeline` | Zoomable event timeline (IKE messages, rekeys, failures, flood windows) | timeline | Zoom/filter | 11 |
| 14 | Compare `/compare` | Two selectors; delta summary; new/resolved/changed tables | compare | Choose baseline/candidate | 20, 2 |
| 15 | Report `/analyses/:id/report` | Format picker, preview (HTML iframe, sandboxed), generate/download buttons, previous reports | reports | Generate, download | 17, 18 |
| 16 | Capabilities `/about` | Table of feature status | capabilities | — | 23 |

Global: header with API-token entry (stored in memory/sessionStorage only), toast errors from the standard envelope, severity shown as icon + label + colour, keyboard-accessible tables, responsive ≥ 1024 px (mobile best-effort).

---

## 14. Report Specification

Formats: **HTML** (self-contained), **PDF** (WeasyPrint from same template), **JSON** (schema-versioned). A4, header with title/analysis id/hash, page numbers (PDF).

| Section | Content |
|---|---|
| 1 Cover | Title, analysis id, capture filename and SHA-256, generation time, tool version, policy profile + hash |
| 2 Executive summary | Posture score/grade, severity counts, top 3–5 risks in plain language, fix-first top 3; narrative origin label (`template`/`LLM-generated, verify against findings`) |
| 3 Analysis metadata | Capture stats (packets, duration, linktypes), parse warnings, skipped packets, analyzer version |
| 4 VPN/IPsec inventory | Table of peers, IKE versions, sessions, outcomes, NAT-T, vendor fingerprints (labelled self-reported) |
| 5 IKE findings | Per finding: title, severity, risk, explanation, evidence table, recommendation id |
| 6 ESP/AH findings | Same, plus flow stats and seq chart |
| 7 Security findings summary | All findings sorted by risk, with scoring breakdown (impact, likelihood, confidence, formula) |
| 8 Anomaly analysis | ML status; flagged windows with top features; explicit statement of model limits |
| 9 Recommendations | Fix-first list with steps and verification |
| 10 IOCs | Table (type, value, context) |
| 11 Technical details | Selected algorithm tables (offered vs selected), handshake timelines, appendix of evidence hex |
| 12 Methodology | Scoring formula, severity bands, rule/ML/LLM roles, policy version |
| 13 Limitations & coverage | Observability boundary table (§2.5), items not assessed for this capture, capture-completeness caveat ("absence of findings is not proof of security"), unsupported encapsulations found, heuristic items marked |
| 14 References | RFCs, NIST, ATT&CK |

Identity values (IKEv1 AM IDs) are redacted by default (`ID type + first 2 chars + ***`).

---

## 15. Testing Requirements (summary; full plan in Document 5)

| Level | Requirement |
|---|---|
| Unit | pytest; parsers (header, payload chain, attributes, bounds), classifier, defrag, session builder, ESP seq logic, rule conditions, each rule, scoring, posture, recommendation ordering; ≥ 90% coverage for these |
| Integration | Pipeline on fixture PCAPs end-to-end (analyzer + DB persistence); tshark cross-validation (when installed) |
| API | `httpx` + FastAPI TestClient: all endpoints, error codes, pagination, auth on/off, rate limit |
| Frontend | Vitest + React Testing Library for components; Playwright for upload → findings → report flow |
| Security | Fuzzing (Hypothesis/mutation) of IKE/ESP/IP parsers; oversized/zip-bomb-like/corrupt files; path traversal in filename; XSS strings in IDs/vendor IDs rendered escaped; policy YAML with `!!python` tags rejected; dependency audit |
| ML | Schema validation, determinism (fixed seed), benign FPR and injected-anomaly recall on held-out lab runs; `unavailable/insufficient_data` behaviour |
| E2E | Scripted demo run on weak + hardened lab captures; assert expected findings list exactly |

**Sample test cases** (Actual Result is recorded at execution time; initial state **Not Run**)

| Test ID | Input | Expected result | Actual | Pass/Fail |
|---|---|---|---|---|
| TC-001 | `.txt` renamed `.pcap` | 415 `UNSUPPORTED_FILE_TYPE` | — | Not Run |
| TC-002 | `ikev2_modp1024_3des.pcap` (fixture) | Findings CRY-DH-001 (High, risk 80.0), CRY-ENC-001 (Medium, 60.0), both with packet #2 or #4 evidence | — | Not Run |
| TC-003 | `ikev2_modern_gcm_x25519.pcap` | No finding above Info; grade A | — | Not Run |
| TC-004 | `ikev1_aggressive_psk.pcap` | IKE-V1-001, IKE-V1-002, IKE-V1-003 present | — | Not Run |
| TC-005 | `natt_ikev2_esp.pcap` | IKE session `natt=true`; ESP flows `encap=natt`; keepalives counted | — | Not Run |
| TC-006 | `ike_init_flood.pcap` (lab) | IKE-DOS-001 raised; ML flags ≥ 1 window (if model present) | — | Not Run |
| TC-007 | `esp_seq_gaps.pcap` | ESP-SEQ-001 with confidence ≤ 0.6 | — | Not Run |
| TC-008 | `esp_null.pcap` | ESP-NULL-001 Critical/High; inferred mode "tunnel" | — | Not Run |
| TC-009 | Truncated pcap (cut mid-packet) | Analysis completes with warning; no crash | — | Not Run |
| TC-010 | 10,000 fuzzed IKE packets | 0 unhandled exceptions | — | Not Run |
| TC-011 | Two analyses before/after hardening | Compare shows resolved findings, posture delta > 0 | — | Not Run |
| TC-012 | Vendor ID payload containing `<script>` | Rendered as escaped text in UI and report | — | Not Run |

---

## 16. Deployment Specification

**16.1 Local (no Docker)**
```
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt -r analyzer/requirements.txt
cp .env.example .env
uvicorn backend.app.main:app --reload --port 8000
cd frontend && npm ci && npm run dev        # http://localhost:5173
```
WeasyPrint needs system libs (Pango/Cairo); on Debian/Ubuntu: `libpango-1.0-0 libpangoft2-1.0-0 libcairo2 fonts-dejavu-core`. tshark is **optional** (tests only).

**16.2 Environment variables (`.env.example`)**

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./data/ipsecscope.db` | Use `postgresql+psycopg://…` in prod |
| `UPLOAD_DIR` | `./data/uploads` | Capture storage |
| `REPORT_DIR` | `./data/reports` | Generated reports |
| `MAX_UPLOAD_MB` | `200` | Upload cap |
| `MAX_PACKETS` | `2000000` | Packet cap |
| `ANALYSIS_TIMEOUT_S` | `300` | Job timeout |
| `WORKERS` | `2` | Process pool size |
| `RETENTION_DAYS` | `7` | Purge job |
| `API_TOKEN` | *(empty = auth off)* | Bearer token |
| `CORS_ORIGINS` | `http://localhost:5173` | Allow-list |
| `DEFAULT_POLICY` | `nist_default` | Policy profile |
| `ML_MODEL_PATH` | `analyzer/ml/models/ike_iforest.joblib` | Missing ⇒ ML `unavailable` |
| `LLM_PROVIDER` | `none` | `none/ollama/openai_compat/anthropic` |
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` | *(empty)* | Provider settings |
| `LLM_SEND_REAL_IPS` | `false` | Must stay false unless user opts in |
| `LOG_LEVEL` | `INFO` | — |

**16.3 Docker (recommended demo path)**
`docker-compose.yml`: `backend` (python:3.11-slim + WeasyPrint libs, volume `./data`), `frontend` (multi-stage: node build → nginx serving `dist`, proxying `/api` to backend), optional `postgres:16` profile. `docker compose up --build` ⇒ UI on `http://localhost:8080`. Lab compose (`lab/docker-compose.lab.yml`) needs a Linux Docker host with `NET_ADMIN` and is separate.

**16.4 Hosting.** Free-tier PaaS (Render/Railway/Fly.io) can run the backend+frontend containers; ephemeral disks mean captures/reports are lost on restart — acceptable for demos, use a volume or Postgres + object storage for production. Do **not** host real sensitive captures on public free tiers.

**16.5 Production configuration.** Set `API_TOKEN`, restrict CORS, serve behind HTTPS reverse proxy (Caddy/nginx), set upload limits at the proxy as well, run containers as non-root, read-only root filesystem except `data/`, enable daily purge, back up the DB.
