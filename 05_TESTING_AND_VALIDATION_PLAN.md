# DOCUMENT 5 — TESTING & VALIDATION PLAN

Companion to `02_SRS_IPsecScope.md` §15. **Actual Result / Pass-Fail columns are intentionally "Not Run"**: they are filled during execution; nothing in this plan reports results that have not been produced.

---

## 1. Objectives and principles
1. Prove the analyzer parses real IPsec captures correctly (independent oracle: tshark).
2. Prove every rule fires on a positive fixture and stays silent on negative ones.
3. Prove scoring is deterministic and matches the documented formula.
4. Prove malformed/hostile input cannot crash or compromise the system.
5. Prove the app never presents unsupported claims (no cipher/PFS/AUTH claims; heuristics labelled).
6. **Golden files (`tests/fixtures/expected/*.json`) are derived by hand from the SRS formulas (shown in §3), never auto-generated from the analyzer's own output** — otherwise tests only prove self-consistency.

## 2. Levels, tools, gates

| Level | Tools | Scope | Gate |
|---|---|---|---|
| Unit | pytest, hypothesis | parsers, classifier, defrag, sessions, ESP seq, null heuristic, conditions, rules, scoring, prioritizer, narrator, LLM validator | `analyzer/` ≥ 80% line coverage; parsers/rules/scoring ≥ 90% |
| Integration | pytest | pipeline on fixtures; DB persistence; tshark cross-validation (skipped if absent) | golden outputs match; NFR-16 ≥ 99% |
| API | httpx/TestClient | all 24 endpoints, envelopes, pagination, auth on/off, rate limit | 100% endpoints covered |
| Frontend | Vitest + RTL; Playwright | components; upload→findings→report flow | flow passes in Chromium |
| Security | hypothesis fuzz, custom, `pip-audit`, `npm audit` | §7 checklist | all items pass |
| ML | pytest | feature schema, determinism, states, metrics from lab runs | state tests pass; metrics documented |
| E2E / demo | shell + Playwright | §6 scenario against Docker stack | completes ≤ 5 min |
| Performance | script | NFR-01..03 | measured, recorded |

## 3. Fixture corpus (`tests/fixtures/pcaps/`)

Built by `generate_fixtures.py` using byte-level builders (deterministic). Expected values computed with `R = I×L/25×100×(0.5+0.5×conf)`; bands Critical ≥ 85, High ≥ 65, Medium ≥ 35, Low ≥ 15, else Info. Engine rule: when the same (session, kind, id) is both *offered* and *selected*, one finding is reported with role `selected`.

| ID | File | Content | Expected findings (rule: risk → severity) | Posture |
|---|---|---|---|---|
| F01 | `ikev2_modern_gcm_x25519.pcap` | IKEv2 SA_INIT: AES-GCM-16 (256), PRF SHA2-256, DH 31, + ESP flows | IKE-INFO-001 (Info) only | 100 → A |
| F02 | `ikev2_modp1024_3des.pcap` | Offered = selected: 3DES, PRF HMAC_SHA1, INTEG HMAC_SHA1_96, DH 2 | CRY-DH-001: 80.0 High; CRY-ENC-001: 60.0 Medium; CRY-INT-001 (PRF): 20.0 Low; CRY-INT-001 (INTEG): 20.0 Low | (1−.48)(1−.36)(1−.12)(1−.12) ≈ 25.8 → F |
| F03 | `ikev2_offered_weak_selected_strong.pcap` | Initiator offers {3DES/SHA1/DH2} and {AES-CBC-256/SHA2-256/DH14}; responder selects second | CRY-DH-001 (offered, group 2): 48.0 Medium; CRY-ENC-001 (offered 3DES): 36.0 Medium; CRY-INT-001 (PRF SHA1 offered): 12.0 Info; CRY-ENC-002 (AES-CBC selected): Info | ≈ 55.8 → D |
| F04 | `ikev1_mainmode_psk.pcap` | Main Mode msgs 1–4 clear, 5–6 E-flag: AES-CBC, SHA1, PSK, group 2, lifetime 28800 | IKE-V1-001: 40.0 Medium; CRY-DH-001: 80.0 High; IKE-V1-005: 20.0 Low; CRY-INT-001 (hash SHA1): 20.0 Low; CRY-ENC-002 Info. **No** IKE-V1-004 | cap High ≤ 59 |
| F05 | `ikev1_aggressive_psk.pcap` | AM msgs 1–2 (ID + HASH clear), AES-CBC/SHA1/PSK/group 2 | IKE-V1-001 40.0 M; IKE-V1-002 60.0 M; IKE-V1-003 80.0 H; CRY-DH-001 80.0 H; IKE-V1-005 20.0 L; CRY-INT-001 20.0 L | cap High |
| F06 | `natt_ikev2_esp.pcap` | IKE on UDP/4500 with non-ESP marker, ESP-in-UDP both ways, 10 keepalives, strong crypto | IKE-INFO-002 Info; IKE-INFO-001 Info | 100 → A |
| F07 | `ikev2_cookie_retry.pcap` | SA_INIT → COOKIE notify → SA_INIT+COOKIE → response | one session, `cookie_used=true`; no findings above Info | A |
| F08 | `ikev2_invalid_ke_retry.pcap` | KE group 2 → INVALID_KE_PAYLOAD → retry group 14 | one session, `ke_retries=1`; CRY-DH-001 (offered): 48.0 Medium | ≈ 71 → C |
| F09 | `ikev2_no_proposal_chosen.pcap` | 5 SA_INIT answered by NO_PROPOSAL_CHOSEN within 60 s | IKE-NEG-001: 30.4 Low (2×4=8/25→32 ×0.95) | — |
| F10 | `lab_ike_init_flood.pcap` | 2,000 SA_INIT in 10 s from one source; full responses, no COOKIE | IKE-DOS-001: 57.6 Medium; IKE-DOS-002: 43.2 Medium (+ session-derived findings by construction: strong crypto ⇒ none) | — |
| F11 | `ikev1_scan_multihost.pcap` | One source → 12 hosts, Main Mode msg 1 with single AES/SHA2-256/PSK/group 14 transform varying only lifetime; no replies | IKE-RECON-001: 28.8 Low (8/25→32 ×0.9); IKE-V1-001: 40.0 Medium | — |
| F12 | `esp_seq_gaps.pcap` | 1,000 ESP packets, 3 gaps (15 missing total), 2 duplicates, 1 reorder; no IKE in capture | ESP-SEQ-001: 18.0 Low (conf 0.5); ESP-NOIKE-001: 9.0 Info | — |
| F13 | `esp_null.pcap` | Tunnel-mode ESP whose payload is plaintext IPv4/TCP (valid checksums) | ESP-NULL-001: 92.5 Critical (5×5→100 ×0.925); ESP-NOIKE-001 9.0 Info | cap Critical ≤ 39 |
| F14 | `ah_flow.pcap` | AH packets both directions | AH-001: 20.0 Low | — |
| F15 | `ikev2_malformed.pcap` | Header length > UDP payload; payload length lies; truncated transform | IKE-PROTO-001: 22.8 Low (2×3=6/25→24 ×0.95); no crash | — |
| F16 | `ikev2_ip_fragmented.pcap` | Large SA_INIT split into 3 IPv4 fragments (one out of order) | Same facts as the unfragmented equivalent; `reassembled=true` | — |
| F17 | `ikev2_des_md5_group1.pcap` | Selected: DES, PRF HMAC_MD5, INTEG HMAC_MD5_96, DH 1 | CRY-ENC-001 100.0 Critical (override); CRY-DH-001 100.0 Critical; CRY-INT-001 ×2: 40.0 Medium | ≤ 39 → F |
| F18 | `ikev2_unanswered.pcap` | SA_INIT + 3 retransmits, no reply | IKE-NEG-003: 20.4 Low (2×3=6/25→24 ×0.85) | — |
| F19 | `truncated.pcap` | Valid pcap cut mid-packet | completes with warning; frames before cut analysed | — |
| F20 | `not_a_pcap.txt` / `renamed.pcap` | Random text | upload rejected (415) | — |
| F21 | `ikev2_vendor_xss.pcap` | Vendor ID payload bytes `<script>alert(1)</script>` | IKE-INFO-001; rendered escaped everywhere | — |
| F22 | `benign_multiclient.pcap` | 5 clients, strong crypto, rekeys | no finding above Info; no ML flag | A |
| F23 | `pcapng_two_interfaces.pcapng` | pcapng with Ethernet + SLL interfaces | parses both; counts correct | — |
| F24 | `sll_linktype.pcap` | Linux cooked capture | parses | — |

Public captures (Wireshark SampleCaptures ISAKMP/IPsec sections) are used **only** for functional parsing smoke tests; check licence/availability **(verify)** and never for expected-score tests or ML training.

## 4. Test case catalogue

Status for all rows: **Not Run**. "Actual" filled at execution.

### 4.1 Upload, validation, parsing (unit/API)
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-001 | API | F20 | 415 `UNSUPPORTED_FILE_TYPE`; no file persisted | — | Not Run |
| TC-013 | API | empty file | 400 `EMPTY_FILE` | — | Not Run |
| TC-014 | API | > `MAX_UPLOAD_MB` | 413 `FILE_TOO_LARGE`; partial file deleted | — | Not Run |
| TC-015 | API | filename `../../etc/passwd.pcap` | stored under UUID; original name sanitized in metadata | — | Not Run |
| TC-016 | Unit | each magic number (4 pcap variants + pcapng) | detected format correct | — | Not Run |
| TC-009 | Integration | F19 | status `completed`, warning "truncated", frames before cut parsed | — | Not Run |
| TC-017 | Unit | F23 | both interfaces' linktypes honoured | — | Not Run |
| TC-018 | Unit | F24 | SLL decoded, IKE found | — | Not Run |
| TC-019 | Unit | F16 | message reassembled; IKE parsed; `reassembled=true` | — | Not Run |
| TC-020 | Unit | fragments overlapping/oversized | discarded, warning, no crash, memory bounded | — | Not Run |

### 4.2 IKE/ESP analysis
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-021 | Integration | F01, F02, F04, F05 | session count, version, exchange types, offered/selected exactly as hand-written in `expected/*.facts.json` | — | Not Run |
| TC-022 | Integration | F01–F18 vs tshark | header fields + transform IDs agreement ≥ 99% (skip if no tshark) | — | Not Run |
| TC-005 | Integration | F06 | `natt=true`; ESP `encap=natt`; keepalives = 10 | — | Not Run |
| TC-023 | Unit | F07 | single session; cookie used; no retransmission miscount | — | Not Run |
| TC-024 | Unit | F08 | single session; `ke_retries=1` | — | Not Run |
| TC-025 | Unit | F04 | messages 5–6 `encrypted=true`, no parsed payloads | — | Not Run |
| TC-026 | Unit | F05 | AM ID type/value (redacted form) and HASH length extracted | — | Not Run |
| TC-027 | Unit | IKEv2 fixture with SK payload | `encrypted_not_observable` lists IKE_AUTH identities & child SA | — | Not Run |
| TC-007 | Unit | F12 | gaps = 3, duplicates = 2, reorders = 1 | — | Not Run |
| TC-008 | Unit | F13 | `null_suspected=true`, conf 0.85, mode "tunnel (inferred)" | — | Not Run |
| TC-028 | Unit | 1,000 random-payload ESP flows | 0 flagged as NULL (report observed false-positive count) | — | Not Run |
| TC-029 | Unit | F14 | AH flow, no ESP flow | — | Not Run |
| TC-030 | Unit | F15 | anomalies recorded; analysis continues | — | Not Run |
| TC-010 | Security | 10,000 hypothesis-mutated IKE/ESP/IP packets | 0 unhandled exceptions; every failure recorded as anomaly | — | Not Run |

### 4.3 Rules and scoring
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-002 | Integration | F02 | exactly the 4 findings and scores in §3 | — | Not Run |
| TC-003 | Integration | F01 | no finding above Info; grade A | — | Not Run |
| TC-004 | Integration | F05 | IKE-V1-001/002/003 present with scores in §3 | — | Not Run |
| TC-031 | Integration | F03 | offered-only weak items scored with likelihood 3 | — | Not Run |
| TC-032 | Integration | F17 | overrides ⇒ Critical 100.0; posture ≤ 39 | — | Not Run |
| TC-033 | Integration | F09 | IKE-NEG-001 = 30.4 | — | Not Run |
| TC-006 | Integration | F10 | IKE-DOS-001 = 57.6, IKE-DOS-002 = 43.2 | — | Not Run |
| TC-034 | Integration | F11 | IKE-RECON-001 = 28.8; MITRE T1046 shown as "related technique" | — | Not Run |
| TC-035 | Integration | F18 | IKE-NEG-003 = 20.4 | — | Not Run |
| TC-036 | Integration | F22 | no finding above Info; no false flood/scan | — | Not Run |
| TC-037 | Unit | scoring boundaries | 14.9→Info, 15.0→Low, 34.9→Low, 35.0→Medium, 64.9→Medium, 65.0→High, 84.9→High, 85.0→Critical | — | Not Run |
| TC-038 | Property | random impact/likelihood/confidence | R in [0,100]; monotonic; posture in [0,100]; caps enforced | — | Not Run |
| TC-039 | Unit | each MVP rule (SRS §12.2) | positive fixture fires; negative fixture does not | — | Not Run |
| TC-040 | Unit | policy files | strict ≥ default ≥ legacy in severity for the same input; DES/NULL/MODP-768 never downgraded by legacy | — | Not Run |
| TC-041 | Unit | invalid policy (unknown key, `!!python/object`) | rejected with `POLICY_INVALID` | — | Not Run |
| TC-042 | Unit | recommendations | fix-first order = risk desc, effort asc, affected desc | — | Not Run |
| TC-043 | Unit | rule titles with unknown placeholders | no exception; empty substitution | — | Not Run |

### 4.4 Compare, reports, exports
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-011 | API | baseline F02, candidate F01 | resolved: CRY-DH-001, CRY-ENC-001, CRY-INT-001 (2); posture delta ≈ +74 | — | Not Run |
| TC-044 | Integration | report HTML for F02 | contains sections 1–14 (SRS §14), evidence for each finding, limitations table, formula | — | Not Run |
| TC-045 | Integration | PDF for F02 | file generated, ≥ 1 page, text extractable, contains posture grade | — | Not Run |
| TC-046 | Integration | JSON export | validates against schema; schema version present | — | Not Run |
| TC-047 | Unit | CSV exports | round-trips; formula-injection characters (`=`,`+`,`-`,`@`) prefixed with `'` | — | Not Run |
| TC-048 | Integration | identity redaction | AM ID redacted by default; shown only if `redact_identities=false` | — | Not Run |

### 4.5 ML/LLM
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-049 | Unit | no model file | `ml_status.state="unavailable"`; no ML findings; UI shows honest message | — | Not Run |
| TC-050 | Unit | capture with < 20 windows | `insufficient_data` | — | Not Run |
| TC-051 | Unit | feature schema drift (model expects 14 features, code supplies 13) | model load rejected | — | Not Run |
| TC-052 | ML | trained model, held-out benign lab runs | benign window FPR reported (target ≤ 5%, record actual) | — | Not Run |
| TC-053 | ML | held-out injected flood/scan windows | recall reported (target ≥ 80%, record actual); caveat text present in `docs/ml-evaluation.md` | — | Not Run |
| TC-054 | Unit | ML finding scoring | risk ≤ 48; severity ≤ Medium; top-3 features present | — | Not Run |
| TC-055 | Unit | determinism | same input + model ⇒ identical scores | — | Not Run |
| TC-056 | Unit | LLM output with unknown finding_id or altered number | rejected; template summary used; origin = `template` | — | Not Run |
| TC-057 | Unit | LLM prompt payload | contains no raw IPs/hex; pseudonyms present | — | Not Run |

### 4.6 Frontend and E2E
| ID | Level | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| TC-058 | Playwright | upload F02 via UI | progress → overview; counts equal API; grade F shown | — | Not Run |
| TC-059 | Playwright | open CRY-DH-001 | evidence list shows packet number, field path, hex; reference shown | — | Not Run |
| TC-060 | Playwright | session detail F04 | encrypted portions displayed as "not observable" | — | Not Run |
| TC-061 | Playwright | filter findings by severity=high and search "DH" | server-side filtered list correct | — | Not Run |
| TC-012 | Playwright | F21 | `<script>` text appears escaped in UI and report; no script executes | — | Not Run |
| TC-062 | Playwright | generate PDF + HTML from report page | both download | — | Not Run |
| TC-063 | Playwright | failed analysis (corrupt file) | failed screen shows `error_code`; no stack trace | — | Not Run |
| TC-064 | Playwright | capabilities page | statuses equal `/capabilities`; ML shows `partial/not_implemented` if no model | — | Not Run |
| TC-065 | Playwright | keyboard-only navigation of findings table | all actions reachable; severity not colour-only | — | Not Run |
| TC-066 | E2E | demo script §6 | completes ≤ 5 min, all expected findings visible | — | Not Run |

### 4.7 Performance
| ID | Input | Expected | Actual | Pass/Fail |
|---|---|---|---|---|
| TC-067 | 100 MB mixed capture (mostly non-IPsec) | ≤ 60 s on 4-core/8 GB (NFR-01); record real number | — | Not Run |
| TC-068 | 500 MB capture | peak RSS ≤ 1 GB (NFR-03) | — | Not Run |
| TC-069 | 10,000 findings seeded via test data | list endpoint p95 ≤ 500 ms (NFR-02) | — | Not Run |

## 5. Acceptance criteria (release gate)
1. All **Must** FRs pass their tests, or are listed `partial/not_implemented` in `/capabilities` with documented reasons.
2. TC-002..TC-008, TC-021..TC-036 pass (golden fixtures).
3. TC-010/fuzz: 0 unhandled exceptions in 10,000 cases; TC-022 ≥ 99% agreement (if tshark available; otherwise record "not measured").
4. Security checklist (§7) fully passed.
5. Coverage gates met; lint/type checks clean.
6. Demo scenario (§6) passes on a fresh Docker deployment.
7. No P1/P2 defects open.

## 6. Demo scenario (4–5 minutes) and validation of the live system

**Data:** use **authorised** sources only: (a) fixtures F02 (weak), F01 (hardened), F10 (flood, lab-generated), optionally F05; (b) if the Docker lab ran: real strongSwan weak/hardened captures. Never demo with captures you are not authorised to analyse.

| Time | Action | What judges should see |
|---|---|---|
| 0:00–0:30 | Problem framing slide: manual Wireshark vs our passive assessment; the observability boundary table | Honest scope |
| 0:30–1:00 | Upload `weak` capture (F02/lab) with `nist_default` | Progress stages, then overview |
| 1:00–1:45 | Overview: protocols, IKE sessions, posture gauge (F), severity counts, narrative with "template" badge | Automatic IPsec/IKE/ESP identification |
| 1:45–2:30 | Open CRY-DH-001: evidence (packet #, field path, hex), formula breakdown 4×5/25×100×1.0 = 80.0, why-it-matters, RFC/NIST references, recommendation | Evidence + explainable scoring |
| 2:30–3:00 | IKE session detail: ladder diagram, offered-vs-selected table, "not observable" panel (IKE_AUTH, ESP cipher) | Technical depth and honesty |
| 3:00–3:40 | Upload flood capture F10: IKE-DOS-001/002 findings, timeline spike, ML anomaly panel with top deviating features (if model exists; otherwise show honest "unavailable") | Behavioural detection |
| 3:40–4:15 | Compare weak vs hardened: resolved findings, posture delta; fix-first list | Actionable value |
| 4:15–4:45 | Generate and open PDF report (executive summary, evidence, limitations section) | Deliverable |
| 4:45–5:00 | Capabilities page and closing | Transparency |

Rehearsal checklist: pre-load fixtures; keep a recorded fallback; verify WeasyPrint in the demo environment; avoid external network dependencies.

## 7. Security testing checklist (NFR-07..NFR-10)

| # | Check | Method |
|---|---|---|
| S-01 | Magic-byte validation independent of extension | TC-001/016 |
| S-02 | Upload size enforced during streaming, not after | oversize test, memory observed |
| S-03 | UUID storage; filename never used in paths | TC-015 |
| S-04 | Parser bounds checks | fuzz TC-010 + malformed fixtures |
| S-05 | Defrag memory/time bounded | TC-020 |
| S-06 | YAML `safe_load` only; malicious tags rejected | TC-041 |
| S-07 | No `eval/exec/subprocess` with user data | `grep` + bandit |
| S-08 | XSS: all user-derived strings escaped in UI and Jinja2 (autoescape on) | TC-012 |
| S-09 | Report iframe sandboxed; `Content-Disposition: attachment` downloads; `X-Content-Type-Options: nosniff` | manual + test |
| S-10 | CSV formula injection mitigated | TC-047 |
| S-11 | Auth enforced when `API_TOKEN` set; `/health` open | API tests |
| S-12 | CORS allow-list; no wildcard | test |
| S-13 | Rate limit on upload | API test |
| S-14 | Error envelopes leak no paths/stack traces | test |
| S-15 | LLM disabled by default; payload sanitized | TC-056/057 |
| S-16 | Dependency audits clean at release | `pip-audit`, `npm audit` |
| S-17 | Containers non-root; secrets only via env | Docker inspection |
| S-18 | Lab attack script refuses non-lab/non-RFC1918 targets | unit test |

## 8. Claim validation (what the product may and may not state)

| Claim | Allowed? | Basis |
|---|---|---|
| "IKEv2 negotiated MODP-1024 and 3DES (selected)" | Yes | Cleartext IKE_SA_INIT, tested vs tshark |
| "Peer offered weak group X" | Yes (likelihood 3) | Initiator proposal |
| "Tunnel uses AES-256 for ESP" | **No** | ESP cipher not observable without keys |
| "PFS is enabled/disabled" | **No** | Child SA proposals encrypted |
| "Tunnel mode" | Only as "tunnel (inferred)" for ESP-NULL heuristic; otherwise "unknown" | Heuristic |
| "Peer runs strongSwan x.y" | Only as "peer-reported vendor ID" | Vendor ID payload self-reported |
| "Attack detected" for floods/scans | As "pattern consistent with…" with confidence 0.8 | Thresholds |
| "ML detected anomaly" | As "statistical outlier vs lab baseline", confidence ≤ 0.6 | Unsupervised model, lab-trained |
| "VPN is secure" | **Never**; absence of findings is not proof | Capture completeness |

## 9. Defect handling and exit criteria
P1 crash/data loss/security flaw · P2 wrong finding/score/parse · P3 UI/usability · P4 cosmetic. Exit: zero P1/P2 open, P3 triaged, benchmark and ML evaluation documents committed with real numbers.

## 10. Traceability (excerpt)
| Requirement | Tests |
|---|---|
| FR-02 | TC-001, TC-016 |
| FR-11 | TC-019, TC-020 |
| FR-14..FR-17 | TC-005, TC-029 |
| FR-23/24 | TC-021, TC-022, TC-025 |
| FR-30..FR-32 | TC-023, TC-024, TC-035 |
| FR-36 | TC-007 |
| FR-39 | TC-008, TC-028 |
| FR-45/46 | TC-039 |
| FR-50..FR-54 | TC-037, TC-038, TC-032 |
| FR-55..FR-59 | TC-049..TC-055 |
| FR-60..FR-62 | TC-056, TC-057 |
| FR-74 | TC-011 |
| FR-75..FR-80 | TC-044..TC-048 |
| NFR-01..03 | TC-067..TC-069 |
| NFR-05 | TC-010 |
