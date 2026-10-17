# DOCUMENT 4 — DEVELOPMENT TASK LIST

Execute in ID order unless dependencies allow parallel work. "SRS" refs are to `02_SRS_IPsecScope.md`; "SPEC" refs to `03_ANTIGRAVITY_IMPLEMENTATION_SPEC.md`. A task is done only when its acceptance criteria pass **and** the full test suite is green.

---

## PHASE 1 — Foundation

**TASK-001 Repository skeleton**
- Objective: create layout (SPEC §3), tooling (ruff, mypy, pytest, pre-commit), Makefile (`make test`, `make lint`, `make run`, `make fixtures`).
- Files: root files, `analyzer/__init__.py`, `backend/app/main.py`, `tests/`.
- Deps: none. Output: installable project. Acceptance: `make test` runs (0 tests ok), `make lint` clean.

**TASK-002 Config and capabilities registry**
- Objective: `analyzer/config.py` (limits, thresholds defaults), `analyzer/capabilities.py` (feature status list), `backend/app/config.py` (env vars from SRS §16.2).
- Deps: 001. Output: typed settings, capabilities list. Acceptance: unit test loads defaults and overrides from env; every FR with priority A/F has an entry.

**TASK-003 Database models and session**
- Objective: SQLAlchemy models for all SRS §10 tables; `create_all` on startup; repository helpers.
- Files: `backend/app/db/{base,models,repositories}.py`. Deps: 001–002. Acceptance: tests create/read/delete cascade on SQLite; schema valid for PostgreSQL (`CreateTable` compile test).

**TASK-004 FastAPI app shell**
- Objective: app factory, error envelope, security headers, CORS, `/health`, `/capabilities`, optional bearer auth (FR-82, FR-83, FR-85).
- Files: `backend/app/{main,deps}.py`, `core/{errors,security,logging}.py`, `api/v1/meta.py`. Deps: 002–003. Acceptance: API tests for 200/401/404/422 envelopes; auth on/off.

**TASK-005 Frontend shell**
- Objective: Vite+React+TS+Tailwind, router with all 16 routes as empty states, API client with envelope handling, token entry, capabilities page wired to API.
- Files: `frontend/src/**`. Deps: 004. Acceptance: `npm run build` and lint pass; Capabilities page displays real API data.

**TASK-006 Docker skeleton + CI script**
- Objective: Dockerfiles, compose, `.env.example`. Deps: 004–005. Acceptance: `docker compose up --build` serves UI and `/health`.

---

## PHASE 2 — Core analyzer

**TASK-007 Capture reader**
- Objective: stream pcap (µs/ns, both endians) and pcapng (multiple interfaces) frames; capture metadata; truncation tolerance (FR-08, FR-12).
- Files: `analyzer/capture/{reader,linktypes}.py`. Deps: 001. Output: frame iterator. Acceptance: reads all fixture formats; truncated file yields frames before cut + warning; memory constant (test with 200 MB synthetic file ≤ 300 MB RSS).

**TASK-008 L2–L4 decoder**
- Objective: Ethernet, VLAN/QinQ, SLL/SLL2, raw, loopback; IPv4/IPv6 (ext headers); UDP (FR-09, FR-10).
- Files: `capture/decode.py`. Deps: 007. Acceptance: unit tests per link type with handcrafted frames; unsupported link type reported once.

**TASK-009 IPv4 defragmentation**
- Objective: reassemble with bounds/timeouts (FR-11).
- Files: `capture/defrag.py`. Deps: 008. Acceptance: fragmented IKE message (large cert-bearing SA_INIT fixture) reassembles; overlapping/oversized fragments discarded safely; memory cap enforced.

**TASK-010 Protocol classifier + capture statistics**
- Objective: SPEC §5.1; protocol distribution, top talkers, ports (FR-13..FR-17, FR-19).
- Files: `classify/classifier.py`, `features/facts.py` (stats part). Deps: 008–009. Acceptance: counts of IKE/ESP/AH/keepalive on each fixture equal expected JSON and tshark counts (when available).

**TASK-011 Fixture builders**
- Objective: byte-level builders for IKEv1/IKEv2 messages (header, SA proposals/transforms, KE, nonce, notify, VID, ID, HASH, SK stub), ESP/AH packets, NAT-T encapsulation, fragmentation, pcap writer; `generate_fixtures.py` creating the corpus listed in Document 5 §3 with `expected/*.json`.
- Files: `tests/fixtures/{builders,generate_fixtures}.py`. Deps: 007. Acceptance: `make fixtures` regenerates identical files (deterministic seeds); `tshark -r` can dissect each IKE fixture without malformed-packet errors (when tshark available).

**TASK-012 CLI + pipeline skeleton**
- Objective: `python -m analyzer analyze file --out result.json`; `pipeline.run` with progress callbacks, limits (FR-07, FR-86).
- Files: `analyzer/{pipeline,__main__,models,errors}.py`. Deps: 007–010. Acceptance: CLI on each fixture outputs valid JSON with capture stats; limits produce typed errors.

---

## PHASE 3 — IPsec analyzer

**TASK-013 IKE constants and common helpers**
- Files: `ike/{constants,common}.py`. Deps: 001. Acceptance: tests cover name lookups, `UNKNOWN(n)` fallback, AEAD set, expected KE lengths.

**TASK-014 IKEv2 parser**
- Objective: FR-20, FR-21, FR-23, FR-25, FR-26, FR-27, FR-28, FR-34.
- Files: `ike/parser_v2.py`. Deps: 013, 011. Acceptance: all v2 fixtures parse to expected proposals/transforms/notifies; payload length lies produce anomalies not exceptions; SK payload marked encrypted.

**TASK-015 IKEv1 parser**
- Objective: FR-22, FR-24, FR-29, FR-34 (TV/TLV attributes, Main/Aggressive handling).
- Files: `ike/parser_v1.py`. Deps: 013, 011. Acceptance: v1 fixtures parse; E-flag messages are opaque; aggressive-mode ID/hash extracted; identity redaction function tested.

**TASK-016 Parser fuzzing and tshark cross-validation**
- Objective: Hypothesis/mutation fuzz (10,000 cases) and tshark field comparison (NFR-05, NFR-16).
- Files: `tests/security/test_fuzz_ike.py`, `tests/integration/test_tshark_crossval.py`. Deps: 014–015. Acceptance: 0 unhandled exceptions; agreement ≥ 99% on header fields and transform IDs; skipped cleanly without tshark.

**TASK-017 IKE session reconstruction**
- Objective: FR-30..FR-33 per SPEC §5.5; timelines; encrypted_not_observable lists.
- Files: `ike/sessions.py`. Deps: 014–015. Acceptance: COOKIE and INVALID_KE retry fixtures stay one session; retransmission count correct; outcomes classified as expected.

**TASK-018 Vendor ID fingerprinting**
- Files: `ike/vendor_ids.py`, `enrich/fingerprint.py`. Deps: 014. Acceptance: strongSwan-fixture VID matched; unknown VID displayed as hex; match labelled "self-reported".

**TASK-019 ESP/AH tracker**
- Objective: FR-35, FR-36, FR-40, FR-41 per SPEC §5.6.
- Files: `esp/{tracker,ah}.py`. Deps: 010. Acceptance: gap/duplicate/reorder fixture yields exact expected counts; wrap-near flagged; memory bounded.

**TASK-020 ESP-NULL heuristic**
- Files: `esp/null_heuristic.py`. Deps: 019. Acceptance: ESP-NULL fixture flagged (conf 0.85); AES-encrypted fixture (random bytes) not flagged across 1,000 random flows (false-positive count 0 expected, report observed).

**TASK-021 Flow pairing and IKE linking**
- Files: `esp/linking.py`. Deps: 017, 019. Acceptance: linked fixture shows `link_confidence ≤ 0.7`; unlinked flows reported `None`.

**TASK-022 Facts builder**
- Objective: flatten sessions to Observations, build `Facts` incl. unsupported/warning lists, coverage notes (FR-42, FR-49).
- Files: `features/facts.py`. Deps: 017–021. Acceptance: facts JSON for fixtures matches `expected/*.facts.json` (selected fields).

---

## PHASE 4 — Security engine

**TASK-023 Policy schema and loader**
- Objective: pydantic schema for rules/tables/params; `safe_load`; hash of policy (FR-44, NFR-08).
- Files: `rules/{schema,loader}.py`, `policies/*.yaml` skeletons. Deps: 002. Acceptance: invalid YAML/unknown field/`!!python` tag rejected; policy hash stable.

**TASK-024 Condition evaluator and declarative engine**
- Files: `rules/{conditions,engine}.py`. Deps: 022–023. Acceptance: each operator tested; group/dedupe verified; missing fields evaluate false, never raise.

**TASK-025 Policy content: crypto rules**
- Objective: write CRY-DH-001, CRY-ENC-001/002, CRY-INT-001/002 with impact tables (cite sources or mark "team decision" in `docs/policy-rationale.md`).
- Files: `policies/nist_default.yaml`, `strict.yaml`, `legacy_tolerant.yaml`. Deps: 024. Acceptance: positive and negative fixture test per rule; risk values equal SRS worked examples (80.0, 48.0, 60.0).

**TASK-026 Policy content: IKE rules**
- Objective: IKE-V1-001..005, IKE-PROTO-001/002, IKE-INFO-001/002.
- Deps: 024. Acceptance: fixtures produce exactly expected findings; informational findings are Info severity.

**TASK-027 Detectors: negotiation, flood, scan, protocol anomaly**
- Files: `rules/detectors/{negotiation,ike_flood,ike_scan,protocol_anomaly}.py`. Deps: 022–023. Acceptance: flood/scan fixtures trigger; benign multi-client fixture does not; thresholds configurable via policy.

**TASK-028 Detectors: ESP/AH**
- Files: `rules/detectors/{esp_seq,esp_null,esp_noike,ah_usage}.py`. Deps: 019–021. Acceptance: expected findings on fixtures; ESP-SEQ confidence ≤ 0.6; negative fixture clean.

**TASK-029 Scoring and posture**
- Files: `scoring/{risk,posture}.py`. Deps: 024. Acceptance: SRS §12.3 examples reproduce; property tests (monotonicity, boundaries, caps) pass.

**TASK-030 Recommendations, MITRE, IOC**
- Files: `recommend/prioritizer.py`, `enrich/{mitre,iocs}.py`, `policies/{remediation,mitre}.yaml`. Deps: 029. Acceptance: fix-first ordering test; MITRE only on three mapped rules; IOC export includes peers/SPIs/VIDs.

**TASK-031 Template narrator**
- Files: `llm/{templates,narrator}.py`. Deps: 029–030. Acceptance: deterministic summary referencing real finding ids/numbers; snapshot test.

**TASK-032 Pipeline integration**
- Objective: wire all stages with progress mapping (SRS §7.3), coverage notes, narrative; golden-output tests per fixture.
- Deps: 022–031. Acceptance: CLI output on every fixture equals `expected/*.json` (rule ids, severities, scores); runtime benchmark recorded.

---

## PHASE 5 — Backend integration (before ML so the UI can be built on real results)

**TASK-033 Upload service and job orchestration**
- Objective: FR-01..FR-07 (stream-to-disk, magic check, hash, UUID, limits, rate limit), process-pool jobs, progress, stale-job recovery.
- Files: `services/{uploads,jobs,persist,retention}.py`, `api/v1/analyses.py`. Deps: 003–004, 032. Acceptance: API tests for 202/413/415/429, status polling reaches `completed`, failed job has `error_code`.

**TASK-034 Read APIs**
- Objective: endpoints 2–16 of SRS §9 with filters/pagination.
- Files: `api/v1/{analyses,findings,ike,esp}.py`, `schemas/`. Deps: 033. Acceptance: contract tests (response schema) for each endpoint on fixture analyses; 409 for incomplete analyses.

---

## PHASE 6 — AI/ML

**TASK-035 Lab environment**
- Objective: strongSwan hardened/weak/NAT-T topologies, capture script, own-lab-only flood script (refuses non-lab targets), dataset README.
- Files: `lab/**`. Deps: none (Linux Docker). Acceptance: `lab/scripts/capture.sh hardened` produces a pcap containing IKEv2 + ESP that IPsecScope parses with no findings above Low; weak topology produces CRY findings. If Docker is unavailable, mark task `partial` and keep scripts.

**TASK-036 Window features and dataset generator**
- Files: `features/windows.py`, `lab/dataset/generate_dataset.py`, `ml/features_schema.py`. Deps: 022, 035. Acceptance: ≥ 30 benign runs and labelled injected-anomaly runs produced; manifest with SHA-256 in `docs/datasets.md`.

**TASK-037 Training and evaluation**
- Files: `ml/{train,evaluate}.py`. Deps: 036. Acceptance: model + metadata written; evaluation split by run; `docs/ml-evaluation.md` generated with benign FPR, anomaly recall, comparison with rule detectors and the mandatory caveat. If lab data is absent, record `partial` and **do not** ship a model.

**TASK-038 Inference and anomaly findings**
- Files: `ml/infer.py`, integration into pipeline. Deps: 037 (or stub-free `unavailable` path). Acceptance: `unavailable` and `insufficient_data` states tested; ML findings ≤ Medium; top-3 features present.

**TASK-039 Optional LLM narrator**
- Files: `llm/{providers,validate}.py`. Deps: 031. Acceptance: with a fake provider in tests, invalid output (unknown finding id, altered number) is rejected and template used; IPs pseudonymized in the prompt payload (test inspects payload).

---

## PHASE 7 — Dashboard

**TASK-040 Upload, progress, overview, protocols screens**
- Deps: 033–034, 005. Acceptance: Playwright: upload fixture → progress → overview shows counts equal to API.

**TASK-041 IKE sessions and session detail (ladder, proposal compare)**
- Deps: 040. Acceptance: weak transforms flagged with icon+text; encrypted regions shown as "not observable".

**TASK-042 ESP/AH flows with charts**
- Deps: 040. Acceptance: seq chart renders gaps; ESP-NULL badge shown on fixture.

**TASK-043 Findings list, finding detail, evidence/hex viewer**
- Deps: 040. Acceptance: filters/sort/search hit server; evidence matches API; XSS fixture rendered escaped.

**TASK-044 Risk dashboard, recommendations, timeline, anomalies**
- Deps: 040, 038. Acceptance: ML panel shows `unavailable` state honestly when no model.

**TASK-045 Compare screen and capabilities/About**
- Deps: 046 (API), 040. Acceptance: before/after fixtures show resolved findings.

---

## PHASE 8 — Reports and compare

**TASK-046 Compare service and API**
- Files: `services/compare.py`, `api/v1/compare.py`. Deps: 034. Acceptance: fingerprint matching test; posture delta computed.

**TASK-047 Report templates and charts**
- Files: `reports/{generator,charts}.py`, `templates/report.html.j2`. Deps: 034. Acceptance: HTML contains all SRS §14 sections; autoescape verified; no external assets.

**TASK-048 Report API, PDF, JSON, CSV exports**
- Files: `api/v1/reports.py`. Deps: 047. Acceptance: PDF opens and has ≥ 1 page per major section; JSON validates against published schema; CSV round-trips.

**TASK-049 Report page in frontend**
- Deps: 048, 040. Acceptance: generate → preview (sandboxed iframe) → download works.

---

## PHASE 9 — Testing, hardening, deployment

**TASK-050 Complete test suites**
- Objective: implement all test cases in Document 5; coverage gates (analyzer ≥ 80%, parsers/rules/scoring ≥ 90%).
- Acceptance: CI command `make ci` green.

**TASK-051 Security hardening pass**
- Objective: NFR-07..NFR-10 checklist; dependency audits; path traversal and oversize tests; headers.
- Acceptance: Document 5 §7 security checklist all pass.

**TASK-052 Performance benchmarks**
- Objective: measure NFR-01..03; record in `docs/benchmarks.md` (actual numbers, hardware).
- Acceptance: results recorded; if targets missed, document and optimise hot paths (classifier/decoder) or adjust documented targets honestly.

**TASK-053 Docker/production config and README**
- Objective: final compose, healthchecks, non-root users, `.env.example`, README quick start and limitations.
- Acceptance: fresh-clone smoke test script `scripts/smoke.sh` uploads a fixture via API and downloads a PDF report.

**TASK-054 Demo script and final review**
- Objective: `scripts/demo.sh` + `docs/demo.md` per Document 5 §6; run SPEC §13 checklist; update `capabilities.py` to match reality.
- Acceptance: demo completes in ≤ 5 minutes; checklist signed off in `docs/DECISIONS.md`.

---

## Parallelisation hints
- Frontend (005, 040–045, 049) can proceed once API contracts (SRS §9) are fixed, using the real backend with fixtures.
- Lab/ML (035–038) is independent of rules work and can run in parallel after TASK-022.
- Do not parallelise 014/015 with 017 — sessions depend on parser output shape.
