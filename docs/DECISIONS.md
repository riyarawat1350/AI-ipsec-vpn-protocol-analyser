# IPsecScope Architecture & Engineering Decisions Log

This document records all architectural decisions, trade-offs, and disambiguations made during development, as mandated by Rule 1 of the Antigravity Implementation Specification.

---

## DEC-001: Custom Binary Parser Architecture
- **Date:** 2026-10-17
- **Context:** Core parser requirement prohibits wrapping Wireshark/tshark or pyshark in production code.
- **Decision:** All IKEv1, IKEv2, ESP, and AH packet headers and payloads are parsed from raw bytes using Python's `struct` module and bitwise operations. Scapy is used solely as a streaming reader for pcap/pcapng raw bytes (`RawPcapReader`/`RawPcapNgReader`), and `dpkt` is used for L2–L4 frame decoding.
- **Consequences:** Safe, zero-shell, memory-efficient packet parsing with strictly bounded loops.

## DEC-002: Observability Boundary Adherence
- **Date:** 2026-10-17
- **Context:** IPsec encrypts payloads after the initial handshake (IKE_AUTH in IKEv2, Quick Mode in IKEv1, all ESP packets).
- **Decision:** The system will never guess or claim to decrypt encrypted regions without keys. In IKEv2, payloads following SK(46) or SKF(53) are recorded with `encrypted=True`, and `encrypted_not_observable` lists child SA proposals and identities. ESP ciphers and PFS are explicitly documented as unobservable from passive captures.

## DEC-003: Honest Capabilities & ML Stance
- **Date:** 2026-10-17
- **Context:** Requirement prohibits fabricating synthetic ML models or faking detection without real ground truth.
- **Decision:** If no valid lab-trained model is present on disk, ML is exposed as `unavailable` or `partial`. All heuristic detections (such as ESP-NULL) are explicitly marked with `heuristic: true` and confidence < 1.0.

## DEC-004: Workspace Setup & Python 3.14 Compatibility
- **Date:** 2026-10-17
- **Context:** Workspace initialized on Python 3.14 on Windows.
- **Decision:** Dependencies pinned in `requirements.txt` with compatibility for Python 3.14+. Virtual environment initialized in `./venv`.

## DEC-005: Database Migration — SQLAlchemy/SQLite → MongoDB Atlas (Motor)
- **Date:** 2026-10-17
- **Context:** User requested full MongoDB migration. Project was initially designed with SQLAlchemy + SQLite/PostgreSQL per SRS §10.
- **Decision:** Replaced SQLAlchemy entirely with **Motor** (async MongoDB driver). All SRS §10 tables are now MongoDB collections in Atlas. Old SQLAlchemy files archived as `*.sqlalchemy_old`. The analyzer core (`analyzer/`) is unaffected — it has no DB dependency.
- **Collections:** `uploads`, `analyses`, `ike_sessions`, `ike_messages`, `findings`, `ipsec_flows`, `recommendations`, `audit_log`.
- **Connection:** `MONGODB_URL` env var (Atlas SRV string). `MONGODB_DB_NAME` defaults to `ipsecscope`.
- **Tests:** API tests mock the MongoDB lifespan with `unittest.mock` — no live Atlas connection required for CI.
- **Consequences:** No SQL migrations needed; schema is document-oriented. Pydantic models (analyzer layer) are unchanged.

## DEC-006: Independent Decoder Verification Architecture (Phase 1–3)
- **Date:** 2026-10-19
- **Context:** Ensuring the analyzer's packet parsing and security evaluations are correct requires verification against an external, zero-dependency ground truth decoder.
- **Decision:** Built `tests/verification/independent_decoder.py` that imports 0 modules from `analyzer/` and parses raw pcap frames using standalone Python struct code. Created automated suites `verify_phase1.py`, `verify_phase2.py`, and `verify_phase3.py` that cross-check protocol distributions, exact rule firing, risk math formulas ($R = \frac{\text{Impact} \times \text{Likelihood}}{25} \times 100 \times (0.5 + 0.5 \times \text{Confidence})$), raw byte evidence excerpts, and cross-screen consistency.
- **Consequences:** Automated `make verify` catches any parser regression or calculation drift deterministically.

## DEC-007: Plain English and Deterministic Report Card System (Phase 4)
- **Date:** 2026-10-19
- **Context:** Non-technical stakeholders require immediate clarity on risk posture without getting lost in hex dumps or cryptographic jargon.
- **Decision:** Implemented `analyzer/explain/glossary.yaml` (75 terms with plain explanations <= 25 words, analogies, and technical details). Added `plain_summary`, `plain_impact`, and `plain_fix` to all declarative rules in `nist_default.yaml`. Created deterministic 5-point report cards and step-by-step IKE/ESP handshake narratives with average sentence lengths <= 20 words.
- **Consequences:** Users can toggle between Simple and Technical view; interactive `<Term>` components provide inline popovers for every technical term.

## DEC-008: Strict Elimination of Overclaim Words & Banned Fallback Strings
- **Date:** 2026-10-19
- **Context:** Passive analysis cannot guarantee security or absence of tampering without private keys. Overpromising words undermine security audits.
- **Decision:** Completely purged words like `secure`, `safe`, `strong security`, `unhackable`, `guaranteed` from UI, reports, and rules. Replaced with factual phrasing ("No weaknesses found in observed parameters", "Complies with baseline policy"). Purged hardcoded mock fallback strings (`disallow deprecated`, `man-in-the-middle downgrade`, `aes256gcm16`).
- **Consequences:** Reports and screens remain strictly factual and scientifically defensible.

## DEC-009: Strict Observability Boundary for Passive Analysis
- **Date:** 2026-10-19
- **Context:** Passive capture analyzers cannot observe ESP payload ciphers, inner tunnel IPs, PFS rekeying, or IKE_AUTH encrypted contents without keys.
- **Decision:** All such properties are strictly labeled "not observable" across all UI cards, API responses, and generated PDF/HTML reports. Any attempt to fabricate or guess unobservable properties is forbidden.

