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
