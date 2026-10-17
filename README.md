# IPsecScope

**AI-Assisted IPsec VPN Protocol Analyzer and Security Assessment Framework**

IPsecScope is a passive, offline analyzer for PCAP and PCAPNG network captures containing IPsec VPN traffic (IKEv1, IKEv2, ESP, AH, and NAT-T). It parses observable protocol parameters with a dedicated, zero-dependency binary parser, evaluates configurations against declarative YAML security policies, detects behavioral anomalies, deterministically scores risk, and produces audit-ready reports.

---

## Observability Boundary & Honest Limitations

In strict compliance with RFC 7296 and cryptographic principles:
1. **No Traffic Decryption**: IPsecScope performs **passive keyless analysis**. Encrypted traffic (including IKEv2 `IKE_AUTH`, IKEv1 `Quick Mode`, and all standard ESP payloads) is treated as opaque and marked `not_observable`.
2. **No Cipher Guessing**: ESP ciphers, PFS status, and child SA proposals are never guessed when encapsulated in encrypted payloads.
3. **Transparent Heuristics**: Any heuristic detection (such as ESP-NULL unencrypted payload detection via IPv4 header checksum verification) carries `confidence < 1.0` and a `heuristic: true` flag.

---

## Architecture Overview

```
ipsecscope/
├── analyzer/     # Standalone binary parser, session reconstructor, rule engine, risk scoring
├── backend/      # FastAPI application, async task management, SQLite/PostgreSQL storage
├── frontend/     # React 18, Vite, TypeScript, Tailwind CSS dashboard
├── reports/      # Jinja2 & WeasyPrint PDF/HTML/JSON report generation
└── tests/        # Unit, integration, security fuzzing, and API test suites
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+

### Running Locally

```bash
# Python backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev
```
