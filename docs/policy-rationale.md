# Policy Rationale — IPsecScope Cryptographic Rules

## 1. Overview
This document specifies the technical and regulatory rationale for the cryptographic rules in IPsecScope policies (`nist_default.yaml`, `strict.yaml`, and `legacy_tolerant.yaml`).

Impact values (1–5 scale):
- **5 (Critical):** Broken cryptosystems with practical attacks (DES, NULL cipher, DH Group 1 768-bit).
- **4 (High):** Weak algorithms below modern work factor standards (DH Group 2 1024-bit, MD5).
- **3 (Medium):** Deprecated algorithms with structural weaknesses (3DES Sweet32 attack, DH Group 5 1536-bit).
- **2 (Low):** Phased-out legacy algorithms (HMAC-SHA1 collision resistance concerns).
- **1 (Acceptable / Info):** Standard modern algorithms (AES-GCM, AES-CBC with HMAC-SHA256, DH Group 14+).

---

## 2. Rule Rationales

### CRY-DH-001: Weak or Broken Diffie-Hellman Groups
- **Standard citations:** NIST SP 800-77 Rev. 1 §4.1; NIST SP 800-131A Rev. 2 §3; RFC 8247 §2.4.
- **Rationale:**
  - Group 1 (MODP-768): 768-bit primes can be factored by academic clusters. Impact = 5.
  - Group 2 (MODP-1024): 1024-bit primes are vulnerable to nation-state precomputation (Logjam attack). Impact = 4.
  - Group 5 (MODP-1536): Disallowed by NIST after 2013; provides ~96 bits of security. Impact = 3.
  - Group 14 (MODP-2048): Minimum acceptable transitional MODP group (112 bits security). Impact = 1.
  - Groups 19, 20, 21, 31 (ECP-256/384/521, Curve25519): Modern strong groups (128+ bits). Impact = 1.

### CRY-ENC-001: Broken or Deprecated Encryption Ciphers
- **Standard citations:** NIST SP 800-131A Rev. 2; RFC 8247 §2.1; RFC 7321.
- **Rationale:**
  - DES / DES-IV64 (IDs 1, 2): 56-bit keys breakable in hours by brute force. Impact = 5.
  - NULL (ID 11): Unencrypted plaintext payload. Impact = 5.
  - 3DES (ID 3): 64-bit block size vulnerable to Sweet32 collision attacks after 32 GB of data. Disallowed by NIST beyond 2023. Impact = 3.
  - Blowfish, CAST, IDEA (IDs 5, 6, 7): Legacy 64-bit or unapproved block ciphers. Impact = 4.

### CRY-ENC-002: Legacy CBC Mode (AES-CBC)
- **Standard citations:** RFC 8247 §2.1.2; team decision.
- **Rationale:**
  - AES-CBC (ID 12): Cryptographically sound when combined with strong integrity (HMAC-SHA256), but lacks the efficiency, AEAD single-pass speed, and nonce-misuse resistance of AES-GCM (IDs 18, 19, 20) or ChaCha20-Poly1305 (ID 28).
  - Severity: Informational (Info). Encourages migration to AEAD without penalizing compliant baseline configurations.

### CRY-INT-001: Weak Integrity or PRF Hash Algorithm
- **Standard citations:** NIST SP 800-131A; RFC 8247 §2.2–§2.3; RFC 7321.
- **Rationale:**
  - MD5 (PRF 1, INTEG 1, HASH 1): Completely broken collision resistance; disallowed for all government/enterprise use. Impact = 4.
  - SHA-1 (PRF 2, INTEG 2, HASH 2): Collision attacks demonstrated (SHAttered, Shambles); deprecated for digital signatures and integrity. Impact = 2 (or 1 in tolerant mode).

### CRY-INT-002: Missing Integrity Protection (NONE)
- **Standard citations:** RFC 7296 §3.3.2; RFC 8247 §2.2.
- **Rationale:**
  - INTEG ID 0 (NONE) is only permitted when an AEAD cipher (AES-GCM, AES-CCM, ChaCha20-Poly1305) is selected. When non-AEAD ciphers (such as AES-CBC or 3DES) are used without integrity protection, traffic is vulnerable to active bit-flipping attacks. Impact = 5.
