"""IANA / RFC IKE constants and name lookups — TASK-013.

Values from SPEC §6 (verify against IANA registries when updating).
Unknown IDs render as ``UNKNOWN(<n>)``, never guessed.
"""

from __future__ import annotations

# verify against IANA

# ── Exchange types ──────────────────────────────────────────────────────────

IKEv2_EXCHANGE: dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    39: "IKE_INTERMEDIATE",
    40: "IKE_FOLLOWUP_KE",
}

IKEv1_EXCHANGE: dict[int, str] = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

# ── Payload types ───────────────────────────────────────────────────────────

IKEv2_PAYLOAD: dict[int, str] = {
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "Ni/Nr",
    41: "Notify",
    42: "Delete",
    43: "Vendor ID",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    53: "SKF",
}

IKEv1_PAYLOAD: dict[int, str] = {
    1: "SA",
    2: "Proposal",
    3: "Transform",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CERTREQ",
    8: "HASH",
    9: "SIG",
    10: "Nonce",
    11: "Notification",
    12: "Delete",
    13: "Vendor ID",
    20: "NAT-D",
    21: "NAT-OA",
}

# ── Transform types (IKEv2) ─────────────────────────────────────────────────

TRANSFORM_TYPE: dict[int, str] = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "DH",
    5: "ESN",
}

# ── ENCR / PRF / INTEG / DH ids ─────────────────────────────────────────────

ENCR_IDS: dict[int, str] = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    4: "ENCR_RC5",
    5: "ENCR_IDEA",
    6: "ENCR_CAST",
    7: "ENCR_BLOWFISH",
    8: "ENCR_3IDEA",
    9: "ENCR_DES_IV32",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    23: "ENCR_CAMELLIA_CBC",
    28: "ENCR_CHACHA20_POLY1305",
}

# AEAD set: CCM / GCM / ChaCha20-Poly1305 — no separate integrity transform
AEAD_ENCR_IDS: frozenset[int] = frozenset({14, 15, 16, 18, 19, 20, 28})

PRF_IDS: dict[int, str] = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}

INTEG_IDS: dict[int, str] = {
    0: "AUTH_NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128",
    7: "AUTH_HMAC_SHA1_160",
    8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC",
    10: "AUTH_AES_192_GMAC",
    11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

DH_IDS: dict[int, str] = {
    1: "DH_MODP_768",
    2: "DH_MODP_1024",
    5: "DH_MODP_1536",
    14: "DH_MODP_2048",
    15: "DH_MODP_3072",
    16: "DH_MODP_4096",
    17: "DH_MODP_6144",
    18: "DH_MODP_8192",
    19: "DH_ECP_256",
    20: "DH_ECP_384",
    21: "DH_ECP_521",
    22: "DH_MODP_1024_160",
    23: "DH_MODP_2048_224",
    24: "DH_MODP_2048_256",
    25: "DH_ECP_192",
    26: "DH_ECP_224",
    27: "DH_BRAINPOOL_P224R1",
    28: "DH_BRAINPOOL_P256R1",
    29: "DH_BRAINPOOL_P384R1",
    30: "DH_BRAINPOOL_P512R1",
    31: "DH_CURVE25519",
    32: "DH_CURVE448",
}

# Expected KE payload *data* length (bytes after the 4-byte DH-group header)
_KE_SIZES: dict[int, int] = {
    1: 96,    # MODP-768
    2: 128,   # MODP-1024
    5: 192,   # MODP-1536
    14: 256,  # MODP-2048
    15: 384,  # MODP-3072
    16: 512,  # MODP-4096
    17: 768,  # MODP-6144
    18: 1024, # MODP-8192
    19: 64,   # ECP-256 (2*32)
    20: 96,   # ECP-384
    21: 132,  # ECP-521
    22: 128,  # MODP-1024/160
    23: 256,  # MODP-2048/224
    24: 256,  # MODP-2048/256
    25: 48,   # ECP-192
    26: 56,   # ECP-224
    31: 32,   # Curve25519
    32: 56,   # Curve448
}

# Classic weak MODP groups (≤1536-bit)
WEAK_DH_GROUPS: frozenset[int] = frozenset({1, 2, 5, 22})

ESN_IDS: dict[int, str] = {
    0: "No-ESN",
    1: "ESN",
}

# ── Notify types (IKEv2 subset) ─────────────────────────────────────────────

NOTIFY_IDS: dict[int, str] = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16396: "MOBIKE_SUPPORTED",
    16406: "REDIRECT_SUPPORTED",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
}

# ── IKEv1 attribute value maps ──────────────────────────────────────────────

IKEv1_ENCR: dict[int, str] = {
    1: "DES-CBC",
    2: "IDEA",
    3: "Blowfish",
    4: "RC5",
    5: "3DES-CBC",
    6: "CAST",
    7: "AES-CBC",
    8: "Camellia",
}

IKEv1_HASH: dict[int, str] = {
    1: "MD5",
    2: "SHA1",
    3: "Tiger",
    4: "SHA2-256",
    5: "SHA2-384",
    6: "SHA2-512",
}

IKEv1_AUTH: dict[int, str] = {
    1: "PSK",
    2: "DSS-sig",
    3: "RSA-sig",
    4: "RSA-enc",
    5: "RSA-enc-revised",
    64221: "Hybrid-RSA",
    65001: "XAUTH-PSK",
    65005: "XAUTH-RSA",
}

IKEv1_LIFE_TYPE: dict[int, str] = {
    1: "seconds",
    2: "kilobytes",
}


# ── Lookup helpers ──────────────────────────────────────────────────────────

def _unknown(n: int) -> str:
    return f"UNKNOWN({n})"


def encr_name(encr_id: int) -> str:
    return ENCR_IDS.get(encr_id, _unknown(encr_id))


def prf_name(prf_id: int) -> str:
    return PRF_IDS.get(prf_id, _unknown(prf_id))


def integ_name(integ_id: int) -> str:
    return INTEG_IDS.get(integ_id, _unknown(integ_id))


def dh_name(dh_id: int) -> str:
    return DH_IDS.get(dh_id, _unknown(dh_id))


def notify_name(notify_type: int) -> str:
    return NOTIFY_IDS.get(notify_type, _unknown(notify_type))


def ikev2_exchange_name(exchange_type: int) -> str:
    return IKEv2_EXCHANGE.get(exchange_type, _unknown(exchange_type))


def ikev1_exchange_name(exchange_type: int) -> str:
    return IKEv1_EXCHANGE.get(exchange_type, _unknown(exchange_type))


def payload_name(payload_type: int, *, version: int = 2) -> str:
    table = IKEv2_PAYLOAD if version == 2 else IKEv1_PAYLOAD
    return table.get(payload_type, _unknown(payload_type))


def transform_type_name(ttype: int) -> str:
    return TRANSFORM_TYPE.get(ttype, _unknown(ttype))


def transform_name(transform_type: int, transform_id: int) -> str:
    """Dispatch name lookup by transform type (ENCR/PRF/INTEG/DH/ESN)."""
    if transform_type == 1:
        return encr_name(transform_id)
    if transform_type == 2:
        return prf_name(transform_id)
    if transform_type == 3:
        return integ_name(transform_id)
    if transform_type == 4:
        return dh_name(transform_id)
    if transform_type == 5:
        return ESN_IDS.get(transform_id, _unknown(transform_id))
    return _unknown(transform_id)


def is_aead(encr_id: int) -> bool:
    return encr_id in AEAD_ENCR_IDS


def expected_ke_size(dh_group: int) -> int | None:
    """Return expected KE data length in bytes, or None if unknown group."""
    return _KE_SIZES.get(dh_group)


def is_weak_dh(dh_group: int) -> bool:
    return dh_group in WEAK_DH_GROUPS


def is_error_notify(notify_type: int) -> bool:
    """Error-class notifies have type < 16384 (RFC 7296)."""
    return notify_type < 16384
