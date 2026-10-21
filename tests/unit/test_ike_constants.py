"""Tests for IKE constants and common helpers — TASK-013."""

from __future__ import annotations

import pytest

from analyzer.ike.common import ParseError, hex_spi, iter_payloads, safe_unpack
from analyzer.ike.constants import (
    dh_name,
    encr_name,
    expected_ke_size,
    ikev1_exchange_name,
    ikev2_exchange_name,
    integ_name,
    is_aead,
    is_weak_dh,
    notify_name,
    prf_name,
    transform_name,
)

# ── Name lookup tests ──────────────────────────────────────────────────────

def test_known_encr_name():
    assert encr_name(12) == "ENCR_AES_CBC"
    assert encr_name(20) == "ENCR_AES_GCM_16"


def test_unknown_returns_fallback():
    assert encr_name(999) == "UNKNOWN(999)"
    assert prf_name(999) == "UNKNOWN(999)"
    assert integ_name(999) == "UNKNOWN(999)"
    assert dh_name(999) == "UNKNOWN(999)"
    assert notify_name(999) == "UNKNOWN(999)"


def test_ikev2_exchange_names():
    assert ikev2_exchange_name(34) == "IKE_SA_INIT"
    assert ikev2_exchange_name(35) == "IKE_AUTH"
    assert ikev2_exchange_name(36) == "CREATE_CHILD_SA"
    assert ikev2_exchange_name(37) == "INFORMATIONAL"
    assert ikev2_exchange_name(0) == "UNKNOWN(0)"


def test_ikev1_exchange_names():
    assert "Main" in ikev1_exchange_name(2) or "Identity" in ikev1_exchange_name(2)
    assert "Aggressive" in ikev1_exchange_name(4)
    assert "Quick" in ikev1_exchange_name(32)


def test_transform_name_dispatch():
    assert "AES" in transform_name(1, 12)    # ENCR AES-CBC
    assert "HMAC_SHA2_256" in transform_name(2, 5)  # PRF
    assert "HMAC_SHA2_256" in transform_name(3, 12)  # INTEG
    assert "2048" in transform_name(4, 14)   # DH
    assert "ESN" in transform_name(5, 1)
    assert "No-ESN" in transform_name(5, 0)


# ── AEAD set ──────────────────────────────────────────────────────────────

def test_aead_ids_are_identified():
    for aead_id in [18, 19, 20, 28]:  # GCM variants + ChaCha20
        assert is_aead(aead_id), f"Expected {aead_id} to be AEAD"


def test_non_aead_ids():
    assert not is_aead(12)  # AES-CBC is not AEAD
    assert not is_aead(11)  # NULL
    assert not is_aead(3)   # 3DES


# ── DH KE expected sizes ─────────────────────────────────────────────────

def test_expected_ke_size_known():
    assert expected_ke_size(14) == 256   # 2048-bit
    assert expected_ke_size(19) == 64    # P-256
    assert expected_ke_size(31) == 32    # Curve25519


def test_expected_ke_size_unknown():
    assert expected_ke_size(999) is None


def test_weak_dh_groups():
    for g in [1, 2, 5]:
        assert is_weak_dh(g), f"group {g} should be weak"
    assert not is_weak_dh(14)
    assert not is_weak_dh(19)


# ── iter_payloads ─────────────────────────────────────────────────────────

def test_iter_payloads_single():
    import struct
    # One payload: type=40 (nonce), next=0, crit=0, len=4+4=8, body=0xABCD1234
    body = b"\xab\xcd\x12\x34"
    hdr = struct.pack(">BBH", 0, 0, 8)  # next=0, flags=0, len=8
    raw = hdr + body
    result = iter_payloads(raw, 40)
    assert len(result) == 1
    assert result[0][0] == 40
    assert result[0][2] == body


def test_iter_payloads_chained():
    import struct
    nonce_body = b"\xAA" * 4
    sa_body = b"\xBB" * 4
    # SA (type=33) → Nonce (type=40) → end
    nonce_hdr = struct.pack(">BBH", 0, 0, 8)   # next=none
    sa_hdr = struct.pack(">BBH", 40, 0, 8)     # next=nonce
    raw = sa_hdr + sa_body + nonce_hdr + nonce_body
    result = iter_payloads(raw, 33)
    assert len(result) == 2
    assert result[0][0] == 33
    assert result[1][0] == 40


def test_iter_payloads_truncated_graceful():
    """Truncated buffer must not raise — just return what was parsed."""
    import struct
    hdr = struct.pack(">BBH", 0, 0, 200)  # claims 200 bytes but only 4+4 available
    raw = hdr + b"\xCC" * 4
    result = iter_payloads(raw, 41)
    assert len(result) == 1  # partial payload still returned


def test_iter_payloads_corrupt_length_stops():
    """Payload_len < 4 must stop iteration gracefully."""
    import struct
    hdr = struct.pack(">BBH", 40, 0, 2)  # len=2 is corrupt
    raw = hdr + b"\xDD" * 4
    result = iter_payloads(raw, 33)
    assert result == []


# ── safe_unpack ───────────────────────────────────────────────────────────

def test_safe_unpack_ok():
    import struct
    data = struct.pack(">HH", 0x1234, 0x5678)
    a, b = safe_unpack(">HH", data)
    assert a == 0x1234
    assert b == 0x5678


def test_safe_unpack_too_short():
    with pytest.raises(ParseError):
        safe_unpack(">HH", b"\x00")  # need 4 bytes, have 1


# ── hex_spi ───────────────────────────────────────────────────────────────

def test_hex_spi():
    raw = bytes.fromhex("0123456789abcdef")
    assert hex_spi(raw) == "0123456789abcdef"
