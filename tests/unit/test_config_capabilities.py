"""Unit tests for analyzer config, backend config, and capabilities registry."""

import pytest

from analyzer.capabilities import get_capabilities
from analyzer.config import AnalyzerConfig
from backend.app.config import AppSettings


@pytest.mark.unit
def test_analyzer_config_defaults():
    """Verify analyzer limits and heuristic defaults."""
    cfg = AnalyzerConfig()
    assert cfg.max_file_size_mb == 200
    assert cfg.max_packets == 2_000_000
    assert cfg.timeout_seconds == 300
    assert cfg.esp_null_min_packets == 10
    assert cfg.esp_null_threshold_ratio == 0.90
    assert cfg.esp_null_confidence == 0.85
    assert cfg.window_duration_s == 10.0


@pytest.mark.unit
def test_backend_config_defaults_and_overrides(monkeypatch):
    """Verify backend settings load defaults and honor environment overrides."""
    # Test default values
    settings = AppSettings()
    assert settings.PORT == 8000
    assert settings.MAX_UPLOAD_MB == 200
    assert settings.DEFAULT_POLICY == "nist_default"

    # Test environment variable override
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("MAX_UPLOAD_MB", "50")
    monkeypatch.setenv("DEFAULT_POLICY", "strict")
    monkeypatch.setenv("CORS_ORIGINS", '["http://example.com","http://test.com"]')

    custom_settings = AppSettings()
    assert custom_settings.PORT == 9000
    assert custom_settings.MAX_UPLOAD_MB == 50
    assert custom_settings.DEFAULT_POLICY == "strict"
    assert "http://example.com" in custom_settings.CORS_ORIGINS
    assert "http://test.com" in custom_settings.CORS_ORIGINS


@pytest.mark.unit
def test_all_priority_a_and_f_features_in_capabilities():
    """Verify every requirement with priority A or F has an explicit entry (TASK-002 acceptance)."""
    caps = get_capabilities()
    cap_ids = {c.id: c for c in caps}

    # Mandated Priority A requirements
    required_priority_a = [
        "FR-39",  # ESP-NULL heuristic
        "FR-43",  # Windowed behavioural features
        "FR-55",  # Training pipeline
        "FR-56",  # Isolation forest anomaly detection
        "FR-57",  # Top-3 feature deviations
        "FR-58",  # ML honest unavailable/insufficient_data
        "FR-59",  # Model artifact schema validation
        "FR-60",  # LLM narrative summary
        "FR-61",  # LLM input sanitization & schema validation
        "FR-66",  # MITRE ATT&CK technique mapping
        "FR-67",  # IOC extraction
        "FR-74",  # Analysis comparison
    ]

    for req_id in required_priority_a:
        assert req_id in cap_ids, f"Priority A requirement {req_id} missing from capabilities registry"
        assert cap_ids[req_id].priority == "A"
        assert cap_ids[req_id].status in ("implemented", "partial", "not_implemented")

    # Mandated Priority F requirements
    required_priority_f = [
        "FR-87",  # Key-assisted decryption
    ]

    for req_id in required_priority_f:
        assert req_id in cap_ids, f"Priority F requirement {req_id} missing from capabilities registry"
        assert cap_ids[req_id].priority == "F"
        assert cap_ids[req_id].status == "not_implemented"
