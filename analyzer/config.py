"""Configuration and default thresholds for the IPsecScope analyzer."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AnalyzerConfig:
    """Limits and heuristic thresholds for the standalone analyzer."""

    # Processing and ingestion limits (FR-07)
    max_file_size_mb: int = 200
    max_packets: int = 2_000_000
    timeout_seconds: int = 300

    # IPv4 defragmentation limits (FR-11)
    max_fragments_per_packet: int = 64
    max_defrag_cache_entries: int = 1000
    max_defrag_memory_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    defrag_timeout_seconds: float = 30.0

    # ESP sequence tracking (SPEC §5.6)
    seq_window_size: int = 1024
    max_gaps_stored: int = 200
    max_downsampled_points: int = 500
    sample_prefixes_count: int = 50

    # ESP-NULL heuristic thresholds (FR-39, SPEC §5.7)
    esp_null_min_packets: int = 10
    esp_null_threshold_ratio: float = 0.90
    esp_null_confidence: float = 0.85

    # IKE flood detection thresholds (SPEC §5.8)
    ike_flood_per_source_rps: int = 50
    ike_flood_aggregate_rps: int = 200
    ike_flood_min_duration_s: int = 2

    # IKE scan detection thresholds (SPEC §5.9)
    ike_scan_distinct_responders: int = 5
    ike_scan_window_s: int = 60
    ike_scan_min_proposals: int = 5

    # Behavioural feature windowing (SRS §11.2)
    window_duration_s: float = 10.0
    min_windows_for_ml: int = 20

    # Custom options
    custom_options: dict[str, Any] = field(default_factory=dict)


DEFAULT_ANALYZER_CONFIG = AnalyzerConfig()
