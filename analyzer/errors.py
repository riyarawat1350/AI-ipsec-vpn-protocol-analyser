"""Analyzer errors — typed exceptions for pipeline and CLI (FR-07, FR-86)."""

from __future__ import annotations


class AnalyzerError(Exception):
    """Base class for all analyzer errors."""
    code: str = "ANALYZER_ERROR"


class FileTooLargeError(AnalyzerError):
    """Capture file exceeds the configured size limit."""
    code = "FILE_TOO_LARGE"


class PacketLimitError(AnalyzerError):
    """Analysis stopped because packet count exceeded MAX_PACKETS."""
    code = "PACKET_LIMIT_EXCEEDED"


class TimeoutError(AnalyzerError):
    """Analysis timed out."""
    code = "ANALYSIS_TIMEOUT"


class UnsupportedFormatError(AnalyzerError):
    """Capture file format is not pcap or pcapng."""
    code = "UNSUPPORTED_FORMAT"


class CorruptedCaptureError(AnalyzerError):
    """Capture file is unreadable or corrupt beyond tolerance."""
    code = "CORRUPTED_CAPTURE"
