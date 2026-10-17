"""Analysis pipeline — orchestrates capture reading, decoding, classification.

TASK-012 scope: streaming pipeline with progress callbacks, packet/size limits.
Full IPsec analysis stages (IKE parse, ESP track, rules) are wired in TASK-032.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from analyzer.capture.reader import CaptureReader
from analyzer.capture.decode import PacketDecoder
from analyzer.capture.defrag import IPv4Defragmenter
from analyzer.classify.classifier import ProtocolClassifier
from analyzer.config import AnalyzerConfig
from analyzer.errors import (
    FileTooLargeError,
    PacketLimitError,
    UnsupportedFormatError,
)
from analyzer.features.facts import build_facts_from_classifier
from analyzer.models import AnalysisResult, Facts

ProgressCallback = Callable[[int, str], None]  # (percent, stage_name)


def _noop_progress(pct: int, stage: str) -> None:
    pass


class Pipeline:
    """Streaming analysis pipeline.

    Stages (TASK-012 skeleton):
      1. Read frames from pcap/pcapng
      2. Decode L2-L4
      3. IPv4 defragmentation
      4. Protocol classification
      [5–N: IKE parse, ESP track, rules — wired in TASK-032]
    """

    def __init__(
        self,
        config: AnalyzerConfig | None = None,
        progress: ProgressCallback = _noop_progress,
    ) -> None:
        self.config = config or AnalyzerConfig()
        self.progress = progress

    def run(self, capture_path: Path) -> AnalysisResult:
        """Run the full pipeline on *capture_path* and return an AnalysisResult.

        Raises:
            FileTooLargeError: if file exceeds config.max_capture_bytes
            UnsupportedFormatError: if not a pcap/pcapng file
            PacketLimitError: if packet count exceeds config.max_packets
        """
        self.progress(0, "validating")
        self._validate_file(capture_path)

        self.progress(5, "reading")
        reader = CaptureReader(capture_path)
        decoder = PacketDecoder()
        defrag = IPv4Defragmenter(
            max_cache_bytes=self.config.defrag_max_cache_bytes,
            timeout_seconds=self.config.defrag_timeout_s,
        )
        classifier = ProtocolClassifier()

        packet_count = 0
        warnings: list[str] = []

        self.progress(10, "decoding")
        for frame in reader.iter_frames():
            pkt = decoder.decode(frame)
            if pkt is None:
                continue

            # Defragment
            result = defrag.process(pkt)
            if result is None:
                continue  # Still buffering

            # Classify
            classifier.process(result)

            packet_count += 1
            if packet_count >= self.config.max_packets:
                warnings.append(
                    f"Packet limit ({self.config.max_packets}) reached. "
                    "Remaining packets skipped."
                )
                break

            if packet_count % 10000 == 0:
                pct = min(90, 10 + int(packet_count / self.config.max_packets * 80))
                self.progress(pct, "decoding")

        warnings.extend(defrag.warnings)
        if decoder.unsupported_linktypes:
            warnings.append(
                f"Unsupported link types encountered: {sorted(decoder.unsupported_linktypes)}"
            )

        self.progress(92, "building_facts")
        clf_result = classifier.result()
        clf_result.warnings.extend(warnings)
        facts = build_facts_from_classifier(clf_result)

        self.progress(100, "done")

        return AnalysisResult(
            facts=facts,
            findings=[],
            posture={},
            recommendations=[],
            iocs=[],
            narrative={},
            ml_status={"status": "not_run"},
            coverage_notes=list(facts.warnings),
        )

    def _validate_file(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Capture file not found: {path}")
        if path.suffix.lower() not in (".pcap", ".pcapng"):
            raise UnsupportedFormatError(
                f"Unsupported file extension: {path.suffix}. Expected .pcap or .pcapng"
            )
        size = path.stat().st_size
        if size > self.config.max_capture_bytes:
            raise FileTooLargeError(
                f"File size {size} bytes exceeds limit {self.config.max_capture_bytes} bytes"
            )
