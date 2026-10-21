"""Analysis pipeline — orchestrates capture reading, decoding, classification,
IKE/ESP session reconstruction, rule evaluation, scoring, and posture assessment.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from analyzer.capture.decode import PacketDecoder
from analyzer.capture.defrag import IPv4Defragmenter
from analyzer.capture.reader import CaptureReader
from analyzer.classify.classifier import ProtocolClassifier
from analyzer.config import AnalyzerConfig
from analyzer.enrich.iocs import extract_iocs
from analyzer.errors import (
    FileTooLargeError,
    UnsupportedFormatError,
)
from analyzer.esp.ah import parse_ah_header
from analyzer.esp.linking import link_flows_to_ike_sessions, pair_flows
from analyzer.esp.null_heuristic import check_esp_null
from analyzer.esp.tracker import FlowTracker, parse_esp_packet
from analyzer.features.facts import build_facts
from analyzer.ike.parser_v1 import parse_ikev1
from analyzer.ike.parser_v2 import parse_ikev2
from analyzer.ike.sessions import (
    IkeSessionReconstructor,
    ikemessage_to_model,
)
from analyzer.llm.narrator import generate_narrative
from analyzer.models import (
    AnalysisResult,
    Finding,
    RawFinding,
)
from analyzer.recommend.prioritizer import prioritize_recommendations
from analyzer.rules.detectors.esp_detectors import detect_esp_anomalies
from analyzer.rules.detectors.ike_flood import detect_ike_floods
from analyzer.rules.detectors.ike_scan import detect_ike_scans
from analyzer.rules.detectors.negotiation import detect_negotiation_anomalies
from analyzer.rules.detectors.protocol_anomaly import detect_protocol_anomalies
from analyzer.rules.engine import RuleEngine
from analyzer.rules.loader import load_policy
from analyzer.scoring.posture import calculate_posture
from analyzer.scoring.risk import calculate_risk, calculate_severity

ProgressCallback = Callable[[int, str], None]  # (percent, stage_name)


def _noop_progress(pct: int, stage: str) -> None:
    pass


_DETECTOR_PLAIN: dict[str, dict[str, str]] = {
    "ESP-NULL-001": {
        "plain_summary": "The VPN is transmitting packets with NULL encryption (zero payload encryption).",
        "plain_impact": "User data, passwords, and sensitive files travel across the internet in plain readable text.",
        "plain_fix": "Remove NULL encryption transforms and enforce AES-GCM or AES-CBC in IPsec child proposals.",
    },
    "ESP-SEQ-001": {
        "plain_summary": "Severe sequence number gaps, duplicates, or packet reordering observed in ESP traffic.",
        "plain_impact": "Packets are being dropped or delayed in transit, degrading tunnel throughput and risking replay attacks.",
        "plain_fix": "Inspect intermediate routers for MTU clamping, verify anti-replay window sizing, and check interface errors.",
    },
    "ESP-NOIKE-001": {
        "plain_summary": "ESP encrypted traffic observed without an accompanying IKE handshake.",
        "plain_impact": "Informational finding; indicates manual static keying or that the key handshake occurred before capture started.",
        "plain_fix": "Ensure capture covers tunnel initiation or verify automated IKE key management is active.",
    },
    "AH-001": {
        "plain_summary": "The connection uses the legacy Authentication Header (AH) protocol.",
        "plain_impact": "AH provides no encryption or privacy; all transmitted data can be read by any network observer.",
        "plain_fix": "Migrate to ESP with authenticated encryption (AES-GCM) and disable AH.",
    },
    "IKE-RECON-001": {
        "plain_summary": "Multiple repeated connection attempts to non-existent or varying endpoints detected.",
        "plain_impact": "An adversary or scanner is systematically probing the network to discover active VPN gateways.",
        "plain_fix": "Restrict UDP ports 500 and 4500 using edge firewall access lists to known peer addresses.",
    },
    "IKE-DOS-001": {
        "plain_summary": "A high volume of IKE connection requests without completion was observed.",
        "plain_impact": "Potential denial-of-service flood attempting to exhaust gateway memory and state tables.",
        "plain_fix": "Enable statutory IKEv2 cookie challenges and rate-limit half-open SA handshakes.",
    },
}


class Pipeline:
    """Full streaming analysis pipeline per SPEC §4 and §5."""

    def __init__(
        self,
        config: AnalyzerConfig | None = None,
        progress: ProgressCallback = _noop_progress,
    ) -> None:
        self.config = config or AnalyzerConfig()
        self.progress = progress

    def run(
        self,
        capture_path: Path,
        policy_id: str = "nist_default",
        options: dict[str, Any] | None = None,
    ) -> AnalysisResult:
        """Run the full end-to-end analysis on *capture_path*."""
        opts = options or {}
        self.progress(0, "validating")
        self._validate_file(capture_path)

        # Stage 1: Read & decode frames
        self.progress(5, "reading")
        reader = CaptureReader(capture_path)
        decoder = PacketDecoder()
        defrag = IPv4Defragmenter(
            max_cache_bytes=self.config.defrag_max_cache_bytes,
            timeout_seconds=self.config.defrag_timeout_s,
        )
        classifier = ProtocolClassifier()
        session_rec = IkeSessionReconstructor()
        flow_tracker = FlowTracker()

        packet_count = 0
        warnings: list[str] = []

        self.progress(10, "decoding_and_tracking")
        for frame in reader.iter_frames():
            pkt = decoder.decode(frame)
            if pkt is None:
                continue

            packet_count += 1
            classifier.process(pkt)

            if packet_count >= self.config.max_packets:
                warnings.append(
                    f"Packet limit ({self.config.max_packets}) reached. Remaining packets skipped."
                )
                break

            if packet_count % 10000 == 0:
                pct = min(50, 10 + int(packet_count / self.config.max_packets * 40))
                self.progress(pct, "decoding_and_tracking")

            # Defragment
            result = defrag.process(pkt)
            if result is None:
                continue

            # Deep inspect for IKE / ESP / AH
            payload = result.payload
            sport = result.sport or 0
            dport = result.dport or 0

            # 1. UDP 500 / 4500 (IKE or NAT-T ESP)
            if result.ip_proto == 17 and (sport in (500, 4500) or dport in (500, 4500)):
                natt = False
                ike_bytes = payload

                if sport == 4500 or dport == 4500:
                    if len(payload) == 1 and payload[0] == 0xFF:
                        # NAT-T keepalive
                        pass
                    elif len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                        ike_bytes = payload[4:]
                        natt = True
                    elif len(payload) >= 8 and payload[:4] != b"\x00\x00\x00\x00":
                        # ESP inside UDP 4500
                        esp_parsed = parse_esp_packet(payload)
                        if esp_parsed:
                            spi, seq, inner = esp_parsed
                            flow_tracker.process_esp(
                                src=result.src,
                                dst=result.dst,
                                spi=spi,
                                seq=seq,
                                pkt_no=frame.pkt_no,
                                ts=frame.ts,
                                packet_len=len(payload),
                                payload_prefix=inner[:64],
                                encap="natt",
                            )

                # Attempt IKE parse
                if len(ike_bytes) >= 28:
                    version_byte = ike_bytes[17] if len(ike_bytes) > 17 else 0
                    major_v = version_byte >> 4

                    parsed_msg = None
                    if major_v == 2:
                        parsed_msg = parse_ikev2(ike_bytes)
                    elif major_v == 1:
                        parsed_msg = parse_ikev1(ike_bytes)

                    if parsed_msg:
                        model_msg = ikemessage_to_model(
                            parsed_msg,
                            pkt_no=frame.pkt_no,
                            ts=frame.ts,
                            src_ip=result.src,
                            src_port=sport,
                            dst_ip=result.dst,
                            dst_port=dport,
                            natt=natt,
                            raw_bytes=ike_bytes,
                        )
                        session_rec.process_message(model_msg)

            # 2. ESP (IP protocol 50)
            elif result.ip_proto == 50 and payload:
                esp_parsed = parse_esp_packet(payload)
                if esp_parsed:
                    spi, seq, inner = esp_parsed
                    flow_tracker.process_esp(
                        src=result.src,
                        dst=result.dst,
                        spi=spi,
                        seq=seq,
                        pkt_no=frame.pkt_no,
                        ts=frame.ts,
                        packet_len=len(payload),
                        payload_prefix=inner[:64],
                        encap="raw",
                    )

            # 3. AH (IP protocol 51)
            elif result.ip_proto == 51 and payload:
                ah_parsed = parse_ah_header(payload)
                if ah_parsed:
                    flow_tracker.process_ah(
                        src=result.src,
                        dst=result.dst,
                        spi=ah_parsed.spi,
                        seq=ah_parsed.seq,
                        pkt_no=frame.pkt_no,
                        ts=frame.ts,
                        packet_len=len(payload),
                        payload_prefix=ah_parsed.payload[:64],
                        encap="raw",
                    )

        warnings.extend(reader.metadata.warnings)
        warnings.extend(defrag.warnings)
        if decoder.unsupported_linktypes:
            warnings.append(
                f"Unsupported link types encountered: {sorted(decoder.unsupported_linktypes)}"
            )

        # Stage 2: Reconstruct sessions and flows (50-60%)
        self.progress(55, "reconstructing_sessions")
        sessions = session_rec.get_sessions()
        flows = flow_tracker.get_flows()

        # Run ESP-NULL heuristic on each flow
        for flow in flows:
            state = flow_tracker.flows.get(flow.id)
            if state and state.sample_payload_prefixes:
                null_res = check_esp_null(state.sample_payload_prefixes)
                flow.null_suspected = null_res.null_suspected
                flow.null_confidence = null_res.confidence
                flow.inferred_mode = null_res.inferred_mode

        # Pair directional flows and link to IKE sessions
        pair_flows(flows)
        link_flows_to_ike_sessions(flows, sessions)

        # Stage 3: Build Facts (65%)
        self.progress(65, "building_facts")
        clf_result = classifier.result()
        clf_result.warnings.extend(warnings)
        facts = build_facts(
            classifier_result=clf_result,
            sessions=sessions,
            flows=flows,
            warnings=warnings,
        )

        # Stage 4: Policy evaluation and security checks (75%)
        self.progress(75, "evaluating_security_rules")
        raw_findings: list[RawFinding] = []

        # Load policy
        try:
            policy = load_policy(policy_id)
        except Exception:
            policy = load_policy("nist_default")

        rule_engine = RuleEngine(policy)
        raw_findings.extend(rule_engine.evaluate(facts))

        # Run heuristic and behavioral detectors
        detector_cfg = getattr(policy, "detector_settings", {}) or {}
        raw_findings.extend(detect_negotiation_anomalies(facts, detector_cfg))
        raw_findings.extend(detect_ike_floods(facts, detector_cfg))
        raw_findings.extend(detect_ike_scans(facts, detector_cfg))
        raw_findings.extend(detect_protocol_anomalies(facts, detector_cfg))
        raw_findings.extend(detect_esp_anomalies(facts, detector_cfg))

        # Stage 5: Scoring and Posture (85%)
        self.progress(85, "scoring_and_posture")
        findings: list[Finding] = []
        for rf in raw_findings:
            risk_score = calculate_risk(rf.impact, rf.likelihood, rf.confidence)
            sev = calculate_severity(risk_score, rf.impact, rf.override_severity)
            if sev == "Info":
                risk_score = None

            # Parameter fingerprint
            param_str = ",".join(f"{k}={v}" for k, v in sorted(rf.params.items()))
            fingerprint = hashlib.sha1(f"{rf.rule_id}|{param_str}".encode()).hexdigest()[:16]
            finding_id = f"f_{hashlib.sha256(f'{rf.rule_id}_{fingerprint}_{len(findings)}'.encode()).hexdigest()[:12]}"

            # Plain language fields
            p_summary = rf.plain_summary or _DETECTOR_PLAIN.get(rf.rule_id, {}).get("plain_summary") or rf.title
            p_impact = rf.plain_impact or _DETECTOR_PLAIN.get(rf.rule_id, {}).get("plain_impact") or rf.why_this_matters
            p_fix = rf.plain_fix or _DETECTOR_PLAIN.get(rf.rule_id, {}).get("plain_fix") or "Investigate and reconfigure the parameter according to security recommendations."

            findings.append(
                Finding(
                    id=finding_id,
                    rule_id=rf.rule_id,
                    origin=rf.origin,
                    category=rf.category,
                    title=rf.title,
                    explanation=rf.explanation,
                    why_this_matters=rf.why_this_matters,
                    impact=rf.impact,
                    likelihood=rf.likelihood,
                    confidence=rf.confidence,
                    evidence=rf.evidence,
                    affected_sessions=rf.affected_sessions,
                    count=rf.count,
                    references=rf.references,
                    mitre=rf.mitre,
                    recommendation_id=rf.recommendation_id,
                    params=rf.params,
                    override_severity=rf.override_severity,
                    plain_summary=p_summary,
                    plain_impact=p_impact,
                    plain_fix=p_fix,
                    risk_score=risk_score,
                    severity=sev,
                    scoring={
                        "formula": f"{rf.impact}*{rf.likelihood}/25*100*(0.5+0.5*{rf.confidence})" if sev != "Info" else "not scored",
                        "overridden": bool(rf.override_severity),
                        "not_scored": sev == "Info",
                    },
                    fingerprint=fingerprint,
                )
            )

        # Sort findings by risk score descending (Info findings with None at the end)
        findings.sort(key=lambda f: f.risk_score if f.risk_score is not None else -1.0, reverse=True)

        # Compute posture
        posture = calculate_posture(findings)

        # Prioritize recommendations
        self.progress(92, "generating_recommendations")
        recommendations = prioritize_recommendations(findings)

        # Extract IOCs
        iocs = extract_iocs(facts, findings)

        # Generate Narrative and Phase 4 Explainable Story
        self.progress(96, "generating_narrative")
        enable_llm = bool(opts.get("enable_llm", False))
        narrative = generate_narrative(
            posture=posture,
            findings=findings,
            capture_meta=facts.capture,
            recommendations=recommendations,
            facts=facts,
            enable_llm=enable_llm,
        )

        # Deterministic 5-point Report Card & Stories (Phase 4)
        from analyzer.explain.engine import (
            generate_esp_flow_story,
            generate_ike_story,
            generate_report_card,
        )
        narrative["report_card"] = generate_report_card(facts, findings, posture, recommendations)
        narrative["ike_stories"] = {s.id: generate_ike_story(s) for s in facts.sessions}
        narrative["esp_stories"] = {f.id: generate_esp_flow_story(f) for f in facts.flows}

        self.progress(100, "done")

        return AnalysisResult(
            facts=facts,
            findings=findings,
            posture=posture,
            recommendations=recommendations,
            iocs=iocs,
            narrative=narrative,
            ml_status={"status": "unavailable", "reason": "Evaluated with rule-based heuristics only"},
            coverage_notes=list(facts.warnings) + [
                "Passive observation only; IKE_AUTH and child SA encrypted payloads unobserved without keys.",
                "ESP encryption keys unobserved; plaintext detection based on IPv4 checksum heuristics.",
            ],
            analyzer_version="0.1.0",
        )

    def _validate_file(self, path: Path | str) -> None:
        path = Path(path)
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
