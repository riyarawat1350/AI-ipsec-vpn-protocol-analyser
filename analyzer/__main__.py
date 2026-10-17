"""CLI entry point: python -m analyzer analyze <file> [--out result.json]

TASK-012 — FR-07, FR-86.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analyzer.errors import AnalyzerError
from analyzer.pipeline import Pipeline


def _progress(pct: int, stage: str) -> None:
    print(f"  [{pct:3d}%] {stage}", flush=True)


def cmd_analyze(args: argparse.Namespace) -> int:
    capture = Path(args.file)
    out_path = Path(args.out) if args.out else None

    print(f"IPsecScope Analyzer — {capture.name}")
    print("-" * 50)

    try:
        pipeline = Pipeline(progress=_progress if not args.quiet else lambda p, s: None)
        result = pipeline.run(capture)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except AnalyzerError as exc:
        print(f"ERROR [{exc.code}]: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 4

    output = result.model_dump(mode="json")

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2))
        print(f"\nResult saved to: {out_path}")
    else:
        print("\n" + json.dumps(output, indent=2))

    # Summary
    cap = result.facts.capture
    ps = result.facts.protocol_stats
    print(f"\n{'='*50}")
    print(f"  Total packets : {cap.get('total_packets', 0)}")
    print(f"  Duration      : {cap.get('duration_seconds', 0):.2f}s")
    print(f"  Protocol dist : {ps.get('counts', {})}")
    print(f"  Findings      : {len(result.findings)}")
    print(f"{'='*50}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analyzer",
        description="IPsecScope — AI-Powered IPsec VPN Analyser",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze a pcap/pcapng capture file")
    analyze_p.add_argument("file", help="Path to capture file (.pcap / .pcapng)")
    analyze_p.add_argument("--out", "-o", metavar="FILE", help="Write JSON result to file")
    analyze_p.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
