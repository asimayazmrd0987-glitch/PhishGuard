#!/usr/bin/env python3
"""PhishGuard command-line entry point (Python port)."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from phishguard.benchmark import run_benchmarks
from phishguard.detection_data import DetectionData
from phishguard.engine import ScanService
from phishguard.types import InputType
from phishguard.ui import Interface
from phishguard.demos import demo_scenarios


def usage_error(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='PhishGuard: local, explainable phishing/scam risk analysis.')
    parser.add_argument('--data', default='', help='data folder (default: auto-detect)')
    parser.add_argument('--history', default='phishguard_history.txt', help='history file (default: phishguard_history.txt)')
    parser.add_argument('--url', help='scan one URL')
    parser.add_argument('--message', help='scan one message')
    parser.add_argument('--demo', action='store_true', help='run 14 demo scenarios')
    parser.add_argument('--bench', action='store_true', help='run DSA benchmarks')
    args = parser.parse_args(argv)
    if args.bench:
        run_benchmarks()
        return 0
    data_dir = DetectionData.find_data_directory(args.data)
    if not data_dir:
        return usage_error('Could not find data/ (risk_config.txt). Run from project folder or pass --data <folder>.')
    try:
        data = DetectionData.load_from_directory(data_dir)
        service = ScanService(data)
        if args.demo:
            interface = Interface(data, args.history)
            interface.run_demos()
            return 0
        if args.url is not None:
            result = service.scan_url(args.url)
            _print_one_result(result)
            # CLI one-shot scans are also recorded, consistent with interactive scans.
            interface = Interface(data, args.history)
            scan_id = interface.history.add(result)
            from phishguard.graph_builder import add_scan_to_graph
            add_scan_to_graph(interface.graph, scan_id, result)
            interface.save_history()
            return 0
        if args.message is not None:
            result = service.scan_message(args.message)
            _print_one_result(result)
            interface = Interface(data, args.history)
            scan_id = interface.history.add(result)
            from phishguard.graph_builder import add_scan_to_graph
            add_scan_to_graph(interface.graph, scan_id, result)
            interface.save_history()
            return 0
        return Interface(data, args.history).run()
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


def _print_one_result(result) -> None:
    print(f'Risk Score : {result.score} / 100\nRisk Level : {result.level.name}')
    if result.indicators:
        print('\nWhy this score:')
        for indicator in result.indicators:
            print(f' [+{indicator.weight}] {indicator.description}')
    else:
        print('\nNo suspicious signs were found by our checks.')
    print('\nRecommendation:\n' + result.recommendation)
    print('\nPhishGuard is an educational tool. A LOW result is not a guarantee of safety, and a high result is not proof of a scam.')

if __name__ == '__main__':
    raise SystemExit(main())
