#!/usr/bin/env python3
"""
Reg-Hunter — Windows Registry Persistence Scanner

Malware forensics tool: audits auto-run keys, startup folders, and UserAssist
(ROT-13 decoded). Compare live state to baseline.json to alert on new entries.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reg_hunter import __version__
from reg_hunter.baseline import compare_to_baseline, load_baseline, save_baseline
from reg_hunter.report import print_diff, print_json, print_snapshot
from reg_hunter.scanner import collect_snapshot


def _default_baseline() -> Path:
    return Path(__file__).resolve().parent / "baseline.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reg_hunter",
        description="Audit Windows Registry persistence and compare against a clean baseline.",
    )
    parser.add_argument("--version", action="version", version=f"Reg-Hunter {__version__}")

    parser.add_argument(
        "-b",
        "--baseline",
        type=Path,
        default=_default_baseline(),
        help="Path to baseline.json (default: ./baseline.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout",
    )
    parser.add_argument(
        "--show-removed",
        action="store_true",
        help="When diffing, also list entries removed since baseline",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--create-baseline",
        action="store_true",
        help="Capture current registry state as the trusted baseline",
    )
    group.add_argument(
        "--scan",
        action="store_true",
        help="Full live scan (no baseline comparison)",
    )
    group.add_argument(
        "--compare",
        action="store_true",
        help="Diff live registry against baseline; alert on NEW entries only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print("Reg-Hunter requires Windows (winreg).", file=sys.stderr)
        return 2

    args = build_parser().parse_args(argv)
    baseline_path: Path = args.baseline

    # Default mode: compare if baseline exists, else instruct user.
    mode = "compare"
    if args.create_baseline:
        mode = "create"
    elif args.scan:
        mode = "scan"
    elif args.compare:
        mode = "compare"
    elif not baseline_path.is_file():
        mode = "help"

    if mode == "help":
        print(
            "No baseline.json found. Create a clean-system baseline first:\n"
            f"  python reg_hunter.py --create-baseline -b {baseline_path}\n"
            "Then run periodic checks:\n"
            f"  python reg_hunter.py --compare -b {baseline_path}",
            file=sys.stderr,
        )
        return 1

    if mode == "create":
        snapshot = save_baseline(baseline_path)
        if args.json:
            print_json({"status": "baseline_created", "path": str(baseline_path), **snapshot.to_dict()})
        else:
            print(f"Baseline written: {baseline_path}")
            print(f"  Registry entries: {len(snapshot.registry)}")
            print(f"  Startup files:      {len(snapshot.startup)}")
            print(f"  UserAssist items:   {len(snapshot.userassist)}")
        return 0

    snapshot = collect_snapshot()

    if mode == "scan":
        if args.json:
            print_json(snapshot.to_dict())
        else:
            print_snapshot(snapshot)
        return 0

    # compare
    try:
        baseline = load_baseline(baseline_path)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    diff = compare_to_baseline(baseline, snapshot)
    if args.json:
        print_json(
            {
                "baseline": str(baseline_path),
                "alerts": diff.alert_count,
                "new": {
                    "registry": diff.new_registry,
                    "startup": diff.new_startup,
                    "userassist": diff.new_userassist,
                },
                "removed": {
                    "registry": diff.removed_registry,
                    "startup": diff.removed_startup,
                    "userassist": diff.removed_userassist,
                },
            }
        )
    else:
        print_diff(diff, show_removed=args.show_removed)

    return 1 if diff.has_new_entries else 0


if __name__ == "__main__":
    raise SystemExit(main())
