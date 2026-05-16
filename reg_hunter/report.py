"""Console reporting for scans and baseline diffs."""

from __future__ import annotations

import sys
from typing import Any, TextIO

from reg_hunter.baseline import DiffResult
from reg_hunter.scanner import ScanSnapshot


def _print_section(title: str, stream: TextIO) -> None:
    stream.write(f"\n{'=' * 60}\n{title}\n{'=' * 60}\n")


def print_snapshot(snapshot: ScanSnapshot, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    data = snapshot.to_dict()
    _print_section("AUTO-RUN REGISTRY KEYS", out)
    for entry in data["registry"]:
        out.write(f"  [{entry['hive']}] {entry['name']}\n")
        out.write(f"    Path:  {entry['path']}\n")
        out.write(f"    Value: {entry['value']}\n\n")

    _print_section("STARTUP FOLDERS", out)
    if not data["startup"]:
        out.write("  (no tracked files)\n")
    for item in data["startup"]:
        out.write(f"  {item['name']}\n")
        out.write(f"    {item['full_path']} ({item['size_bytes']} bytes)\n\n")

    _print_section("USERASSIST (ROT-13 DECODED)", out)
    if not data["userassist"]:
        out.write("  (no UserAssist Count entries)\n")
    shown = sorted(data["userassist"], key=lambda x: x.get("last_run_utc") or "", reverse=True)
    for item in shown[:50]:
        out.write(f"  {item['program']}\n")
        out.write(f"    Runs: {item['run_count']}  Last: {item['last_run_utc']}\n\n")
    if len(shown) > 50:
        out.write(f"  ... and {len(shown) - 50} more (use --json for full export)\n")


def print_diff(diff: DiffResult, *, show_removed: bool = False, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    if not diff.has_new_entries:
        out.write("\n[OK] No new persistence entries compared to baseline.\n")
        return

    out.write(f"\n[ALERT] {diff.alert_count} new entr{'y' if diff.alert_count == 1 else 'ies'} vs baseline\n")

    if diff.new_registry:
        _print_section("NEW REGISTRY PERSISTENCE", out)
        for entry in diff.new_registry:
            out.write(f"  [{entry['hive']}] {entry['name']}\n")
            out.write(f"    {entry['path']}\n")
            out.write(f"    => {entry['value']}\n\n")

    if diff.new_startup:
        _print_section("NEW STARTUP FOLDER FILES", out)
        for item in diff.new_startup:
            out.write(f"  {item['full_path']}\n\n")

    if diff.new_userassist:
        _print_section("NEW USERASSIST PROGRAMS", out)
        for item in diff.new_userassist:
            out.write(f"  {item['program']}\n")
            out.write(f"    Runs: {item['run_count']}  Last: {item['last_run_utc']}\n\n")

    if show_removed:
        removed = diff.removed_registry + diff.removed_startup + diff.removed_userassist
        if removed:
            _print_section("REMOVED SINCE BASELINE (informational)", out)
            for item in removed:
                out.write(f"  {item.get('id', item)}\n")


def print_json(data: Any, stream: TextIO | None = None) -> None:
    import json

    out = stream or sys.stdout
    json.dump(data, out, indent=2)
    out.write("\n")
