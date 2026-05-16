"""Baseline capture and diff against live registry state."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reg_hunter.scanner import ScanSnapshot, collect_snapshot


@dataclass
class DiffResult:
    new_registry: list[dict[str, Any]]
    new_startup: list[dict[str, Any]]
    new_userassist: list[dict[str, Any]]
    removed_registry: list[dict[str, Any]]
    removed_startup: list[dict[str, Any]]
    removed_userassist: list[dict[str, Any]]

    @property
    def has_new_entries(self) -> bool:
        return bool(self.new_registry or self.new_startup or self.new_userassist)

    @property
    def alert_count(self) -> int:
        return len(self.new_registry) + len(self.new_startup) + len(self.new_userassist)


def save_baseline(path: Path, snapshot: ScanSnapshot | None = None) -> ScanSnapshot:
    snapshot = snapshot or collect_snapshot()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
    return snapshot


def load_baseline(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Baseline not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _index_by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in items}


def compare_to_baseline(
    baseline: dict[str, Any],
    live: ScanSnapshot | None = None,
) -> DiffResult:
    """Return entries present in live scan but absent from baseline (alerts)."""
    live = live or collect_snapshot()
    live_dict = live.to_dict()

    base_reg = _index_by_id(baseline.get("registry", []))
    live_reg = _index_by_id(live_dict["registry"])

    base_startup = _index_by_id(baseline.get("startup", []))
    live_startup = _index_by_id(live_dict["startup"])

    base_ua = _index_by_id(baseline.get("userassist", []))
    live_ua = _index_by_id(live_dict["userassist"])

    return DiffResult(
        new_registry=[live_reg[k] for k in live_reg if k not in base_reg],
        new_startup=[live_startup[k] for k in live_startup if k not in base_startup],
        new_userassist=[live_ua[k] for k in live_ua if k not in base_ua],
        removed_registry=[base_reg[k] for k in base_reg if k not in live_reg],
        removed_startup=[base_startup[k] for k in base_startup if k not in live_startup],
        removed_userassist=[base_ua[k] for k in base_ua if k not in live_ua],
    )
