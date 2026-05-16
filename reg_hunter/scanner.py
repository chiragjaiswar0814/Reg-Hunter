"""Collect persistence artifacts from registry and startup folders."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from reg_hunter import registry, startup, userassist
from reg_hunter.targets import AUTORUN_TARGETS, RegistryTarget


@dataclass(frozen=True)
class RegistryEntry:
    id: str
    hive: str
    path: str
    name: str
    value: str
    reg_type: int
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanSnapshot:
    version: int
    created_at: str
    registry: list[RegistryEntry]
    startup: list[dict[str, Any]]
    userassist: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "registry": [e.to_dict() for e in self.registry],
            "startup": self.startup,
            "userassist": self.userassist,
        }


def _entry_id(hive: str, path: str, name: str) -> str:
    return f"{hive}\\{path}\\{name}"


def _scan_registry_target(target: RegistryTarget) -> list[RegistryEntry]:
    entries: list[RegistryEntry] = []
    try:
        with registry.open_key(target.hive, target.path) as key:
            for name, data, reg_type in registry.enum_values(key):
                entries.append(
                    RegistryEntry(
                        id=_entry_id(target.hive, target.path, name),
                        hive=target.hive,
                        path=target.path,
                        name=name,
                        value=registry.format_value(data, reg_type),
                        reg_type=reg_type,
                        category=target.category,
                    )
                )
    except OSError:
        pass
    return entries


def scan_autorun() -> list[RegistryEntry]:
    results: list[RegistryEntry] = []
    for target in AUTORUN_TARGETS:
        results.extend(_scan_registry_target(target))
    return results


def _userassist_to_dict(entry: userassist.UserAssistEntry) -> dict[str, Any]:
    last_run = entry.last_run_utc.isoformat() if entry.last_run_utc else None
    return {
        "id": f"UserAssist\\{entry.guid}\\{entry.program}",
        "guid": entry.guid,
        "encoded_name": entry.encoded_name,
        "program": entry.program,
        "run_count": entry.run_count,
        "focus_count": entry.focus_count,
        "last_run_utc": last_run,
        "raw_size": entry.raw_size,
    }


def _startup_to_dict(item: startup.StartupFile) -> dict[str, Any]:
    return {
        "id": f"Startup\\{item.full_path}",
        "folder": item.folder,
        "name": item.name,
        "full_path": item.full_path,
        "size_bytes": item.size_bytes,
    }


def collect_snapshot() -> ScanSnapshot:
    now = datetime.now(timezone.utc).isoformat()
    ua_entries = userassist.scan_userassist()
    startup_entries = startup.scan_startup_folders()
    return ScanSnapshot(
        version=1,
        created_at=now,
        registry=scan_autorun(),
        startup=[_startup_to_dict(s) for s in startup_entries],
        userassist=[_userassist_to_dict(u) for u in ua_entries],
    )
