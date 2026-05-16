"""Startup folder persistence (filesystem complement to Run keys)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from reg_hunter import registry
from reg_hunter.targets import STARTUP_FOLDER_VALUE_NAMES

SHELL_FOLDERS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
USER_SHELL_FOLDERS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

TRACKED_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".lnk", ".url"}


@dataclass(frozen=True)
class StartupFile:
    folder: str
    name: str
    full_path: str
    size_bytes: int


def _resolve_folder(value_name: str) -> str | None:
    for path_key, hive in (
        (SHELL_FOLDERS_PATH, "HKCU"),
        (USER_SHELL_FOLDERS_PATH, "HKCU"),
    ):
        result = registry.read_value(hive, path_key, value_name)
        if result:
            return str(result[0])
    return None


def _default_startup_paths() -> list[str]:
    paths: list[str] = []
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("ProgramData", r"C:\ProgramData")
    if appdata:
        paths.append(
            os.path.join(
                appdata,
                r"Microsoft\Windows\Start Menu\Programs\Startup",
            )
        )
    paths.append(
        os.path.join(
            programdata,
            r"Microsoft\Windows\Start Menu\Programs\StartUp",
        )
    )
    return paths


def scan_startup_folders() -> list[StartupFile]:
    """List executable/script shortcuts in user and common Startup folders."""
    folders: list[str] = []
    for name in STARTUP_FOLDER_VALUE_NAMES:
        resolved = _resolve_folder(name)
        if resolved and os.path.isdir(resolved):
            folders.append(resolved)
    for fallback in _default_startup_paths():
        if os.path.isdir(fallback) and fallback not in folders:
            folders.append(fallback)

    results: list[StartupFile] = []
    for folder in folders:
        try:
            for entry in os.scandir(folder):
                if not entry.is_file():
                    continue
                if Path(entry.name).suffix.lower() not in TRACKED_EXTENSIONS:
                    continue
                stat = entry.stat()
                results.append(
                    StartupFile(
                        folder=folder,
                        name=entry.name,
                        full_path=entry.path,
                        size_bytes=stat.st_size,
                    )
                )
        except OSError:
            continue
    return results
