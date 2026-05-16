"""UserAssist key parser with ROT-13 name decoding."""

from __future__ import annotations

import codecs
import struct
import winreg
from dataclasses import dataclass
from datetime import datetime, timezone

from reg_hunter import registry
from reg_hunter.targets import USERASSIST_ROOT


def rot13_decode(text: str) -> str:
    """Decode Microsoft's ROT-13 obfuscation on UserAssist value names."""
    return codecs.decode(text, "rot_13")


def _filetime_to_datetime(filetime: int) -> datetime | None:
    if filetime <= 0:
        return None
    # FILETIME: 100-ns intervals since 1601-01-01 UTC.
    try:
        return datetime.fromtimestamp((filetime - 116444736000000000) / 1e7, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


@dataclass(frozen=True)
class UserAssistEntry:
    guid: str
    encoded_name: str
    program: str
    run_count: int | None
    focus_count: int | None
    last_run_utc: datetime | None
    raw_size: int


def parse_count_blob(data: bytes) -> tuple[int | None, int | None, datetime | None]:
    """Parse UserAssist Count value binary (XP 16-byte or Win7+ 72-byte layout)."""
    size = len(data)
    if size >= 72:
        run_count = struct.unpack_from("<I", data, 4)[0]
        focus_count = struct.unpack_from("<I", data, 8)[0]
        last_run = _filetime_to_datetime(struct.unpack_from("<q", data, 60)[0])
        return run_count, focus_count, last_run
    if size >= 16:
        run_count = max(0, struct.unpack_from("<I", data, 4)[0] - 5)
        last_run = _filetime_to_datetime(struct.unpack_from("<q", data, 8)[0])
        return run_count, None, last_run
    return None, None, None


def scan_userassist() -> list[UserAssistEntry]:
    """Enumerate all UserAssist {GUID}\\Count entries."""
    entries: list[UserAssistEntry] = []
    try:
        with registry.open_key("HKCU", USERASSIST_ROOT) as root:
            guids = list(registry.enum_subkeys(root))
    except OSError:
        return entries

    for guid in guids:
        count_path = f"{USERASSIST_ROOT}\\{guid}\\Count"
        try:
            with registry.open_key("HKCU", count_path) as count_key:
                for encoded_name, data, reg_type in registry.enum_values(count_key):
                    if reg_type != winreg.REG_BINARY or not isinstance(data, bytes):
                        continue
                    program = rot13_decode(encoded_name)
                    run_count, focus_count, last_run = parse_count_blob(data)
                    entries.append(
                        UserAssistEntry(
                            guid=guid,
                            encoded_name=encoded_name,
                            program=program,
                            run_count=run_count,
                            focus_count=focus_count,
                            last_run_utc=last_run,
                            raw_size=len(data),
                        )
                    )
        except OSError:
            continue
    return entries
