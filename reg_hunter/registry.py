"""Low-level registry access via winreg."""

from __future__ import annotations

import winreg
from typing import Any, Iterator

from reg_hunter.targets import HiveName

_HIVE_MAP: dict[HiveName, int] = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
}


def open_key(hive: HiveName, path: str, *, write: bool = False) -> winreg.HKEY:
    access = winreg.KEY_READ
    if write:
        access |= winreg.KEY_WRITE
    return winreg.OpenKey(_HIVE_MAP[hive], path, 0, access)


def enum_values(key: winreg.HKEY) -> Iterator[tuple[str, Any, int]]:
    index = 0
    while True:
        try:
            yield winreg.EnumValue(key, index)
        except OSError:
            break
        index += 1


def enum_subkeys(key: winreg.HKEY) -> Iterator[str]:
    index = 0
    while True:
        try:
            yield winreg.EnumKey(key, index)
        except OSError:
            break
        index += 1


def read_value(hive: HiveName, path: str, name: str) -> tuple[Any, int] | None:
    try:
        with open_key(hive, path) as key:
            return winreg.QueryValueEx(key, name)
    except OSError:
        return None


def format_value(data: Any, reg_type: int) -> str:
    if reg_type == winreg.REG_SZ:
        return str(data)
    if reg_type in (winreg.REG_EXPAND_SZ,):
        return str(data)
    if reg_type == winreg.REG_DWORD:
        return f"DWORD:{data}"
    if reg_type == winreg.REG_MULTI_SZ:
        return " | ".join(data)
    if reg_type == winreg.REG_BINARY:
        return data.hex()
    return repr(data)
