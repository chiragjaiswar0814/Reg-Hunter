"""Registry paths and persistence locations to audit."""

from dataclasses import dataclass
from typing import Literal

HiveName = Literal["HKCU", "HKLM"]


@dataclass(frozen=True)
class RegistryTarget:
    hive: HiveName
    path: str
    category: str


# Standard auto-run keys (malware persistence hotspots).
AUTORUN_TARGETS: tuple[RegistryTarget, ...] = (
    RegistryTarget(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "autorun_run",
    ),
    RegistryTarget(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "autorun_runonce",
    ),
    RegistryTarget(
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "autorun_run",
    ),
    RegistryTarget(
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "autorun_runonce",
    ),
    RegistryTarget(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "policy_run",
    ),
    RegistryTarget(
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "policy_run",
    ),
)

USERASSIST_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

# Shell folder value names used to resolve startup directory paths.
STARTUP_FOLDER_VALUE_NAMES: tuple[str, ...] = ("Startup", "Common Startup")
