# Reg-Hunter

**Windows Registry Persistence Scanner** — a Python forensics utility that audits common malware persistence locations in the live registry, decodes UserAssist execution history, and alerts only when something new appears compared to a trusted baseline.

> **Role:** Malware artifact forensics · **Platform:** Windows only · **Dependencies:** Python standard library (`winreg`)

---

## Features

- **Auto-run keys** — Scans standard persistence hives and values:
  - `HKCU` / `HKLM` → `Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU` / `HKLM` → `...\RunOnce`
  - `HKCU` / `HKLM` → `...\Policies\Explorer\Run`
- **Startup folders** — Enumerates user and common Startup directories (`.exe`, `.lnk`, `.bat`, `.ps1`, etc.)
- **UserAssist forensics** — Parses `HKCU\...\Explorer\UserAssist\{GUID}\Count`, decodes Microsoft's **ROT-13** obfuscation on program names, and extracts run counts and last-execution timestamps
- **Baseline diffing** — Capture `baseline.json` on a clean system; later scans report **new entries only** (ideal for change detection and incident triage)
- **JSON output** — `--json` for scripting, CI, or log aggregation

---

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Windows 10/11 (or Server with equivalent registry layout) |
| Python | 3.10+ recommended |
| Packages | None — uses built-in `winreg`, `struct`, `codecs` |
| Privileges | Standard user is sufficient for `HKCU` and most `HKLM` Run keys; some `HKLM` values may require elevation |

---

## Installation

```powershell
git clone https://github.com/YOUR_USERNAME/Reg-Hunter.git
cd Reg-Hunter
```

No `pip install` step is required. Run directly:

```powershell
python reg_hunter.py --version
```

---

## Quick start

### 1. Create a baseline (trusted clean state)

Run this once on a system you consider clean — before infection or right after a verified rebuild:

```powershell
python reg_hunter.py --create-baseline
```

This writes `baseline.json` in the project directory (or the path you pass with `-b`).

### 2. Run periodic audits

```powershell
python reg_hunter.py --compare
```

- **Exit code `0`** — No new entries vs baseline  
- **Exit code `1`** — New persistence or UserAssist programs detected  

### 3. Full live scan (no comparison)

```powershell
python reg_hunter.py --scan
```

---

## CLI reference

```
usage: reg_hunter [--version] [-b BASELINE] [--json] [--show-removed]
                  [--create-baseline | --scan | --compare]

options:
  -b, --baseline PATH     Baseline file (default: ./baseline.json)
  --json                  Machine-readable JSON on stdout
  --show-removed          When diffing, list entries removed since baseline
  --create-baseline       Capture current state as trusted baseline
  --scan                  Full live scan without baseline comparison
  --compare               Diff live registry against baseline (default if baseline exists)
  --version               Show version and exit
```

**Examples**

```powershell
# Custom baseline location
python reg_hunter.py --create-baseline -b C:\Forensics\clean_baseline.json
python reg_hunter.py --compare -b C:\Forensics\clean_baseline.json

# JSON for automation
python reg_hunter.py --compare --json > diff_report.json

# Include removals in the report
python reg_hunter.py --compare --show-removed
```

If no `baseline.json` exists and you run the tool without flags, it prints setup instructions and exits with code `1`.

---

## What gets scanned

### Registry auto-run

| Hive | Path |
|------|------|
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Run` |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| HKLM | `Software\Microsoft\Windows\CurrentVersion\Run` |
| HKLM | `Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| HKCU / HKLM | `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` |

### Startup folders

Resolved via Shell Folders registry values, with fallbacks to:

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`

### UserAssist

- Root: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
- Each `{GUID}\Count` value name is **ROT-13 decoded** to reveal the GUI program path
- Binary `Count` blobs are parsed for Windows XP (16-byte) and Windows 7+ (72-byte) layouts

---

## Baseline format

`baseline.json` is a snapshot with three sections:

```json
{
  "version": 1,
  "created_at": "2026-05-16T12:00:00+00:00",
  "registry": [ { "id": "HKCU\\...", "hive": "HKCU", "path": "...", "name": "...", "value": "..." } ],
  "startup":  [ { "id": "Startup\\C:\\...", "full_path": "...", "name": "..." } ],
  "userassist": [ { "id": "UserAssist\\{guid}\\...", "program": "...", "run_count": 42 } ]
}
```

Each item has a stable `id` used for diffing. **Do not commit host-specific baselines** — `baseline.json` is listed in `.gitignore`.

---

## Project structure

```
Reg-Hunter/
├── reg_hunter.py          # CLI entry point
├── reg_hunter/
│   ├── scanner.py         # Snapshot collection
│   ├── registry.py        # winreg helpers
│   ├── userassist.py      # ROT-13 + Count parser
│   ├── startup.py         # Startup folder enumeration
│   ├── baseline.py        # Create / load / diff
│   ├── report.py          # Console output
│   └── targets.py         # Registry paths
├── requirements.txt       # Stdlib only (documentation)
├── baseline.json          # Generated locally (gitignored)
└── README.md
```

---

## Forensics notes

- **Baseline timing matters.** Capture the baseline when the system is known clean. Anything installed afterward (legitimate or malicious) will appear as “new.”
- **UserAssist is execution history**, not strictly persistence. New programs there indicate GUI apps the user (or malware posing as the user) launched — valuable context, but interpret alongside Run keys and startup files.
- **Legitimate software updates** can change Run values (paths, arguments). Re-baseline after intentional software changes to avoid false positives.
- This tool performs **live** analysis. For offline hive analysis, export the registry with `reg save` or forensic tools and extend the project as needed.

---

## Limitations

- Windows-only (`winreg` is not available on Linux/macOS hosts for live scans)
- Does not cover all persistence vectors (scheduled tasks, services, WMI, etc.)
- `HKLM` access may be incomplete without administrator rights
- UserAssist list can be large; `--scan` shows the 50 most recent entries in the console (use `--json` for the full set)

---

## Contributing

Issues and pull requests are welcome. When adding new persistence locations, update `reg_hunter/targets.py` and document them in this README.

---

## License

Specify your license here (e.g. MIT). Add a `LICENSE` file to the repository root if you publish under an open-source license.

---

## Disclaimer

Reg-Hunter is a forensic **aid**, not a replacement for antivirus, EDR, or professional incident response. Use only on systems you own or are authorized to analyze.
