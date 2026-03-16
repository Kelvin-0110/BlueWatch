# BlueWatch 

**Windows Process & Service Monitoring Agent — Blue Team Edition**

A lightweight, EDR-style endpoint monitoring agent that detects suspicious process behaviour, service misconfigurations, and common attacker techniques on Windows systems. Produces structured alerts with MITRE ATT&CK mappings and an interactive HTML dashboard.

---

## Table of Contents

- [Features](#features)
- [Detection Rules](#detection-rules)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output & Reports](#output--reports)
- [False-Positive Mitigations](#false-positive-mitigations)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Extending the Agent](#extending-the-agent)
- [License](#license)

---

## Features

- **Process tree analysis** — builds a parent-child process map and flags known-bad execution chains (Office → PowerShell, CMD → PowerShell, LOLBin abuse, etc.)
- **Encoded PowerShell detection** — inspects command lines of all PowerShell processes for `-enc`, `-EncodedCommand`, `-w hidden`, `IEX`, `WebClient`, and more
- **Masquerade-by-path detection** — catches attackers who use the exact correct system binary name (`svchost.exe`) but run it from the wrong directory
- **Typosquat detection** — hard-coded blacklist + regex patterns for `svch0st.exe`, `rundl132.exe`, `lsasss.exe`, etc.
- **Suspicious directory detection** — flags executables running from `%TEMP%`, `AppData\Roaming`, `Desktop`, `Downloads`, `Users\Public`
- **Windows service auditing** — detects suspicious service names, binaries in writable paths, and genuine unquoted service path vulnerabilities
- **Whitelist / blacklist engine** — 5-layer classification pass over all running processes
- **Multi-format reports** — JSON, CSV, plain-text, and a dark-theme interactive HTML dashboard
- **Continuous monitoring mode** — `--watch N` re-scans every N seconds
- **Zero false-positives by design** — Windows Defender, NVIDIA, Lenovo, MS Store Python, VS Code, and other common vendor installs are explicitly allow-listed

---

## Detection Rules

| # | Rule | Severity | MITRE |
|---|------|----------|-------|
| 1 | Office app (Word / Excel / Outlook / PowerPoint / OneNote) spawning PowerShell or cmd.exe | HIGH | T1203 / T1059.001 |
| 1b | Browser (Chrome / Firefox / Edge) spawning PowerShell | HIGH | T1203 / T1059.001 |
| 2 | `cmd.exe` spawning `powershell.exe` — post-exploitation staging | MEDIUM | T1059.003 / T1059.001 |
| 3 | Executable running from `%TEMP%`, `AppData\Roaming`, `Desktop`, `Downloads`, `Users\Public` | HIGH | T1036 |
| 4 | Typosquatted system process name (`svch0st.exe`, `lsasss.exe`, `rundl132.exe`, …) | HIGH | T1036.004 |
| 4b | Legitimate system binary name running outside `System32` / `SysWOW64` | CRITICAL | T1036.005 |
| 5 | Encoded or obfuscated PowerShell command line (`-enc`, `-w hidden`, `IEX`, `WebClient`, …) | CRITICAL / HIGH | T1059.001 / T1027 |
| SVC | Suspicious Windows service — typosquatted name, binary in writable path, unquoted path vuln | HIGH / MEDIUM | T1543.003 / T1574 |
| WL | Whitelist / blacklist pass — hard blacklist, masquerade-by-path, typosquat regex, unknown process | CRITICAL → LOW | T1036 / T1055 |

### LOLBin Chain Coverage (Rule 1 extensions)

The following additional parent → child chains are also detected:

```
wscript.exe  → powershell.exe      (VBScript dropper)
cscript.exe  → powershell.exe      (VBScript dropper)
mshta.exe    → powershell.exe      (HTA dropper — T1218.005)
mshta.exe    → cmd.exe
powershell.exe → mshta.exe         (LOLBin proxy)
cmd.exe      → mshta.exe
lsass.exe    → cmd.exe             (credential dumping indicator)
svchost.exe  → cmd.exe / powershell.exe   (hollow process indicator)
services.exe → cmd.exe
spoolsv.exe  → cmd.exe             (print spooler exploit indicator)
taskeng.exe  → powershell.exe / cmd.exe   (scheduled task persistence)
wmiprvse.exe → powershell.exe / cmd.exe   (WMI lateral movement)
msiexec.exe  → powershell.exe / cmd.exe   (malicious installer)
regsvr32.exe → powershell.exe / cmd.exe   (Squiblydoo — T1218.010)
rundll32.exe → powershell.exe / cmd.exe   (DLL proxy — T1218.011)
```

---

## Project Structure

```
bluewatch_agent/
└── monitor/
    ├── main.py              # Orchestrator — runs all rules, writes reports
    ├── process_monitor.py   # Rules 1–5: chain detection, dir check, masquerade, encoded PS
    ├── service_auditor.py   # Service enumeration and suspicious service detection
    ├── whitelist_engine.py  # 5-layer whitelist / blacklist classification engine
    ├── alert_logger.py      # Alert formatting, severity ranking, JSON/CSV/TXT output
    ├── report_generator.py  # HTML dashboard generation
    └── requirements.txt     # Python dependencies
```

---

## Requirements

- **Python** 3.10 or higher (3.12+ recommended)
- **Windows** 10 / 11 / Server 2016+ (for full functionality)
- **psutil** — required
- **wmi + pywin32** — optional, enables richer service data via WMI

> The agent runs on Linux/macOS for development and testing (process detection works; service enumeration requires Windows).

---

## Installation

### 1. Clone or extract the project

```powershell
# If using git
git clone https://github.com/yourname/bluewatch.git
cd bluewatch/monitor

# Or extract the zip and navigate to the monitor folder
cd bluewatch_agent\monitor
```

### 2. Install dependencies

```powershell
# Minimum install (process monitoring only)
pip install -r requirements.txt

# Or manually:
pip install psutil

# Full install (includes Windows service enumeration via WMI)
pip install psutil wmi pywin32
```

### 3. Verify installation

```powershell
python -c "import psutil; print('psutil', psutil.__version__, '— OK')"
```

---

## Usage

Run from inside the `monitor/` directory:

```powershell
# Single scan — results saved to ./reports/
python main.py

# Skip Windows service enumeration (faster, no WMI required)
python main.py --no-services

# Continuous monitoring — re-scan every 60 seconds
python main.py --watch 60

# Custom output directory
python main.py --out C:\BlueWatch\logs

# Combine flags
python main.py --watch 120 --out C:\BlueWatch\logs --no-services
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--watch N` | `0` (single scan) | Re-scan every N seconds. Press `Ctrl+C` to stop. |
| `--out PATH` | `./reports` | Directory to write all report files into. Created if absent. |
| `--no-services` | off | Skip Windows service enumeration. |

### Example console output

```
+==================================================================+
|   Windows Process & Service Monitoring Agent                     |
|   Blue Team Endpoint Security Framework                          |
+==================================================================+

────────────────────────────────────────────────────────────────
  Scan #1  |  2026-03-15T11:27:12.154321
────────────────────────────────────────────────────────────────
[*] Enumerating active processes...
    -> 187 processes found
[*] Enumerating Windows services...
    -> 312 services found
[*] Running detection rules...
    Rule 1/2  (chains)              : 0 alert(s)
    Rule 3/4/4b (process behaviour) : 0 alert(s)
    Rule 5  (encoded PowerShell)    : 0 alert(s)
    Services                        : 1 alert(s)
    Whitelist engine                : 3 alert(s)

[!] 4 total alert(s):

[HIGH] SUSPICIOUS_PROCESS  |  2026-03-15T11:27:12
  Reason : Executable in suspicious directory
  ...

────────────────────────────────────────────────────────────────
  SUMMARY
────────────────────────────────────────────────────────────────
  Total alerts  : 4
  HIGH      : ████ 4

  Reports saved to : ./reports
  HTML dashboard   : ./reports/dashboard_20260315_112712.html
────────────────────────────────────────────────────────────────
```

---

## Output & Reports

Every scan writes four files into the output directory:

| File | Format | Description |
|------|--------|-------------|
| `alerts_YYYYMMDD_HHMMSS.json` | JSON | Machine-readable payload: summary + full sorted alert array. Use for SIEM ingestion. |
| `alerts_YYYYMMDD_HHMMSS.csv` | CSV | Flat alert table (timestamp, severity, type, reason, mitre, name, pid, ppid, exe, username). |
| `report_YYYYMMDD_HHMMSS.txt` | Plain text | Human-readable formatted report sorted by severity. |
| `dashboard_YYYYMMDD_HHMMSS.html` | HTML | Interactive dark-theme dashboard — open in any browser. |

### HTML Dashboard

The HTML dashboard includes:

- **Executive summary** — donut chart + per-severity count cards
- **Tabbed alert view** — All / Suspicious Chains / Processes / Services
- **Full process table** — all running processes (up to 200 rows)
- **Full service table** — all Windows services (up to 200 rows)

No internet connection or external dependencies required — the dashboard is fully self-contained.

### Sample JSON alert

```json
{
  "type": "SUSPICIOUS_CHAIN",
  "severity": "HIGH",
  "reason": "Word document spawned PowerShell — likely macro payload",
  "mitre": "T1203 / T1059.001",
  "timestamp": "2026-03-15T11:27:12.239586",
  "parent": { "name": "winword.exe", "pid": 1892, "exe": "C:\\...\\WINWORD.EXE" },
  "child":  { "name": "powershell.exe", "pid": 4234, "exe": "C:\\...\\powershell.exe" }
}
```

---

## False-Positive Mitigations

The following are explicitly allow-listed and will **never** generate alerts:

| Category | Allow-listed paths / names |
|----------|--------------------------|
| Windows Defender | `C:\ProgramData\Microsoft\Windows Defender\...` |
| NVIDIA drivers | `C:\ProgramData\NVIDIA\...` |
| Lenovo Vantage | `C:\ProgramData\Lenovo\...` |
| Python (MS Store) | `AppData\Local\Python\...` |
| VS Code | `AppData\Local\Programs\Microsoft VS Code\...` |
| Chrome (user install) | `AppData\Local\Google\Chrome\...` |
| OneDrive / Teams | `AppData\Local\Microsoft\...` |
| Office add-ins | `AppData\Roaming\Microsoft\...` |
| Common apps | Spotify, Discord, Zoom, Slack (`AppData\Roaming\...`) |
| svchost.exe args | `svchost.exe -k netsvcs -p` — not an unquoted path vuln |

The **unquoted service path** check was rewritten to extract only the executable portion of the path before any `-flag` arguments. This eliminates the 200+ false positives that the naive `" " in path` check produced against every `svchost.exe -k <group>` service.

---

## MITRE ATT&CK Coverage

| Technique | Name | Rule(s) |
|-----------|------|---------|
| T1003 | OS Credential Dumping | Rule 1 (lsass → cmd) |
| T1027 | Obfuscated Files or Information | Rule 5 |
| T1036 | Masquerading | Rules 3, 4, 4b, WL |
| T1036.004 | Match Legitimate Name or Location | Rule 4 |
| T1036.005 | Match Legitimate Name or Location (path) | Rule 4b |
| T1047 | Windows Management Instrumentation | Rule 1 (wmiprvse) |
| T1053.005 | Scheduled Task | Rule 1 (taskeng) |
| T1055 | Process Injection | Rules 3, 4, WL |
| T1059.001 | PowerShell | Rules 1, 2, 5 |
| T1059.003 | Windows Command Shell | Rules 1, 2 |
| T1059.005 | VBScript | Rule 1 (wscript/cscript) |
| T1068 | Exploitation for Privilege Escalation | Rule 1 (spoolsv) |
| T1203 | Exploitation for Client Execution | Rule 1 (Office → shell) |
| T1218.005 | Mshta | Rule 1 |
| T1218.007 | Msiexec | Rule 1 |
| T1218.010 | Regsvr32 (Squiblydoo) | Rule 1 |
| T1218.011 | Rundll32 | Rule 1 |
| T1543.003 | Windows Service | SVC Rule |
| T1547 | Boot or Logon Autostart Execution | WL Rule |
| T1574 | Hijack Execution Flow | SVC Rule |
| T1574.005 | Unquoted Service Path | SVC Rule |

---

## Extending the Agent

### Adding a new chain rule

Open `process_monitor.py` and add a tuple to `_CHAIN_RULES`:

```python
("parent.exe", "child.exe"): ("HIGH", "Reason string for the alert", "T1059.001"),
```

### Adding a new suspicious process name

Add to the `SUSPICIOUS_NAMES` set in `process_monitor.py`:

```python
SUSPICIOUS_NAMES: set[str] = {
    ...
    "mynewmalware.exe",
}
```

### Adding a new trusted AppData path

Add to `TRUSTED_APPDATA_PREFIXES` in `process_monitor.py`:

```python
TRUSTED_APPDATA_PREFIXES: tuple[str, ...] = (
    ...
    "\\appdata\\local\\mynewapp\\",
)
```

### Adding a new detection rule function

1. Write a `def detect_my_rule(processes: list[dict]) -> list[dict]:` function in `process_monitor.py`
2. Import and call it in `main.py` inside `run_scan()`
3. Add its alerts to `all_alerts`

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [LOLBAS Project](https://lolbas-project.github.io/) — Living Off the Land Binaries
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — Open detection rule format
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — Process chain baselines
- [psutil documentation](https://psutil.readthedocs.io/)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)

---

## License

MIT License — free to use, modify, and distribute for blue-team and educational purposes.
