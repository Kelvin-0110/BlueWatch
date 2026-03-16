# BlueWatch
### Windows Process & Service Monitoring Agent
**Detection Rules, Resources & References**

> Blue Team Endpoint Security Framework

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Detection Rules](#2-detection-rules)
3. [Whitelist / Blacklist Engine](#3-whitelist--blacklist-engine)
4. [MITRE ATT&CK® Reference](#4-mitre-attck-reference)
5. [Libraries & Dependencies](#5-libraries--dependencies)
6. [External Resources & References](#6-external-resources--references)
7. [Alert Severity Reference](#7-alert-severity-reference)
8. [Report Output Formats](#8-report-output-formats)

---

# 1. Project Overview

BlueWatch is a lightweight blue-team monitoring agent for Windows endpoints. It enumerates running processes and Windows services at scan time, applies a layered set of detection rules, and produces structured reports in JSON, CSV, plain-text, and HTML formats. The agent is designed to function as a practical EDR (Endpoint Detection & Response) prototype, covering the most common attacker techniques seen in real-world intrusions.

## 1.1  Architecture

The project is split across six Python modules, each with a single responsibility:

| File | Purpose | Rules Implemented |
| --- | --- | --- |
| `process_monitor.py` | Process enumeration, parent-child tree, all process-level detection rules (Rules 1–5) | Rules 1, 2, 3, 4, 4b, 5 |
| `service_auditor.py` | Windows service enumeration via WMI / sc.exe, suspicious service detection | Service Rule |
| `whitelist_engine.py` | Whitelist / blacklist classification pass over all running processes | WL Rule (layers 1–5) |
| `alert_logger.py` | Structured alert formatting, severity ranking, JSON / CSV / TXT output | — |
| `report_generator.py` | HTML dashboard generation with tabbed alert view and process/service tables | — |
| `main.py` | Orchestrator: runs all detection steps, deduplicates alerts, writes reports | — |

---

# 2. Detection Rules

Each rule is implemented as a standalone function in `process_monitor.py` or `whitelist_engine.py`. Rules can be enabled or disabled independently in `main.py`.

---

## Rule 1 — Office Application → Shell Execution

| Field | Value |
| --- | --- |
| **Severity** | `HIGH` |
| **MITRE ATT&CK** | T1203 / T1059.001 / T1059.003 |
| **Source File** | `process_monitor.py` → `detect_suspicious_chains()` |

**Description**

Phishing documents often contain malicious macros that silently launch PowerShell or cmd.exe to download and execute a payload. Detecting a Microsoft Office application (Word, Excel, Outlook, PowerPoint, OneNote) spawning any shell interpreter is one of the highest-fidelity signals in endpoint security — legitimate Office usage almost never requires spawning an external shell.

**Detection Logic**

```
parent in {winword.exe, excel.exe, outlook.exe, powerpnt.exe, onenote.exe}
AND child in {powershell.exe, cmd.exe}
→ SUSPICIOUS_CHAIN  severity=HIGH
```

**False-Positive Mitigations**

- Office spawning legitimate child processes (e.g. a PDF viewer) is not flagged — only shell interpreters are in the chain rule set.
- The exact MITRE codes differ per child: T1059.001 for PowerShell, T1059.003 for cmd.

**Example Alert Output**

```
[HIGH] SUSPICIOUS_CHAIN  |  2026-03-15T11:27:12
  Reason : Word document spawned PowerShell — likely macro payload
  MITRE  : T1203 / T1059.001
  Parent : winword.exe  PID=1892  C:\Program Files\Microsoft Office\...
  Child  : powershell.exe  PID=4234  C:\Windows\System32\...
```

---

## Rule 2 — CMD → PowerShell Post-Exploitation Chain

| Field | Value |
| --- | --- |
| **Severity** | `MEDIUM` |
| **MITRE ATT&CK** | T1059.003 / T1059.001 |
| **Source File** | `process_monitor.py` → `detect_suspicious_chains()` |

**Description**

A very common attacker one-liner is `cmd /c powershell -enc <base64 payload>`. This pattern — a Command Prompt spawning PowerShell — indicates an attacker who already has code execution and is staging a further payload. It is rated MEDIUM (not HIGH) because it is less definitively malicious than an Office application doing the same thing; system administrators also occasionally run this legitimately.

**Detection Logic**

```
parent == cmd.exe
AND child == powershell.exe
→ SUSPICIOUS_CHAIN  severity=MEDIUM
```

**False-Positive Mitigations**

- Severity is deliberately MEDIUM — this alert is most actionable when combined with a Rule 5 (encoded cmdline) alert on the same PID.
- `cmd.exe` spawning `mshta.exe` is separately rated HIGH (LOLBin abuse).

**Example Alert Output**

```
[MEDIUM] SUSPICIOUS_CHAIN  |  2026-03-15T11:27:12
  Reason : cmd.exe spawned PowerShell — common post-exploitation staging
  MITRE  : T1059.003 / T1059.001
  Parent : cmd.exe  PID=3820
  Child  : powershell.exe  PID=4234
```

---

## Rule 3 — Execution from Suspicious Directory

| Field | Value |
| --- | --- |
| **Severity** | `HIGH` |
| **MITRE ATT&CK** | T1036 / T1036.001 |
| **Source File** | `process_monitor.py` → `detect_suspicious_processes()` |

**Description**

Malware almost always avoids Program Files and System32 because writing there requires elevated privileges. Instead, malware drops executables into world-writable or user-writable locations such as `%TEMP%`, the user's Desktop, Downloads, `AppData\Roaming`, or `C:\Users\Public`. Any process running from one of these directories is a strong indicator of compromise.

**Detection Logic**

```
exe_path.lower() contains any of:
  \temp\               \appdata\local\temp\
  \appdata\roaming\    \users\public\
  \downloads\          \desktop\          \recycle
→ SUSPICIOUS_PROCESS  severity=HIGH
```

**False-Positive Mitigations**

- Trusted AppData sub-paths allow-listed before matching: `\AppData\Local\Python\` (MS Store Python), `\AppData\Local\Programs\` (VS Code), `\AppData\Local\Microsoft\` (Teams/OneDrive), `\AppData\Local\Google\` (Chrome).
- `\ProgramData\` is intentionally excluded — Windows Defender, NVIDIA, Lenovo and other vendors legitimately install services there.

**Example Alert Output**

```
[HIGH] SUSPICIOUS_PROCESS  |  2026-03-15T11:27:12
  Reason : Executable in suspicious directory: C:\Users\shivu\AppData\Local\Temp\evil.exe
  MITRE  : T1036 / T1055
  Process: evil.exe  PID=7788  PPID=1024
  User   : SHIVANSH\shivu
```

---

## Rule 4 — Process Name Typosquatting / Masquerading

| Field | Value |
| --- | --- |
| **Severity** | `HIGH` |
| **MITRE ATT&CK** | T1036 / T1036.004 |
| **Source File** | `process_monitor.py` → `detect_suspicious_processes()` \| `whitelist_engine.py` |

**Description**

Attackers copy the names of well-known Windows system processes with minor variations designed to fool a human analyst at a glance: replacing the letter `l` with the digit `1` (`rundl132.exe`), inserting extra characters (`lsasss.exe`), or appending a digit (`svchost32.exe`). The agent maintains a hard-coded set of 20+ known typosquatted names and additionally runs regex patterns to catch new variants.

**Detection Logic**

```
name in SUSPICIOUS_NAMES set:
  svch0st.exe   expl0rer.exe  lsasss.exe
  svchost32.exe svchost64.exe rundl132.exe  etc.
OR name matches typosquat regex patterns
→ SUSPICIOUS_PROCESS  severity=HIGH
```

**False-Positive Mitigations**

- Exact membership check (O(1) set lookup) before regex scan — fast even at high process counts.
- The whitelist engine runs a second pass to catch typosquats missed by the first scan.

**Example Alert Output**

```
[HIGH] SUSPICIOUS_PROCESS  |  2026-03-15T11:27:12
  Reason : Typosquatted system process name: svch0st.exe
  MITRE  : T1036 / T1055
  Process: svch0st.exe  PID=4512  PPID=1024
  Path   : C:\Users\Admin\AppData\Local\svch0st.exe
```

---

## Rule 4b — Masquerade by Path (Correct Name, Wrong Directory)

| Field | Value |
| --- | --- |
| **Severity** | `CRITICAL` |
| **MITRE ATT&CK** | T1036.005 |
| **Source File** | `process_monitor.py` → `_is_masquerading()` \| `whitelist_engine.py` |

**Description**

A more sophisticated masquerade keeps the exact correct name (`svchost.exe`, `lsass.exe`, `csrss.exe`, etc.) but drops the binary in a non-system directory like `C:\Users\Public\` or `C:\Temp\`. Windows will run it, but it is definitively malicious — these eight processes are only ever launched by Windows from System32 or SysWOW64. Any other location is **CRITICAL**.

**Detection Logic**

```
name in _SYSTEM32_ONLY set:
  svchost.exe  lsass.exe  csrss.exe  smss.exe
  wininit.exe  services.exe  winlogon.exe  spoolsv.exe
AND exe_path does NOT start with:
  C:\Windows\System32\
  C:\Windows\SysWOW64\
  C:\Windows\WinSxS\
→ SUSPICIOUS_PROCESS  severity=CRITICAL
```

**False-Positive Mitigations**

- Path separators normalised to backslash before comparison — prevents bypass via forward-slash paths.
- Only the 8 most critical system-only processes are in the set to eliminate false positives from legitimately-relocated binaries.

**Example Alert Output**

```
[CRITICAL] SUSPICIOUS_PROCESS  |  2026-03-15T11:27:12
  Reason : System process 'svchost.exe' running outside System32
           — masquerade attack (T1036.005):
             C:\Users\Public\svchost.exe
  MITRE  : T1036 / T1036.005
```

---

## Rule 5 — Encoded / Obfuscated PowerShell Command Line

| Field | Value |
| --- | --- |
| **Severity** | `CRITICAL` |
| **MITRE ATT&CK** | T1059.001 / T1027 |
| **Source File** | `process_monitor.py` → `detect_encoded_powershell()` |

**Description**

Attackers almost always base64-encode their PowerShell payloads to evade signature-based detection. PowerShell accepts the encoded payload via the `-enc` / `-EncodedCommand` / `-e` flag. Beyond encoding, attackers combine multiple evasion flags: `-WindowStyle Hidden` (no visible window), `-NoProfile` (avoids detection via profile), `-ExecutionPolicy Bypass` (disables script restrictions). The agent also detects in-memory download cradles using `IEX` + `WebClient` that fetch and execute remote payloads without writing to disk.

**Detection Logic**

```
IF process name in {powershell.exe, pwsh.exe}:
  cmdline matches -enc / -EncodedCommand / -e   → CRITICAL
  cmdline matches -w hidden / -WindowStyle Hidden → HIGH
  cmdline matches -nop / -NoProfile               → HIGH
  cmdline matches -ep bypass                      → HIGH
  cmdline contains IEX( or Invoke-Expression      → HIGH
  cmdline contains DownloadString / WebClient      → HIGH
  cmdline contains [Convert]::FromBase64          → HIGH
```

**False-Positive Mitigations**

- Only fires for `powershell.exe` and `pwsh.exe` — `cmd.exe` is never flagged.
- Clean PowerShell invocations (e.g. `Get-Process`) do not trigger any pattern.
- Command line preview truncated to 120 chars in alert to avoid log bloat.

**Example Alert Output**

```
[CRITICAL] ENCODED_POWERSHELL  |  2026-03-15T11:27:12
  Reason : Encoded PowerShell command (-enc / -EncodedCommand)
           — base64 payload concealment;
           Hidden window flag (-w hidden);
           NoProfile flag (-nop)
  MITRE  : T1059.001 / T1027
  CmdLine: powershell -nop -w hidden -enc aGVsbG8gd29ybGQ=
```

---

## Rule SVC — Suspicious Windows Service Detection

| Field | Value |
| --- | --- |
| **Severity** | `HIGH` / `MEDIUM` |
| **MITRE ATT&CK** | T1543.003 / T1574 / T1574.005 |
| **Source File** | `service_auditor.py` → `detect_suspicious_services()` |

**Description**

Attackers establish persistence by installing malicious Windows services. Three indicators are checked: (1) service names that are typosquats of legitimate services, (2) service binaries located in writable user directories, (3) genuine unquoted service path vulnerabilities (T1574.005) where a path containing a space is not quoted, allowing Windows to be tricked into executing an attacker-controlled binary in a parent directory.

**Detection Logic**

```
IF service_name in SUSPICIOUS_SERVICE_NAMES
  OR service_name matches typosquat regex    → flag
IF binary_path contains \Temp\ \Public\
  \AppData\Local\Temp\ \Downloads\           → flag
IF binary_path has space AND not quoted
  AND exe portion (not args) has space
  AND NOT rooted in C:\Windows\System32\     → flag T1574.005
```

**False-Positive Mitigations**

- `\ProgramData\` excluded from suspicious dirs — Defender, NVIDIA, Lenovo all install legitimate services there. Explicit allow-list: `\ProgramData\Microsoft\`, `\ProgramData\NVIDIA\`, `\ProgramData\Lenovo\`, etc.
- `svchost.exe -k netsvcs -p` is **NOT** flagged as unquoted path — the space is an argument separator, not part of the executable path. The unquoted-path check extracts the exe portion before any flag arguments.

**Example Alert Output**

```
[HIGH] SUSPICIOUS_SERVICE  |  2026-03-15T11:27:12
  Reason : Service binary in suspicious directory;
           Unquoted service path (T1574.005)
  MITRE  : T1543.003 / T1574
  Service: UpdateManagerX (Update Manager)
  Path   : C:\Users\Public\temp\update.exe
```

---

# 3. Whitelist / Blacklist Engine

The whitelist engine in `whitelist_engine.py` runs as a second, independent classification pass over all processes after the primary detection functions. It applies five layered checks and only emits an alert when the signal is strong enough to avoid false-positive noise.

| Layer | Check | Description | Severity | MITRE |
| --- | --- | --- | --- | --- |
| 1 | Hard Blacklist | Process name is in `PROCESS_BLACKLIST` (WannaCry droppers, known typosquats like `scvhost.exe`, `crss.exe`) | `CRITICAL` | T1036 |
| 2 | Masquerade Path | Legitimate system binary name running outside System32/SysWOW64 (duplicate of Rule 4b for belt-and-suspenders) | `CRITICAL` | T1036.005 |
| 3 | Typosquat Regex | Name matches one of the compiled regex patterns for numeric/symbol substitution (`svchost32`, `lsass64`, etc.) | `HIGH` | T1036.004 |
| 4 | Whitelist Miss | Name not found in `SYSTEM_WHITELIST` (100+ known-good process names). Informational on its own — only escalates when combined with another layer. | `LOW` | — |
| 5 | Suspicious Path | Executable path is in a high-risk writable directory after applying the trusted-prefix allow-list. | `HIGH` (escalates) | T1036 / T1055 |

---

# 4. MITRE ATT&CK® Reference

All detection rules are mapped to the MITRE ATT&CK Enterprise matrix. The table below lists every technique referenced in the project.

| Technique ID | Technique Name | Tactic | Used In Rule(s) |
| --- | --- | --- | --- |
| T1003 | OS Credential Dumping | Credential Access | Rule 1 (lsass→cmd) |
| T1027 | Obfuscated Files or Information | Defense Evasion | Rule 5 |
| T1036 | Masquerading | Defense Evasion | Rules 3, 4, 4b, SVC, WL |
| T1036.004 | Masquerading: Match Legitimate Name or Location | Defense Evasion | Rule 4, WL Layer 3 |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | Rule 4b, WL Layer 2 |
| T1047 | Windows Management Instrumentation | Execution | Rule 1 (wmiprvse) |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Rule 1 (taskeng) |
| T1055 | Process Injection | Defense Evasion | Rules 3, 4, WL |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Rules 1, 2, 5 |
| T1059.003 | Command and Scripting Interpreter: Windows Shell | Execution | Rules 1, 2 |
| T1059.005 | Command and Scripting Interpreter: VBScript | Execution | Rule 1 (wscript/cscript) |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | Rule 1 (spoolsv) |
| T1203 | Exploitation for Client Execution | Execution | Rule 1 (Office→shell) |
| T1218.005 | System Binary Proxy Execution: Mshta | Defense Evasion | Rule 1 (mshta) |
| T1218.007 | System Binary Proxy Execution: Msiexec | Defense Evasion | Rule 1 (msiexec) |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Defense Evasion | Rule 1 (Squiblydoo) |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Defense Evasion | Rule 1 (rundll32) |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | SVC Rule |
| T1547 | Boot or Logon Autostart Execution | Persistence | WL Rule |
| T1574 | Hijack Execution Flow | Persistence | SVC Rule |
| T1574.005 | Hijack Execution Flow: Unquoted Service Path | Persistence | SVC Rule |

---

# 5. Libraries & Dependencies

The following Python libraries are used by the agent. Only `psutil` is strictly required for process monitoring; the others enhance service enumeration on Windows hosts.

| Library | Version / Install | Usage |
| --- | --- | --- |
| `psutil` | `pip install psutil` | Process enumeration (`process_iter`, `oneshot`), metadata extraction (pid, name, exe, cmdline, username, create_time, ppid, status). Core dependency — required for all process-level detection rules. |
| `wmi` | `pip install wmi` | Windows service enumeration via Win32_Service WMI class. Provides richer data than sc.exe (binary path, start mode, state). Falls back to sc.exe if unavailable. Windows + pywin32 only. |
| `pywin32` | `pip install pywin32` | Underlying COM bridge required by the wmi library on Windows. Not imported directly by the agent. |
| `re` | stdlib | Compiled regex patterns for typosquat detection (`_SUSPICIOUS_NAME_PATTERNS`), encoded PowerShell detection (`_ENCODED_PS_PATTERN`, `_EVASION_PATTERNS`), unquoted path extraction, and service name matching (`_TYPO_PATTERN`). |
| `subprocess` | stdlib | `sc.exe` fallback: `subprocess.check_output(['sc','query',...])` enumerates services and `sc qc` retrieves binary paths when WMI/pywin32 is not available. |
| `json` | stdlib | Serialises alert dicts and summary payload to `alert_*.json` output files in `alert_logger.save_json()`. |
| `csv` | stdlib | Writes flat alert table to `alerts_*.csv` in `alert_logger.save_csv()` for SIEM ingestion. |
| `datetime` | stdlib | ISO-8601 timestamps on every alert dict; process creation time conversion from Unix epoch; report filename generation. |
| `argparse` | stdlib | CLI argument parsing in `main.py`: `--watch`, `--out`, `--no-services`. |

---

# 6. External Resources & References

## 6.1  MITRE ATT&CK

- MITRE ATT&CK Enterprise Matrix — <https://attack.mitre.org/matrices/enterprise/>
- ATT&CK Navigator (visualise coverage) — <https://mitre-attack.github.io/attack-navigator/>
- Technique T1059 — Command and Scripting Interpreter — <https://attack.mitre.org/techniques/T1059/>
- Technique T1036 — Masquerading — <https://attack.mitre.org/techniques/T1036/>
- Technique T1203 — Exploitation for Client Execution — <https://attack.mitre.org/techniques/T1203/>
- Technique T1543.003 — Windows Service — <https://attack.mitre.org/techniques/T1543/003/>
- Technique T1574.005 — Unquoted Service Path — <https://attack.mitre.org/techniques/T1574/005/>

## 6.2  Threat Intelligence & Research

- SANS Institute — Hunting for Suspicious Parent-Child Process Relationships — <https://www.sans.org/white-papers/>
- Red Canary — Threat Detection Report (annual, Office macro techniques) — <https://redcanary.com/threat-detection-report/>
- Elastic Security Labs — Hunting for Malicious PowerShell — <https://www.elastic.co/security-labs/>
- Microsoft DART — Encoded PowerShell Detections — <https://www.microsoft.com/en-us/security/blog/>
- SwiftOnSecurity — Sysmon configuration (process chain detection baselines) — <https://github.com/SwiftOnSecurity/sysmon-config>
- Sigma Rules — Open detection rules including Office→PS chains — <https://github.com/SigmaHQ/sigma>
- LOLBAS Project — Living Off the Land Binaries reference (mshta, regsvr32, rundll32) — <https://lolbas-project.github.io/>

## 6.3  Python Libraries

- psutil documentation — <https://psutil.readthedocs.io/>
- psutil GitHub — <https://github.com/giampaolo/psutil>
- pywin32 / wmi library — <https://pypi.org/project/wmi/>
- Python re module (regex) — <https://docs.python.org/3/library/re.html>

## 6.4  Windows Internals & Process Tree Research

- Microsoft — Process and Thread Functions (Windows API) — <https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions>
- Microsoft — Service Control Manager (SCM) — <https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager>
- Microsoft — Win32_Service WMI class — <https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service>
- Hexacorn — Parent Process IDs and Process Spoofing — <https://www.hexacorn.com/blog/>
- Didier Stevens — Suspicious PowerShell Command Lines — <https://blog.didierstevens.com/>

## 6.5  Unquoted Service Path

- CVE / Advisory Reference — Unquoted Service Path Privilege Escalation
- Tenable — Unquoted Service Path (T1574.005) — <https://www.tenable.com/blog/>
- PowerSploit / PowerUp — Service path enumeration tooling — <https://github.com/PowerShellMafia/PowerSploit>

---

# 7. Alert Severity Reference

The agent uses four severity levels. Every alert dict carries a `severity` field. The HTML dashboard and text report both sort by severity descending.

| Severity | Score | When Assigned | Recommended Action |
| --- | --- | --- | --- |
| `CRITICAL` | 4 | Rule 4b (masquerade-by-path), Rule 5 (-enc), WL hard blacklist | Immediate investigation. Isolate endpoint. Assume compromise. |
| `HIGH` | 3 | Rule 1 (Office→shell), Rule 3 (suspicious dir), Rule 4 (typosquat), LOLBin chains, encoded PS evasion flags | Investigate within 1 hour. Collect process memory and logs. |
| `MEDIUM` | 2 | Rule 2 (cmd→ps), single-signal whitelist hits, single-flag suspicious service | Review during next SOC shift. Correlate with other alerts. |
| `LOW` | 1 | WL: process not in whitelist (no other signals) | Informational. Log and monitor. No immediate action required. |

---

# 8. Report Output Formats

Every scan writes four files into the output directory:

| Format | Filename Pattern | Contents & Use Case |
| --- | --- | --- |
| JSON | `alerts_YYYYMMDD_HHMMSS.json` | Machine-readable payload: summary object (`total_alerts`, `by_severity`, `by_type`) + full sorted alerts array. Use for SIEM ingestion, automated processing, or programmatic analysis. |
| CSV | `alerts_YYYYMMDD_HHMMSS.csv` | Flat table with columns: `timestamp`, `severity`, `type`, `reason`, `mitre`, `name`, `pid`, `ppid`, `exe`, `username`. One row per alert. Use for Excel analysis or direct SIEM import. |
| Text | `report_YYYYMMDD_HHMMSS.txt` | Human-readable formatted report with header, severity counts, and one formatted block per alert sorted by severity. Use for email distribution or archival. |
| HTML Dashboard | `dashboard_YYYYMMDD_HHMMSS.html` | Dark-theme interactive dashboard. Tabbed alert view (All / Chains / Processes / Services), severity donut chart, full process table (up to 200 rows), full service table. Open in any browser — no external dependencies. |

---

*BlueWatch — Windows Process & Service Monitoring Agent*
*Presented by: Shivansh Sharma | Cybersecurity Intern — Unified Mentor | B.Tech CSE (Cyber Security)*