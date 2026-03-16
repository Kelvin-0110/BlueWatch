"""
process_monitor.py
==================
Process enumeration, parent-child tree building, and all behaviour-based
detection rules.

Detection rules
---------------
Rule 1  — Office → PowerShell/Shell           (MITRE T1203 / T1059)  HIGH
Rule 2  — CMD → PowerShell chain              (MITRE T1059)           MEDIUM
Rule 3  — Execution from suspicious directory  (MITRE T1036)          HIGH
Rule 4  — Process name masquerading / typosquat(MITRE T1036)          HIGH
Rule 4b — Legitimate name, wrong directory    (MITRE T1036)           CRITICAL
Rule 5  — Encoded PowerShell command line     (MITRE T1059.001)       CRITICAL

Each rule is implemented as a standalone detect_* function so new rules can
be added or removed independently, and main.py can call them selectively.

False-positive mitigations
--------------------------
- \\programdata\\ is NOT flagged — Defender, NVIDIA, Lenovo etc. live there.
- Trusted AppData sub-paths are allow-listed (MS Store Python, VS Code, …).
- Masquerade-by-path check only fires on the small set of processes that must
  ALWAYS live in System32/SysWOW64 (svchost, lsass, csrss, …).
"""

import re
import psutil
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# RULE 1 & 2 — Suspicious parent-child chain definitions
# ─────────────────────────────────────────────────────────────────────────────
# Each entry maps (parent_name, child_name) -> (severity, human_reason, mitre)
# This replaces the flat set so every alert carries a specific, actionable reason.

_CHAIN_RULES: dict[tuple[str, str], tuple[str, str, str]] = {

    # ── Rule 1: Office apps spawning shells (T1203 — phishing / macro execution) ──
    ("winword.exe",  "powershell.exe"): ("HIGH",   "Word document spawned PowerShell — likely macro payload",          "T1203 / T1059.001"),
    ("winword.exe",  "cmd.exe"):        ("HIGH",   "Word document spawned cmd.exe — likely macro execution",           "T1203 / T1059.003"),
    ("excel.exe",    "powershell.exe"): ("HIGH",   "Excel spreadsheet spawned PowerShell — likely macro payload",      "T1203 / T1059.001"),
    ("excel.exe",    "cmd.exe"):        ("HIGH",   "Excel spreadsheet spawned cmd.exe — likely macro execution",       "T1203 / T1059.003"),
    ("outlook.exe",  "powershell.exe"): ("HIGH",   "Outlook spawned PowerShell — likely email attachment / macro",     "T1203 / T1059.001"),
    ("outlook.exe",  "cmd.exe"):        ("HIGH",   "Outlook spawned cmd.exe — likely email attachment execution",      "T1203 / T1059.003"),
    ("powerpnt.exe", "powershell.exe"): ("HIGH",   "PowerPoint spawned PowerShell — likely macro payload",            "T1203 / T1059.001"),
    ("powerpnt.exe", "cmd.exe"):        ("HIGH",   "PowerPoint spawned cmd.exe — likely macro execution",             "T1203 / T1059.003"),
    ("onenote.exe",  "powershell.exe"): ("HIGH",   "OneNote spawned PowerShell — common phishing lure technique",     "T1203 / T1059.001"),
    ("onenote.exe",  "cmd.exe"):        ("HIGH",   "OneNote spawned cmd.exe — common phishing lure technique",        "T1203 / T1059.003"),

    # ── Rule 1b: Browsers spawning interpreters ────────────────────────────────
    ("chrome.exe",   "powershell.exe"): ("HIGH",   "Chrome spawned PowerShell — possible drive-by / malvertising",   "T1203 / T1059.001"),
    ("firefox.exe",  "powershell.exe"): ("HIGH",   "Firefox spawned PowerShell — possible drive-by / malvertising",  "T1203 / T1059.001"),
    ("msedge.exe",   "powershell.exe"): ("HIGH",   "Edge spawned PowerShell — possible drive-by / malvertising",     "T1203 / T1059.001"),
    ("iexplore.exe", "powershell.exe"): ("HIGH",   "Internet Explorer spawned PowerShell — drive-by execution",      "T1203 / T1059.001"),

    # ── Rule 2: CMD → PowerShell (post-exploitation staging) ──────────────────
    # "cmd /c powershell -enc <payload>" is the most common attacker one-liner.
    ("cmd.exe",      "powershell.exe"): ("MEDIUM", "cmd.exe spawned PowerShell — common post-exploitation staging",  "T1059.003 / T1059.001"),
    ("cmd.exe",      "mshta.exe"):      ("HIGH",   "cmd.exe spawned mshta.exe — LOLBin abuse for payload execution", "T1059.003 / T1218.005"),

    # ── Script host / LOLBin abuse ─────────────────────────────────────────────
    ("wscript.exe",   "powershell.exe"): ("HIGH",  "wscript spawned PowerShell — script-based dropper",             "T1059.005 / T1059.001"),
    ("cscript.exe",   "powershell.exe"): ("HIGH",  "cscript spawned PowerShell — script-based dropper",             "T1059.005 / T1059.001"),
    ("mshta.exe",     "powershell.exe"): ("HIGH",  "mshta spawned PowerShell — HTA-based dropper (T1218.005)",      "T1218.005 / T1059.001"),
    ("mshta.exe",     "cmd.exe"):        ("HIGH",  "mshta spawned cmd.exe — HTA-based execution (T1218.005)",       "T1218.005 / T1059.003"),
    ("powershell.exe","mshta.exe"):      ("HIGH",  "PowerShell spawned mshta.exe — LOLBin proxy execution",         "T1059.001 / T1218.005"),

    # ── Explorer spawning a shell ──────────────────────────────────────────────
    ("explorer.exe",  "powershell.exe"): ("MEDIUM","Explorer spawned PowerShell — unexpected interactive shell",     "T1059.001"),

    # ── System processes that must never spawn shells ──────────────────────────
    ("lsass.exe",    "cmd.exe"):        ("HIGH",   "lsass spawned cmd.exe — possible credential dumping / injection","T1003 / T1059.003"),
    ("svchost.exe",  "cmd.exe"):        ("HIGH",   "svchost spawned cmd.exe — possible hollow process / injection", "T1055 / T1059.003"),
    ("svchost.exe",  "powershell.exe"): ("HIGH",   "svchost spawned PowerShell — possible hollow process / injection","T1055 / T1059.001"),
    ("services.exe", "cmd.exe"):        ("HIGH",   "services.exe spawned cmd.exe — unexpected shell from SCM",      "T1543.003 / T1059.003"),
    ("spoolsv.exe",  "cmd.exe"):        ("HIGH",   "spoolsv spawned cmd.exe — possible print spooler exploit",      "T1068 / T1059.003"),

    # ── Task scheduler / WMI lateral movement ─────────────────────────────────
    ("taskeng.exe",  "powershell.exe"): ("HIGH",   "Task scheduler spawned PowerShell — possible scheduled task persistence","T1053.005 / T1059.001"),
    ("taskeng.exe",  "cmd.exe"):        ("HIGH",   "Task scheduler spawned cmd.exe — possible scheduled task persistence",   "T1053.005 / T1059.003"),
    ("wmiprvse.exe", "powershell.exe"): ("HIGH",   "WMI spawned PowerShell — possible WMI lateral movement (T1047)",         "T1047 / T1059.001"),
    ("wmiprvse.exe", "cmd.exe"):        ("HIGH",   "WMI spawned cmd.exe — possible WMI lateral movement (T1047)",            "T1047 / T1059.003"),

    # ── Installer / COM surrogate abuse ───────────────────────────────────────
    ("msiexec.exe",  "powershell.exe"): ("HIGH",   "msiexec spawned PowerShell — malicious installer payload",      "T1218.007 / T1059.001"),
    ("msiexec.exe",  "cmd.exe"):        ("HIGH",   "msiexec spawned cmd.exe — malicious installer payload",         "T1218.007 / T1059.003"),
    ("regsvr32.exe", "cmd.exe"):        ("HIGH",   "regsvr32 spawned cmd.exe — Squiblydoo LOLBin abuse",            "T1218.010 / T1059.003"),
    ("regsvr32.exe", "powershell.exe"): ("HIGH",   "regsvr32 spawned PowerShell — Squiblydoo LOLBin abuse",         "T1218.010 / T1059.001"),
    ("rundll32.exe", "cmd.exe"):        ("HIGH",   "rundll32 spawned cmd.exe — DLL proxy execution abuse",          "T1218.011 / T1059.003"),
    ("rundll32.exe", "powershell.exe"): ("HIGH",   "rundll32 spawned PowerShell — DLL proxy execution abuse",       "T1218.011 / T1059.001"),
}

# Fast O(1) lookup set — used by detect_suspicious_chains
_CHAIN_LOOKUP: set[tuple[str, str]] = set(_CHAIN_RULES.keys())


# ─────────────────────────────────────────────────────────────────────────────
# RULE 3 — Execution from suspicious directories
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_DIRS: list[str] = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",   # %TEMP% — primary malware drop zone
    "\\appdata\\roaming\\",       # Roaming profile — common persistence location
    "\\users\\public\\",          # World-writable
    "\\downloads\\",
    "\\desktop\\",
    "\\recycle",
    "/tmp/",
    "/var/tmp/",
]

# Trusted AppData sub-paths that are legitimate install locations.
# Checked BEFORE the suspicious dir scan — any match suppresses the alert.
TRUSTED_APPDATA_PREFIXES: tuple[str, ...] = (
    "\\appdata\\local\\python\\",       # Python via Microsoft Store
    "\\appdata\\local\\programs\\",     # VS Code, GitHub Desktop, etc.
    "\\appdata\\local\\microsoft\\",    # OneDrive, Teams, Edge WebView2
    "\\appdata\\local\\google\\",       # Chrome user-level install
    "\\appdata\\roaming\\microsoft\\",  # Office add-ins, shell components
    "\\appdata\\roaming\\spotify\\",
    "\\appdata\\roaming\\discord\\",
    "\\appdata\\roaming\\zoom\\",
    "\\appdata\\roaming\\slack\\",
)


# ─────────────────────────────────────────────────────────────────────────────
# RULE 4 — Typosquatted / spoofed process names
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_NAMES: set[str] = {
    "svch0st.exe",     "svchost32.exe",   "svchost64.exe",
    "expl0rer.exe",    "explorer32.exe",
    "lsasss.exe",      "lsass64.exe",
    "csrss32.exe",     "csrss64.exe",
    "wininit32.exe",   "services32.exe",  "taskhost32.exe",
    "systemupdate.exe","system_update.exe","windowsupdate.exe",
    "chrome32.exe",    "firefox32.exe",   "spoolsv32.exe",
    "rundl132.exe",    # digit 1 instead of lowercase L
    "iexplore32.exe",  "notepad32.exe",   "winlogon32.exe",
}


# ─────────────────────────────────────────────────────────────────────────────
# RULE 4b — Masquerade by path (legitimate name, wrong directory)
# ─────────────────────────────────────────────────────────────────────────────
# These processes MUST live in System32 or SysWOW64. If they are found
# running from anywhere else, it is almost certainly a masquerade attack.

_SYSTEM32_ONLY: set[str] = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "services.exe", "winlogon.exe", "spoolsv.exe",
}

_SYSTEM_ROOTS: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
)


# ─────────────────────────────────────────────────────────────────────────────
# RULE 5 — Encoded / obfuscated PowerShell command line
# ─────────────────────────────────────────────────────────────────────────────

_PS_NAMES: set[str] = {"powershell.exe", "pwsh.exe"}

# All common variations attackers use to pass encoded payloads
_ENCODED_PS_PATTERN = re.compile(
    r"(\s|^)(-|/)(e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\s",
    re.IGNORECASE,
)

# Additional obfuscation / evasion flags worth flagging
_EVASION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(\s|^)(-|/)w\w*\s+hid", re.I),
     "Hidden window flag (-w hidden) — concealing execution"),
    (re.compile(r"(\s|^)(-|/)nop\w*(\s|$)", re.I),
     "NoProfile flag (-nop) — bypassing profile-based detection"),
    (re.compile(r"(\s|^)(-|/)ex\w*\s+byp", re.I),
     "ExecutionPolicy Bypass (-ep bypass) — disabling script restrictions"),
    (re.compile(r"(\s|^)(-|/)sta(\s|$)", re.I),
     "STA apartment flag (-sta) — common in shellcode runners"),
    (re.compile(r"iex\s*\(", re.I),
     "Invoke-Expression (IEX) — remote code execution pattern"),
    (re.compile(r"invoke-expression", re.I),
     "Invoke-Expression — remote code execution pattern"),
    (re.compile(r"\[convert\]::frombase64", re.I),
     "[Convert]::FromBase64String — base64 payload decoding"),
    (re.compile(r"downloadstring|downloadfile|webclient", re.I),
     "WebClient download — in-memory payload staging"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_attr(proc: psutil.Process, attr: str, default=None):
    """Safely read a psutil attribute, returning default on any exception."""
    try:
        val = getattr(proc, attr)
        return val() if callable(val) else val
    except Exception:
        return default


def _is_suspicious_dir(path: str) -> bool:
    """Return True if the executable path is in a known high-risk directory.

    Path separators are normalised to backslashes before matching so that
    forward-slash paths (some Windows APIs, unit tests) match correctly.
    """
    low = path.lower().replace("/", "\\")
    if any(tp in low for tp in TRUSTED_APPDATA_PREFIXES):
        return False
    return any(sd in low for sd in SUSPICIOUS_DIRS)


def _is_suspicious_name(name: str) -> bool:
    """Return True if the process name is a known typosquat of a system binary."""
    return name.lower() in SUSPICIOUS_NAMES


def _is_masquerading(name: str, exe: str) -> bool:
    """
    Return True if a process uses a trusted system binary name but runs from
    a directory other than System32 / SysWOW64 / WinSxS.

    Example: svchost.exe running from C:\\Users\\Public\\svchost.exe is CRITICAL.
    """
    if name.lower() not in _SYSTEM32_ONLY:
        return False
    if not exe:
        return False
    # Normalise separators so forward-slash paths still match backslash roots
    low_exe = exe.lower().replace("/", "\\")
    return not any(low_exe.startswith(root) for root in _SYSTEM_ROOTS)


# ─────────────────────────────────────────────────────────────────────────────
# Process enumeration
# ─────────────────────────────────────────────────────────────────────────────

def get_process_info(proc: psutil.Process) -> dict:
    """Return a normalised metadata dict for a single process, or {} on error."""
    try:
        with proc.oneshot():
            pid     = proc.pid
            name    = (proc.name() or "").lower()
            ppid    = _safe_attr(proc, "ppid", 0)
            exe     = _safe_attr(proc, "exe",  "") or ""
            uname   = ""
            try:
                uname = proc.username() or ""
            except Exception:
                pass
            ct      = _safe_attr(proc, "create_time", 0) or 0
            created = datetime.datetime.fromtimestamp(ct).isoformat() if ct else ""
            status  = _safe_attr(proc, "status", "unknown")
            cmdline = _safe_attr(proc, "cmdline", []) or []
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {}

    return {
        "pid":      pid,
        "name":     name,
        "ppid":     ppid,
        "exe":      exe,
        "username": uname,
        "created":  created,
        "status":   status,
        "cmdline":  " ".join(cmdline),
    }


def enumerate_processes() -> list[dict]:
    """Enumerate all running processes and return their metadata dicts."""
    result = []
    for proc in psutil.process_iter():
        info = get_process_info(proc)
        if info:
            result.append(info)
    return result


def build_process_tree(processes: list[dict]) -> dict[int, list[dict]]:
    """Return a {ppid: [child, ...]} mapping from a flat process list."""
    tree: dict[int, list[dict]] = {}
    for p in processes:
        tree.setdefault(p.get("ppid", 0), []).append(p)
    return tree


# ─────────────────────────────────────────────────────────────────────────────
# Detection functions — one per rule
# ─────────────────────────────────────────────────────────────────────────────

def detect_suspicious_chains(processes: list[dict]) -> list[dict]:
    """
    Rule 1 & 2 — Suspicious parent->child process relationships.

    Every chain entry now carries a specific reason and MITRE technique code
    instead of a single generic message. Severity is per-rule (HIGH or MEDIUM).
    """
    pid_map = {p["pid"]: p for p in processes}
    alerts  = []

    for child in processes:
        parent = pid_map.get(child.get("ppid", 0))
        if not parent:
            continue
        pname = parent["name"].lower()
        cname = child["name"].lower()
        rule  = _CHAIN_RULES.get((pname, cname))
        if not rule:
            continue
        severity, reason, mitre = rule
        alerts.append({
            "type":      "SUSPICIOUS_CHAIN",
            "severity":  severity,
            "parent":    parent,
            "child":     child,
            "reason":    reason,
            "mitre":     mitre,
            "timestamp": datetime.datetime.now().isoformat(),
        })

    return alerts


def detect_suspicious_processes(processes: list[dict]) -> list[dict]:
    """
    Rule 3 & 4 — Suspicious execution location and process name typosquatting.

    Also handles Rule 4b (masquerade-by-path): a process using a legitimate
    system binary name but running from the wrong directory is CRITICAL.
    """
    alerts = []

    for p in processes:
        name    = p.get("name", "")
        exe     = p.get("exe",  "")
        reasons: list[str] = []
        severity = "HIGH"

        # Rule 4b — masquerade by path (highest priority, CRITICAL)
        if _is_masquerading(name, exe):
            reasons.append(
                f"System process '{name}' running outside System32 — "
                f"masquerade attack (T1036.005): {exe}"
            )
            severity = "CRITICAL"

        # Rule 4 — typosquatted name
        elif _is_suspicious_name(name):
            reasons.append(f"Typosquatted system process name: {name}")

        # Rule 3 — suspicious directory (checked for all processes)
        if exe and _is_suspicious_dir(exe):
            reasons.append(f"Executable in suspicious directory: {exe}")

        if reasons:
            alerts.append({
                "type":      "SUSPICIOUS_PROCESS",
                "severity":  severity,
                "process":   p,
                "reason":    "; ".join(reasons),
                "mitre":     "T1036 / T1036.005" if severity == "CRITICAL" else "T1036 / T1055",
                "timestamp": datetime.datetime.now().isoformat(),
            })

    return alerts


def detect_encoded_powershell(processes: list[dict]) -> list[dict]:
    """
    Rule 5 — Encoded or obfuscated PowerShell command lines.

    Fires CRITICAL on -enc / -encodedcommand.
    Fires HIGH on other evasion flags (hidden window, IEX, WebClient, etc.).
    Each alert lists every evasion technique found in the command line.
    """
    alerts = []

    for p in processes:
        if p.get("name", "").lower() not in _PS_NAMES:
            continue

        cmdline = p.get("cmdline", "")
        if not cmdline:
            continue

        reasons:  list[str] = []
        severity = "HIGH"

        # Encoded command — CRITICAL
        if _ENCODED_PS_PATTERN.search(cmdline):
            reasons.append(
                "Encoded PowerShell command (-enc / -EncodedCommand) — "
                "base64 payload concealment"
            )
            severity = "CRITICAL"

        # Additional evasion flags
        for pattern, label in _EVASION_PATTERNS:
            if pattern.search(cmdline):
                reasons.append(label)

        if reasons:
            # Truncate very long command lines for the alert reason field
            cmd_preview = cmdline if len(cmdline) <= 120 else cmdline[:117] + "..."
            alerts.append({
                "type":      "ENCODED_POWERSHELL",
                "severity":  severity,
                "process":   p,
                "reason":    "; ".join(reasons),
                "cmdline":   cmd_preview,
                "mitre":     "T1059.001 / T1027",
                "timestamp": datetime.datetime.now().isoformat(),
            })

    return alerts
