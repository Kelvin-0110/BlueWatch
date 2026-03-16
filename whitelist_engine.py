"""
whitelist_engine.py
===================
Whitelist / blacklist engine for unauthorized process detection.

Detection layers
----------------
1. Hard blacklist      — known-malicious names (WannaCry, typosquats)  CRITICAL
2. Masquerade-by-path  — real system name, wrong directory             CRITICAL
3. Pattern match       — regex typosquat detection (svchost32, …)     HIGH
4. Whitelist miss      — name not in known-good set                    LOW
5. Suspicious path     — executable in high-risk writable directory    HIGH (escalates)

Layers 2–5 are also present in process_monitor.py (detect_suspicious_processes).
classify_processes() runs as a separate pass over all processes and deliberately
deduplicates against the results of the earlier detection functions via main.py's
flagged_pids set, so there is no double-alerting in practice.

False-positive mitigations
--------------------------
- \\programdata\\ is NOT flagged — vendor tools (Defender, NVIDIA, Lenovo) live there.
- Trusted AppData sub-paths are allow-listed before the broad \\appdata\\ check.
- Severity escalation uses an explicit rank dict (no max() with list.index).
"""

import re
import datetime
from typing import Optional

# ── Known-good process names (lowercase) ──────────────────────────────────────
SYSTEM_WHITELIST: set[str] = {
    # Core OS
    "system",          "smss.exe",        "csrss.exe",       "wininit.exe",
    "winlogon.exe",    "services.exe",    "lsass.exe",       "lsm.exe",
    "svchost.exe",     "spoolsv.exe",     "explorer.exe",    "taskhost.exe",
    "taskhostw.exe",   "dwm.exe",         "conhost.exe",     "dllhost.exe",
    "sihost.exe",      "ctfmon.exe",      "fontdrvhost.exe", "logonui.exe",
    "userinit.exe",
    # Windows Update / Defender
    "wuauclt.exe",     "musnotification.exe", "msmpeng.exe",
    "nissrv.exe",      "mpdefendercoreservice.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    # Common user applications
    "chrome.exe",      "firefox.exe",     "msedge.exe",      "iexplore.exe",
    "notepad.exe",     "notepad++.exe",   "calc.exe",        "mspaint.exe",
    "wordpad.exe",     "winword.exe",     "excel.exe",       "outlook.exe",
    "powerpnt.exe",    "onenote.exe",     "teams.exe",       "onedrive.exe",
    "slack.exe",       "discord.exe",     "zoom.exe",        "spotify.exe",
    # Development tools
    "code.exe",        "devenv.exe",      "python.exe",      "pythonw.exe",
    "node.exe",        "git.exe",         "java.exe",        "javaw.exe",
    "idea64.exe",      "pycharm64.exe",
    # System / admin tools
    "cmd.exe",         "powershell.exe",  "pwsh.exe",        "mmc.exe",
    "taskmgr.exe",     "regedit.exe",     "msiexec.exe",     "regsvr32.exe",
    "rundll32.exe",    "wscript.exe",     "cscript.exe",     "mshta.exe",
    "sc.exe",          "net.exe",         "netsh.exe",       "ipconfig.exe",
    "ping.exe",        "nslookup.exe",    "tracert.exe",     "curl.exe",
    "certutil.exe",
    # Background / service processes
    "wmiprvse.exe",    "wmiapsrv.exe",    "sppsvc.exe",      "wlanext.exe",
    "nvvsvc.exe",      "nvspcaps64.exe",  "igfxem.exe",      "audiodg.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "runtimebroker.exe", "applicationframehost.exe",
    "backgroundtaskhost.exe", "mobsync.exe", "wermgr.exe",
    "msdtc.exe",       "lsaiso.exe",      "vaultclt.exe",    "cryptsvc.exe",
    "batterywidgethost.exe",              # Lenovo Vantage battery widget
    # Windows 10/11 shell
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "systemsettings.exe", "smartscreen.exe",
    "lockapp.exe",
}

# ── Hard blacklist — always CRITICAL, regardless of path ──────────────────────
PROCESS_BLACKLIST: set[str] = {
    "svch0st.exe",    "svchost32.exe",   "svchost64.exe",
    "expl0rer.exe",   "explorer32.exe",
    "lsasss.exe",
    "systemupdate.exe", "system_update.exe", "windowsupdate.exe",
    "tasksche.exe",   # WannaCry ransomware dropper
    "mssecsvc.exe",   # WannaCry service component
    "wuauclt32.exe",
    "csrs.exe",       "crss.exe",
    "rundl132.exe",   # digit 1 in place of lowercase L
    "scvhost.exe",
}

# ── Processes that must ALWAYS run from System32 / SysWOW64 ───────────────────
# If found elsewhere → CRITICAL masquerade alert (T1036.005)
_SYSTEM32_ONLY: set[str] = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "services.exe", "winlogon.exe", "spoolsv.exe",
}

_SYSTEM_ROOTS: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
)

# ── Typosquat regex patterns ───────────────────────────────────────────────────
_SUSPICIOUS_NAME_PATTERNS: list[re.Pattern] = [
    re.compile(r"svchost[0-9_\-]",   re.I),
    re.compile(r"explorer[0-9_\-]",  re.I),
    re.compile(r"lsass[0-9_\-s]",    re.I),
    re.compile(r"csrss[0-9_\-]",     re.I),
    re.compile(r"winlogon[0-9_\-]",  re.I),
    re.compile(r"services[0-9_\-]",  re.I),
    re.compile(r"[0o]host",          re.I),   # svch0st, winl0gon, etc.
    re.compile(r"update.*mgr",       re.I),
    re.compile(r"win.*update",       re.I),
]

# ── Trusted AppData allow-list ─────────────────────────────────────────────────
TRUSTED_PATH_PREFIXES: tuple[str, ...] = (
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

_SEVERITY_RANK: dict[str, int] = {
    "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _name_matches_suspicious_pattern(name: str) -> Optional[str]:
    """Return the matching pattern string if name looks like a typosquat, else None."""
    for pat in _SUSPICIOUS_NAME_PATTERNS:
        if pat.search(name):
            return pat.pattern
    return None


def _path_is_suspicious(exe: str) -> bool:
    """Return True if the executable path is in a known high-risk location.

    Path separators are normalised to backslashes before matching.
    """
    low = exe.lower().replace("/", "\\")
    if any(tp in low for tp in TRUSTED_PATH_PREFIXES):
        return False
    suspicious_dirs = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\temp\\",
        "\\tmp\\",
        "\\users\\public\\",
        "\\downloads\\",
        "\\desktop\\",
        "/tmp/",
        "/var/tmp/",
    ]
    return any(d in low for d in suspicious_dirs)


def _is_masquerading(name: str, exe: str) -> bool:
    """Return True if a trusted system binary name is running outside System32."""
    if name not in _SYSTEM32_ONLY:
        return False
    if not exe:
        return False
    # Normalise separators so forward-slash paths match backslash roots
    return not any(exe.lower().replace("/", "\\").startswith(root) for root in _SYSTEM_ROOTS)


def _escalate(current: str, candidate: str) -> str:
    """Return the higher of two severity strings."""
    if _SEVERITY_RANK.get(candidate, 0) > _SEVERITY_RANK.get(current, 0):
        return candidate
    return current


# ── Public API ─────────────────────────────────────────────────────────────────

def classify_processes(processes: list[dict]) -> list[dict]:
    """
    Cross-reference all running processes against whitelist / blacklist rules.

    Emits an alert only when:
    - severity is HIGH or CRITICAL (single strong signal), OR
    - two or more reasons are present (combined weaker signals)

    This prevents flooding the report with LOW "not in whitelist" noise for
    every legitimate third-party application on the machine.
    """
    alerts = []

    for p in processes:
        name     = p.get("name", "").lower()
        exe      = p.get("exe",  "")
        reasons: list[str] = []
        severity = "MEDIUM"

        # Layer 1 — hard blacklist
        if name in PROCESS_BLACKLIST:
            reasons.append(f"Process is on the hard blacklist: {name}")
            severity = "CRITICAL"

        # Layer 2 — masquerade by path (CRITICAL)
        if _is_masquerading(name, exe):
            reasons.append(
                f"System process '{name}' running outside System32 — "
                f"masquerade attack (T1036.005): {exe}"
            )
            severity = _escalate(severity, "CRITICAL")

        # Layer 3 — typosquat pattern match
        pattern_hit = _name_matches_suspicious_pattern(name)
        if pattern_hit:
            reasons.append(
                f"Name matches suspicious pattern ({pattern_hit}): {name}"
            )
            severity = _escalate(severity, "HIGH")

        # Layer 4 — not in known-good whitelist (informational on its own)
        if name not in SYSTEM_WHITELIST:
            reasons.append(f"Process not in known whitelist: {name}")
            if severity == "MEDIUM":
                severity = "LOW"

        # Layer 5 — running from a high-risk directory
        if exe and _path_is_suspicious(exe):
            reasons.append(f"Running from suspicious directory: {exe}")
            severity = _escalate(severity, "HIGH")

        # Emit alert only when signal is strong enough
        if len(reasons) > 1 or (
            len(reasons) == 1 and severity in ("HIGH", "CRITICAL")
        ):
            alerts.append({
                "type":      "UNAUTHORIZED_PROCESS",
                "severity":  severity,
                "process":   p,
                "reason":    "; ".join(reasons),
                "mitre":     (
                    "T1036.005" if "masquerade" in " ".join(reasons).lower()
                    else "T1036 / T1055 / T1547"
                ),
                "timestamp": datetime.datetime.now().isoformat(),
            })

    return alerts
