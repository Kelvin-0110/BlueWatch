"""
service_auditor.py
==================
Windows service enumeration and suspicious service detection.

Uses WMI (pywin32) when available, falls back to sc.exe for environments
where pywin32 is not installed.

Detection coverage
------------------
- Suspicious service names / typosquats       (T1543.003)
- Binaries in high-risk writable directories  (T1543.003)
- Genuine unquoted service path vulnerabilities (T1574.005)

False-positive mitigations
--------------------------
- \\programdata\\ is NOT in the suspicious-dir list.  Vendor services from
  Microsoft (Defender), NVIDIA, Lenovo, Intel etc. legitimately live there.
  A targeted TRUSTED_SERVICE_PATH_PREFIXES allow-list covers these explicitly.

- The unquoted-path check was completely rewritten.  The old check triggered
  on every "svchost.exe -k <group> -p" path because it simply tested for a
  space anywhere in the path string.  This produced 220+ false positives.
  The new _is_unquoted_path_vuln() function:
    1. Extracts only the executable portion (before any -flag arguments).
    2. Checks whether THAT portion contains a space.
    3. Exempts binaries rooted at C:\\Windows\\System32\\ etc. which can
       never be path-traversal targets regardless.
"""

import datetime
import subprocess
import re

# ── Suspicious directory fragments ────────────────────────────────────────────
# \\programdata\\ and \\appdata\\ omitted — too many legitimate vendor services.
SUSPICIOUS_SERVICE_DIRS: list[str] = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "/tmp/",
    "/var/tmp/",
]

# ── Trusted ProgramData vendor paths ──────────────────────────────────────────
# Services whose binary paths start with one of these prefixes are never flagged
# as "binary in suspicious directory", even if a broader pattern would match.
TRUSTED_SERVICE_PATH_PREFIXES: tuple[str, ...] = (
    "c:\\programdata\\microsoft\\",
    "c:\\programdata\\nvidia\\",
    "c:\\programdata\\intel\\",
    "c:\\programdata\\lenovo\\",
    "c:\\programdata\\dell\\",
    "c:\\programdata\\hp\\",
    "c:\\programdata\\amd\\",
    "c:\\programdata\\package cache\\",
)

# ── Trusted system binary roots for unquoted-path exemption ───────────────────
# Paths that start here have no spaces in the directory component, so
# "svchost.exe -k netsvcs" can never be a path-traversal vector.
# Program Files is intentionally excluded — unquoted paths there ARE T1574.005.
TRUSTED_BINARY_ROOTS: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\servicing\\",
    "c:\\windows\\winsxs\\",
)

# ── Suspicious service names ───────────────────────────────────────────────────
SUSPICIOUS_SERVICE_NAMES: set[str] = {
    "updatemgr", "updatemanagerx", "winupdatesvc", "windowsdefendersvc",
    "securitysvc", "antimalwaresvc", "svchost32", "svchost64",
    "svch0st", "explorer32", "lsasssvc",
    "wuauserv2", "cryptsvc2", "bits2",
    "remoteregistry2", "netlogon2",
}

# Pattern: legitimate-sounding names with digit / symbol substitution
_TYPO_PATTERN = re.compile(
    r"(svchost|explorer|lsass|winlogon|csrss|services|spooler|taskhost)[0-9_\-]",
    re.IGNORECASE,
)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _is_suspicious_path(path: str) -> bool:
    """Return True if the service binary resides in a known high-risk directory."""
    low = path.lower()
    if any(low.startswith(tp) for tp in TRUSTED_SERVICE_PATH_PREFIXES):
        return False
    return any(sd in low for sd in SUSPICIOUS_SERVICE_DIRS)


def _is_unquoted_path_vuln(path: str) -> bool:
    """
    Return True only for genuine unquoted service path vulnerabilities (T1574.005).

    A real vulnerability requires ALL of the following:
      1. The executable path itself (not its arguments) contains a space.
      2. The full path string is not wrapped in double quotes.
      3. The binary root is not an all-lowercase Windows system directory
         (System32 / SysWOW64) that has no spaces and cannot be traversed.

    Why the old check was wrong
    ---------------------------
    "C:\\Windows\\system32\\svchost.exe -k netsvcs -p" contains a space, but
    that space is an argument separator — not part of the file path.  Windows
    resolves svchost.exe unambiguously regardless.  The old one-liner
    `if " " in path and not path.startswith('"')` fired on every such service,
    producing ~220 MEDIUM false-positive alerts.

    This implementation extracts the executable portion before any -flag or
    /flag arguments, then checks only that portion for spaces.
    """
    raw = path.strip()
    if not raw or raw.startswith('"'):
        return False

    # Extract exe portion: everything up to the first argument marker.
    # Argument markers are a space followed by - or / (e.g. " -k", " /svc").
    match = re.match(r'^([^\s]+(?:\s[^/\-\s][^\s]*)*)', raw)
    exe_part = match.group(1).strip() if match else raw.split()[0]

    # No space in the exe path — not vulnerable
    if " " not in exe_part:
        return False

    # Trusted Windows system roots cannot be path-traversal targets
    if any(exe_part.lower().startswith(tr) for tr in TRUSTED_BINARY_ROOTS):
        return False

    return True


def _is_suspicious_name(name: str) -> bool:
    """Return True if the service name is a known fake or typosquatted name."""
    low = name.lower()
    return low in SUSPICIOUS_SERVICE_NAMES or bool(_TYPO_PATTERN.search(low))


# ── Service enumeration ────────────────────────────────────────────────────────

def _wmi_query_all() -> list[dict]:
    """Enumerate services via WMI (requires pywin32). Returns [] if unavailable."""
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        return [
            {
                "name":         svc.Name        or "",
                "display_name": svc.DisplayName or "",
                "state":        svc.State       or "",
                "start_type":   svc.StartMode   or "",
                "binary_path":  svc.PathName    or "",
            }
            for svc in c.Win32_Service()
        ]
    except Exception:
        return []


def _sc_query_all() -> list[dict]:
    """
    Enumerate services via sc.exe — fallback when pywin32 is unavailable.
    Runs sc query to list all services, then sc qc per service for config details.
    """
    services: list[dict] = []
    try:
        out = subprocess.check_output(
            ["sc", "query", "type=", "all", "state=", "all"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except Exception:
        return services

    current: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("DISPLAY_NAME:"):
            current["display_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("STATE"):
            m = re.search(r":\s+\d+\s+(\w+)", line)
            current["state"] = m.group(1) if m else "UNKNOWN"
    if current:
        services.append(current)

    # Enrich each entry with binary path and start type from sc qc
    for svc in services:
        try:
            cfg = subprocess.check_output(
                ["sc", "qc", svc["name"]],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            )
            for cfgline in cfg.splitlines():
                cfgline = cfgline.strip()
                if "BINARY_PATH_NAME" in cfgline:
                    svc["binary_path"] = cfgline.split(":", 1)[1].strip()
                elif "START_TYPE" in cfgline:
                    svc["start_type"] = cfgline.split(":", 1)[1].strip()
        except Exception:
            pass
        svc.setdefault("binary_path",  "")
        svc.setdefault("start_type",   "UNKNOWN")
        svc.setdefault("display_name", svc.get("name", ""))
        svc.setdefault("state",        "UNKNOWN")

    return services


def enumerate_services() -> list[dict]:
    """Enumerate Windows services. Tries WMI first, falls back to sc.exe."""
    services = _wmi_query_all()
    if not services:
        services = _sc_query_all()
    return services


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_suspicious_services(services: list[dict]) -> list[dict]:
    """
    Analyse service configurations and return alert dicts for suspicious entries.

    Severity is HIGH when multiple indicators fire, MEDIUM for a single indicator.
    """
    alerts = []

    for svc in services:
        name  = svc.get("name",        "")
        path  = svc.get("binary_path", "")
        reasons: list[str] = []

        if _is_suspicious_name(name):
            reasons.append(f"Suspicious/typosquatted service name: {name}")

        if path and _is_suspicious_path(path):
            reasons.append(f"Service binary in suspicious directory: {path}")

        if _is_unquoted_path_vuln(path):
            reasons.append(f"Unquoted service path (T1574.005): {path}")

        if reasons:
            alerts.append({
                "type":      "SUSPICIOUS_SERVICE",
                "severity":  "HIGH" if len(reasons) > 1 else "MEDIUM",
                "service":   svc,
                "reason":    "; ".join(reasons),
                "mitre":     "T1543.003 / T1574",
                "timestamp": datetime.datetime.now().isoformat(),
            })

    return alerts
