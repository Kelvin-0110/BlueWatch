"""
alert_logger.py
===============
Structured alert formatting, severity ranking, and multi-format log output.

Outputs
-------
- Console  : human-readable coloured-style text printed during scanning
- JSON     : machine-readable alerts + summary payload
- CSV      : flat table suitable for spreadsheet / SIEM ingestion
- Text     : full formatted report with header and per-alert blocks
"""

import csv
import datetime
import json
import os
from typing import Optional

# ── Severity ordering ──────────────────────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

# ── MITRE ATT&CK technique labels ─────────────────────────────────────────────
_MITRE_DESCRIPTIONS: dict[str, str] = {
    "T1059":     "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1203":     "Exploitation for Client Execution",
    "T1036":     "Masquerading",
    "T1055":     "Process Injection",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1574":     "Hijack Execution Flow",
    "T1574.005": "Executable Installer File Permissions Weakness",
    "T1547":     "Boot or Logon Autostart Execution",
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _mitre_label(codes: str) -> str:
    """Expand a slash-separated MITRE code string into labelled form."""
    parts  = [c.strip() for c in codes.split("/")]
    labels = []
    for code in parts:
        desc = _MITRE_DESCRIPTIONS.get(code)
        labels.append(f"{code} ({desc})" if desc else code)
    return " / ".join(labels)


def _ts() -> str:
    """Return a compact timestamp string for use in filenames."""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# ── Public helpers ─────────────────────────────────────────────────────────────

def format_alert(alert: dict) -> str:
    """Return a human-readable multi-line string for a single alert."""
    ts    = alert.get("timestamp", datetime.datetime.now().isoformat())
    sev   = alert.get("severity", "INFO")
    atype = alert.get("type",     "ALERT")
    mitre = _mitre_label(alert.get("mitre", ""))

    lines = [f"\n[{sev}] {atype}  |  {ts}"]
    lines.append(f"  Reason : {alert.get('reason', '')}")
    if mitre:
        lines.append(f"  MITRE  : {mitre}")

    atype_key = alert.get("type", "")

    if atype_key == "SUSPICIOUS_CHAIN":
        parent = alert.get("parent", {})
        child  = alert.get("child",  {})
        lines.append(
            f"  Parent : {parent.get('name','')}  PID={parent.get('pid','')}  "
            f"{parent.get('exe','')}"
        )
        lines.append(
            f"  Child  : {child.get('name','')}  PID={child.get('pid','')}  "
            f"{child.get('exe','')}"
        )

    elif atype_key in ("SUSPICIOUS_PROCESS", "UNAUTHORIZED_PROCESS"):
        proc = alert.get("process", {})
        lines.append(
            f"  Process: {proc.get('name','')}  "
            f"PID={proc.get('pid','')}  PPID={proc.get('ppid','')}"
        )
        lines.append(f"  Path   : {proc.get('exe','')}")
        lines.append(f"  User   : {proc.get('username','')}")

    elif atype_key == "ENCODED_POWERSHELL":
        proc = alert.get("process", {})
        lines.append(
            f"  Process: {proc.get('name','')}  "
            f"PID={proc.get('pid','')}  PPID={proc.get('ppid','')}"
        )
        lines.append(f"  Path   : {proc.get('exe','')}")
        lines.append(f"  User   : {proc.get('username','')}")
        cmdline = alert.get("cmdline", proc.get("cmdline", ""))
        if cmdline:
            lines.append(f"  CmdLine: {cmdline}")

    elif atype_key == "SUSPICIOUS_SERVICE":
        svc = alert.get("service", {})
        lines.append(
            f"  Service: {svc.get('name','')} ({svc.get('display_name','')})"
        )
        lines.append(f"  Path   : {svc.get('binary_path','')}")
        lines.append(
            f"  Start  : {svc.get('start_type','')}  State: {svc.get('state','')}"
        )

    return "\n".join(lines)


def sort_alerts(alerts: list[dict]) -> list[dict]:
    """Return alerts sorted highest severity first."""
    return sorted(
        alerts,
        key=lambda a: SEVERITY_ORDER.get(a.get("severity", "INFO"), 0),
        reverse=True,
    )


# ── AlertLogger class ──────────────────────────────────────────────────────────

class AlertLogger:
    """
    Collects alerts during a scan and writes structured output files.

    Usage
    -----
        logger = AlertLogger(log_dir="./reports")
        logger.add(list_of_alert_dicts)
        logger.save_json()
        logger.save_text()
        logger.save_csv()
    """

    def __init__(self, log_dir: str = ".") -> None:
        self.log_dir    = log_dir
        self.alerts:    list[dict] = []
        self.log_lines: list[str]  = []
        os.makedirs(log_dir, exist_ok=True)

    def add(self, alert_or_list) -> None:
        """Accept a single alert dict or a list of alert dicts."""
        items = alert_or_list if isinstance(alert_or_list, list) else [alert_or_list]
        for a in items:
            self.alerts.append(a)
            line = format_alert(a)
            self.log_lines.append(line)
            print(line)

    def summary(self) -> dict:
        """Return a summary dict with total counts by severity and type."""
        by_sev:  dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_type: dict[str, int] = {}
        for a in self.alerts:
            sev = a.get("severity", "LOW")
            by_sev[sev]  = by_sev.get(sev, 0) + 1
            t = a.get("type", "UNKNOWN")
            by_type[t]   = by_type.get(t, 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity":  by_sev,
            "by_type":      by_type,
            "generated_at": datetime.datetime.now().isoformat(),
        }

    # ── File output methods ────────────────────────────────────────────────────

    def save_json(self, filename: Optional[str] = None) -> str:
        """Write alerts + summary as a JSON file. Returns the output path."""
        path = os.path.join(self.log_dir, filename or f"alerts_{_ts()}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"summary": self.summary(), "alerts": sort_alerts(self.alerts)},
                fh,
                indent=2,
                default=str,
            )
        print(f"\n[+] JSON report saved -> {path}")
        return path

    def save_text(self, filename: Optional[str] = None) -> str:
        """Write a human-readable text report. Returns the output path."""
        path = os.path.join(self.log_dir, filename or f"report_{_ts()}.txt")
        summ = self.summary()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("=" * 70 + "\n")
            fh.write("  WINDOWS PROCESS & SERVICE MONITORING AGENT -- REPORT\n")
            fh.write(f"  Generated : {datetime.datetime.now().isoformat()}\n")
            fh.write("=" * 70 + "\n\n")
            fh.write(f"Total Alerts : {summ['total_alerts']}\n")
            for k, v in summ["by_severity"].items():
                fh.write(f"  {k:<10}: {v}\n")
            fh.write("\n")
            for alert in sort_alerts(self.alerts):
                fh.write(format_alert(alert) + "\n")
                fh.write("-" * 60 + "\n")
        print(f"[+] Text report saved -> {path}")
        return path

    def save_csv(self, filename: Optional[str] = None) -> str:
        """Write a flat CSV suitable for SIEM ingestion. Returns the output path."""
        path = os.path.join(self.log_dir, filename or f"alerts_{_ts()}.csv")
        fieldnames = [
            "timestamp", "severity", "type", "reason", "mitre",
            "name", "pid", "ppid", "exe", "username",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for a in sort_alerts(self.alerts):
                proc = a.get("process") or a.get("child") or {}
                svc  = a.get("service", {})
                writer.writerow({
                    "timestamp": a.get("timestamp", ""),
                    "severity":  a.get("severity",  ""),
                    "type":      a.get("type",       ""),
                    "reason":    a.get("reason",     ""),
                    "mitre":     a.get("mitre",      ""),
                    "name":      proc.get("name", "") or svc.get("name", ""),
                    "pid":       proc.get("pid",  ""),
                    "ppid":      proc.get("ppid", ""),
                    "exe":       proc.get("exe",  "") or svc.get("binary_path", ""),
                    "username":  proc.get("username", ""),
                })
        print(f"[+] CSV report saved  -> {path}")
        return path
