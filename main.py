"""
main.py
=======
Windows Service & Process Monitoring Agent  —  Blue Team Edition

Detection rules executed per scan
----------------------------------
  Rule 1  Office -> PowerShell/Shell       process_monitor.detect_suspicious_chains
  Rule 2  CMD -> PowerShell chain          process_monitor.detect_suspicious_chains
  Rule 3  Execution from suspicious dir    process_monitor.detect_suspicious_processes
  Rule 4  Process name masquerade          process_monitor.detect_suspicious_processes
  Rule 4b Legit name, wrong directory      process_monitor.detect_suspicious_processes
  Rule 5  Encoded PowerShell cmdline       process_monitor.detect_encoded_powershell
  WL      Whitelist / blacklist engine     whitelist_engine.classify_processes
  SVC     Service auditing                 service_auditor.detect_suspicious_services

Usage
-----
    python main.py                    # single scan, reports saved to ./reports/
    python main.py --watch 60         # continuous scan every 60 seconds
    python main.py --out ./my_logs    # custom output directory
    python main.py --no-services      # skip Windows service enumeration

Dependencies
------------
    pip install psutil
    pip install wmi pywin32           # optional — richer service data on Windows
"""

import argparse
import datetime
import os
import time

from process_monitor import (
    enumerate_processes,
    detect_suspicious_chains,
    detect_suspicious_processes,
    detect_encoded_powershell,
)
from service_auditor  import enumerate_services, detect_suspicious_services
from whitelist_engine import classify_processes
from alert_logger     import AlertLogger
from report_generator import generate_html_report


BANNER = r"""
+==================================================================+
|   Windows Process & Service Monitoring Agent               |
|   Blue Team Endpoint Security Framework                         |
|                                                                  |
|   Rules: Office->Shell  CMD->PS  Suspicious Dirs                |
|          Masquerade  Encoded PowerShell  Service Audit          |
+==================================================================+
"""


def run_scan(args: argparse.Namespace, scan_number: int = 1) -> dict:
    """Execute one full scan cycle and write all report outputs."""
    print(f"\n{'─' * 60}")
    print(f"  Scan #{scan_number}  |  {datetime.datetime.now().isoformat()}")
    print(f"{'─' * 60}")

    logger = AlertLogger(log_dir=args.out)

    # ── Step 1 & 2: Process enumeration ───────────────────────────────────────
    print("[*] Enumerating active processes...")
    processes = enumerate_processes()
    print(f"    -> {len(processes)} processes found")

    # ── Step 3: Service auditing ───────────────────────────────────────────────
    services: list[dict] = []
    if not args.no_services:
        print("[*] Enumerating Windows services...")
        try:
            services = enumerate_services()
            print(f"    -> {len(services)} services found")
        except Exception as exc:
            print(f"    [!] Service enumeration failed: {exc}")

    # ── Step 4: Run all detection rules ───────────────────────────────────────
    print("[*] Running detection rules...")

    # Rule 1 & 2 — suspicious parent-child chains
    chain_alerts = detect_suspicious_chains(processes)
    print(f"    Rule 1/2  (chains)             : {len(chain_alerts)} alert(s)")

    # Rule 3 & 4 & 4b — suspicious location / masquerade
    proc_alerts = detect_suspicious_processes(processes)
    print(f"    Rule 3/4/4b (process behaviour) : {len(proc_alerts)} alert(s)")

    # Rule 5 — encoded / obfuscated PowerShell
    enc_alerts = detect_encoded_powershell(processes)
    print(f"    Rule 5  (encoded PowerShell)   : {len(enc_alerts)} alert(s)")

    # Service audit
    svc_alerts = detect_suspicious_services(services)
    print(f"    Services                       : {len(svc_alerts)} alert(s)")

    # Whitelist / blacklist pass
    wl_alerts = classify_processes(processes)

    # Deduplicate: drop whitelist alerts for PIDs already covered above
    flagged_pids: set = {
        a.get("process", {}).get("pid") or a.get("child", {}).get("pid")
        for a in chain_alerts + proc_alerts + enc_alerts
    }
    wl_alerts_filtered = [
        a for a in wl_alerts
        if a.get("process", {}).get("pid") not in flagged_pids
    ]
    print(f"    Whitelist engine               : {len(wl_alerts_filtered)} alert(s)")

    all_alerts = chain_alerts + proc_alerts + enc_alerts + svc_alerts + wl_alerts_filtered

    # ── Step 5 & 6: Alert output + structured logging ─────────────────────────
    if all_alerts:
        print(f"\n[!] {len(all_alerts)} total alert(s):\n")
        logger.add(all_alerts)
    else:
        print("\n[OK] No alerts triggered in this scan.")

    # ── Step 7: Write report files ────────────────────────────────────────────
    logger.save_json()
    logger.save_text()
    logger.save_csv()

    html_path = generate_html_report(
        alerts    = all_alerts,
        processes = processes,
        services  = services,
        summary   = logger.summary(),
        out_dir   = args.out,
    )

    # ── Console summary ────────────────────────────────────────────────────────
    summ = logger.summary()
    print(f"\n{'─' * 60}")
    print("  SUMMARY")
    print(f"{'─' * 60}")
    print(f"  Total alerts  : {summ['total_alerts']}")
    for sev, count in summ["by_severity"].items():
        if count:
            bar = "\u2588" * min(count, 40)
            print(f"  {sev:<10}: {bar} {count}")
    print(f"\n  Reports saved to : {args.out}")
    print(f"  HTML dashboard   : {html_path}")
    print(f"{'─' * 60}\n")

    return summ


def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Windows Process & Service Monitoring Agent"
    )
    parser.add_argument(
        "--watch", type=int, default=0,
        help="Continuous mode: re-scan interval in seconds (0 = single scan)",
    )
    parser.add_argument(
        "--out", type=str, default="./reports",
        help="Directory to write report files into (created if absent)",
    )
    parser.add_argument(
        "--no-services", action="store_true",
        help="Skip Windows service enumeration",
    )
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.watch > 0:
        print(f"[*] Continuous monitoring enabled (interval: {args.watch}s)")
        print("    Press Ctrl+C to stop.\n")
        scan_n = 1
        try:
            while True:
                run_scan(args, scan_n)
                scan_n += 1
                print(f"[*] Next scan in {args.watch}s...")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
    else:
        run_scan(args)


if __name__ == "__main__":
    main()
