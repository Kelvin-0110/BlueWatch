"""
report_generator.py
===================
Generate a polished dark-theme HTML dashboard from scan results.

The dashboard includes:
- Executive summary strip with donut chart and per-severity counts
- Tabbed alert view (All / Suspicious Chains / Processes / Services)
- Full active-process table (up to 200 rows)
- Full Windows-services table (up to 200 rows)
- JS tab switcher — no external dependencies
"""

import datetime
import os

# ── Severity colours ───────────────────────────────────────────────────────────
SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#ff2e2e",
    "HIGH":     "#ff7a00",
    "MEDIUM":   "#f5c518",
    "LOW":      "#4fc3f7",
    "INFO":     "#90a4ae",
}

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _ts_now() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _esc(value) -> str:
    """HTML-escape a value so it is safe to embed in table cells."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#90a4ae")
    return (
        f'<span style="background:{color};color:#000;font-weight:700;'
        f'padding:2px 8px;border-radius:4px;font-size:11px;'
        f'letter-spacing:0.05em;">{_esc(severity)}</span>'
    )


def _alert_card(alert: dict) -> str:
    """Return the HTML block for a single alert card."""
    sev    = alert.get("severity", "INFO")
    atype  = alert.get("type",     "")
    reason = alert.get("reason",   "")
    mitre  = alert.get("mitre",    "")
    ts     = alert.get("timestamp","")
    color  = SEVERITY_COLOR.get(sev, "#90a4ae")
    proc   = alert.get("process") or alert.get("child") or {}
    svc    = alert.get("service", {})
    parent = alert.get("parent",  {})

    # Detail rows differ by alert type
    detail_rows = ""
    if atype == "SUSPICIOUS_CHAIN":
        child = alert.get("child", {})
        detail_rows = (
            f"<tr><td>Parent</td>"
            f"<td>{_esc(parent.get('name',''))} (PID {_esc(parent.get('pid',''))})</td></tr>"
            f"<tr><td>Child</td>"
            f"<td>{_esc(child.get('name',''))} (PID {_esc(child.get('pid',''))})</td></tr>"
            f"<tr><td>Child path</td><td>{_esc(child.get('exe',''))}</td></tr>"
        )
    elif atype in ("SUSPICIOUS_PROCESS", "UNAUTHORIZED_PROCESS"):
        detail_rows = (
            f"<tr><td>Process</td>"
            f"<td>{_esc(proc.get('name',''))} (PID {_esc(proc.get('pid',''))})</td></tr>"
            f"<tr><td>PPID</td><td>{_esc(proc.get('ppid',''))}</td></tr>"
            f"<tr><td>Path</td><td>{_esc(proc.get('exe',''))}</td></tr>"
            f"<tr><td>User</td><td>{_esc(proc.get('username',''))}</td></tr>"
        )
    elif atype == "ENCODED_POWERSHELL":
        cmdline = alert.get("cmdline", proc.get("cmdline", ""))
        detail_rows = (
            f"<tr><td>Process</td>"
            f"<td>{_esc(proc.get('name',''))} (PID {_esc(proc.get('pid',''))})</td></tr>"
            f"<tr><td>Path</td><td>{_esc(proc.get('exe',''))}</td></tr>"
            f"<tr><td>User</td><td>{_esc(proc.get('username',''))}</td></tr>"
            f"<tr><td>Command</td><td style='font-family:monospace;font-size:11px;"
            f"word-break:break-all;color:#f87171'>{_esc(cmdline)}</td></tr>"
        )
    elif atype == "SUSPICIOUS_SERVICE":
        detail_rows = (
            f"<tr><td>Service</td>"
            f"<td>{_esc(svc.get('name',''))} ({_esc(svc.get('display_name',''))})</td></tr>"
            f"<tr><td>Binary path</td><td>{_esc(svc.get('binary_path',''))}</td></tr>"
            f"<tr><td>Start type</td><td>{_esc(svc.get('start_type',''))}</td></tr>"
            f"<tr><td>State</td><td>{_esc(svc.get('state',''))}</td></tr>"
        )

    mitre_tag = (
        f'<div class="mitre-tag">MITRE: {_esc(mitre)}</div>' if mitre else ""
    )
    detail_table = (
        f'<table class="detail-table">{detail_rows}</table>' if detail_rows else ""
    )

    return f"""
    <div class="alert-card" style="border-left:4px solid {color}">
      <div class="alert-header">
        <span class="alert-type">{_esc(atype.replace('_', ' '))}</span>
        {_badge(sev)}
        <span class="alert-ts">{_esc(ts)}</span>
      </div>
      <div class="alert-reason">&#9873; {_esc(reason)}</div>
      {mitre_tag}
      {detail_table}
    </div>"""


def _process_table_rows(processes: list[dict], max_rows: int = 200) -> str:
    rows = []
    for p in processes[:max_rows]:
        rows.append(
            f"<tr>"
            f"<td>{_esc(p.get('pid',''))}</td>"
            f"<td>{_esc(p.get('name',''))}</td>"
            f"<td>{_esc(p.get('ppid',''))}</td>"
            f'<td class="path-cell">{_esc(p.get("exe",""))}</td>'
            f"<td>{_esc(p.get('username',''))}</td>"
            f"<td>{_esc(p.get('status',''))}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _service_table_rows(services: list[dict], max_rows: int = 200) -> str:
    rows = []
    for s in services[:max_rows]:
        rows.append(
            f"<tr>"
            f"<td>{_esc(s.get('name',''))}</td>"
            f"<td>{_esc(s.get('display_name',''))}</td>"
            f"<td>{_esc(s.get('start_type',''))}</td>"
            f"<td>{_esc(s.get('state',''))}</td>"
            f'<td class="path-cell">{_esc(s.get("binary_path",""))}</td>'
            f"</tr>"
        )
    return "\n".join(rows)


def _donut_svg(counts: dict) -> str:
    """Return an inline SVG donut chart for the severity breakdown."""
    total        = sum(counts.values()) or 1
    keys         = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    colors       = [SEVERITY_COLOR[k] for k in keys]
    vals         = [counts.get(k, 0) for k in keys]
    r            = 40
    cx = cy      = 50
    stroke_w     = 28
    circumference = 2 * 3.14159 * r
    segments     = []
    offset       = 0.0
    for v, c in zip(vals, colors):
        dash = (v / total) * circumference
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{c}" '
            f'stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash:.1f} {circumference:.1f}" '
            f'stroke-dashoffset="-{offset:.1f}" />'
        )
        offset += dash
    segs_html = "\n      ".join(segments)
    return (
        f'<svg viewBox="0 0 100 100" width="100" height="100" '
        f'style="transform:rotate(-90deg)">\n'
        f'  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="#1e293b" stroke-width="{stroke_w}"/>\n'
        f'  {segs_html}\n'
        f'</svg>'
    )


# ── CSS ────────────────────────────────────────────────────────────────────────

_CSS = """
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

  :root {
    --bg:     #0a0e1a;
    --panel:  #111827;
    --border: #1e293b;
    --text:   #e2e8f0;
    --muted:  #64748b;
    --accent: #38bdf8;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding-bottom: 60px;
  }

  /* Top bar */
  .topbar {
    background: linear-gradient(90deg, #0f172a, #0c1a35);
    border-bottom: 1px solid var(--border);
    padding: 18px 40px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .topbar-logo {
    font-family: 'JetBrains Mono', monospace;
    font-size: 20px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.03em;
  }
  .topbar-logo span { color: #f472b6; }
  .topbar-sub  { font-size: 12px; color: var(--muted); font-family: 'JetBrains Mono', monospace; }
  .topbar-ts   { margin-left: auto; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); }

  /* Layout */
  .container { max-width: 1280px; margin: 0 auto; padding: 0 40px; }

  /* Section heading */
  .section-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    padding: 32px 0 12px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-title::before {
    content: '';
    display: inline-block;
    width: 3px; height: 14px;
    background: var(--accent);
    border-radius: 2px;
  }

  /* Summary strip */
  .summary-strip {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 32px;
    align-items: center;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px 28px;
    margin-top: 28px;
  }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .stat-card { background: var(--bg); border-radius: 8px; padding: 14px 16px; text-align: center; }
  .stat-val  { font-family: 'JetBrains Mono', monospace; font-size: 28px; font-weight: 700; line-height: 1; }
  .stat-label { font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin-top: 4px; }
  .total-badge { text-align: center; font-family: 'JetBrains Mono', monospace; }
  .total-num { font-size: 40px; font-weight: 700; color: var(--accent); line-height: 1; }
  .total-sub { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; }

  /* Alert cards */
  .alert-card {
    background: var(--panel);
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 10px;
    transition: background 0.15s;
  }
  .alert-card:hover { background: #1a2233; }
  .alert-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .alert-type  { font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; letter-spacing: 0.04em; }
  .alert-ts    { margin-left: auto; font-size: 11px; color: var(--muted); font-family: 'JetBrains Mono', monospace; }
  .alert-reason { font-size: 13px; color: #cbd5e1; margin-bottom: 6px; }
  .mitre-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: var(--muted);
    background: #0f172a;
    padding: 2px 8px;
    border-radius: 4px;
    display: inline-block;
    margin-bottom: 8px;
  }
  .detail-table { width: 100%; font-size: 12px; border-collapse: collapse; margin-top: 6px; }
  .detail-table td { padding: 3px 8px; color: #94a3b8; border-bottom: 1px solid var(--border); vertical-align: top; }
  .detail-table td:first-child { font-weight: 600; color: var(--muted); width: 100px; white-space: nowrap; }

  /* Data tables */
  .data-table-wrap { overflow-x: auto; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'JetBrains Mono', monospace; }
  .data-table th {
    background: #0f172a;
    color: var(--muted);
    text-align: left;
    padding: 8px 12px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
  }
  .data-table td { padding: 7px 12px; border-bottom: 1px solid #1a2233; color: #94a3b8; vertical-align: top; }
  .data-table tr:hover td { background: #111827; color: var(--text); }
  .path-cell { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #64748b; }

  /* Tabs */
  .tabs { display: flex; gap: 4px; margin-bottom: 20px; }
  .tab {
    padding: 7px 18px;
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    color: var(--muted);
    background: transparent;
    transition: all 0.15s;
  }
  .tab.active, .tab:hover { background: var(--accent); color: #0a0e1a; border-color: var(--accent); }
  .tab-panel         { display: none; }
  .tab-panel.active  { display: block; }

  /* Empty state */
  .no-alerts { text-align: center; padding: 60px; color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 13px; }
  .no-alerts .icon { font-size: 48px; display: block; margin-bottom: 12px; }
"""


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_html_report(
    alerts:    list[dict],
    processes: list[dict],
    services:  list[dict],
    summary:   dict,
    out_dir:   str = ".",
) -> str:
    """
    Build and write the HTML dashboard.  Returns the output file path.
    """
    os.makedirs(out_dir, exist_ok=True)
    filename = os.path.join(out_dir, f"dashboard_{_ts_now()}.html")

    sorted_alerts = sorted(
        alerts,
        key=lambda a: SEVERITY_ORDER.get(a.get("severity", "INFO"), 0),
        reverse=True,
    )

    by_sev    = summary.get("by_severity", {})
    total     = summary.get("total_alerts", 0)
    generated = summary.get("generated_at", datetime.datetime.now().isoformat())

    # Stat cards
    stat_cards_html = "".join(
        f'<div class="stat-card" style="border-top:3px solid {SEVERITY_COLOR.get(k,"#999")}">'
        f'<div class="stat-val" style="color:{SEVERITY_COLOR.get(k,"#999")}">{v}</div>'
        f'<div class="stat-label">{k}</div>'
        f'</div>'
        for k, v in by_sev.items()
    )

    # Alert cards grouped by tab
    def cards_for(pred) -> str:
        filtered = [a for a in sorted_alerts if pred(a)]
        if not filtered:
            return '<div class="no-alerts"><span class="icon">&#10003;</span>No alerts in this category.</div>'
        return "\n".join(_alert_card(a) for a in filtered)

    all_cards   = cards_for(lambda a: True)
    chain_cards = cards_for(lambda a: a.get("type") == "SUSPICIOUS_CHAIN")
    proc_cards  = cards_for(lambda a: a.get("type") in (
        "SUSPICIOUS_PROCESS", "UNAUTHORIZED_PROCESS", "ENCODED_POWERSHELL"
    ))
    svc_cards   = cards_for(lambda a: "SERVICE" in a.get("type", ""))

    n_chains = sum(1 for a in sorted_alerts if a.get("type") == "SUSPICIOUS_CHAIN")
    n_procs  = sum(1 for a in sorted_alerts if a.get("type") in (
        "SUSPICIOUS_PROCESS", "UNAUTHORIZED_PROCESS", "ENCODED_POWERSHELL"
    ))
    n_svcs   = sum(1 for a in sorted_alerts if "SERVICE" in a.get("type", ""))

    proc_rows = _process_table_rows(processes)
    svc_rows  = _service_table_rows(services)
    donut     = _donut_svg(by_sev)

    svc_section = ""
    if services:
        svc_section = (
            f'<div class="section-title">Windows Services '
            f'({len(services)} total, showing up to 200)</div>\n'
            f'<div class="data-table-wrap">\n'
            f'  <table class="data-table">\n'
            f'    <thead><tr>'
            f'<th>Name</th><th>Display Name</th>'
            f'<th>Start Type</th><th>State</th><th>Binary Path</th>'
            f'</tr></thead>\n'
            f'    <tbody>{svc_rows}</tbody>\n'
            f'  </table>\n'
            f'</div>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BlueWatch &mdash; Monitoring Report</title>
<style>
{_CSS}
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="topbar-logo">Blue<span>Watch</span></div>
    <div class="topbar-sub">Windows Process &amp; Service Monitoring Agent</div>
  </div>
  <div class="topbar-ts">Generated: {_esc(generated)}</div>
</div>

<div class="container">

  <div class="section-title">Executive Summary</div>
  <div class="summary-strip">
    <div style="display:flex;flex-direction:column;align-items:center;gap:8px">
      {donut}
      <div class="total-badge">
        <div class="total-num">{total}</div>
        <div class="total-sub">Alerts</div>
      </div>
    </div>
    <div class="stat-grid">{stat_cards_html}</div>
  </div>

  <div class="section-title">Detection Alerts</div>
  <div class="tabs">
    <button class="tab active"  onclick="showTab('all',   this)">All ({total})</button>
    <button class="tab"         onclick="showTab('chain', this)">Chains ({n_chains})</button>
    <button class="tab"         onclick="showTab('proc',  this)">Processes ({n_procs})</button>
    <button class="tab"         onclick="showTab('svc',   this)">Services ({n_svcs})</button>
  </div>

  <div id="tab-all"   class="tab-panel active">{all_cards}</div>
  <div id="tab-chain" class="tab-panel">{chain_cards}</div>
  <div id="tab-proc"  class="tab-panel">{proc_cards}</div>
  <div id="tab-svc"   class="tab-panel">{svc_cards}</div>

  <div class="section-title">
    Active Processes ({len(processes)} total, showing up to 200)
  </div>
  <div class="data-table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>PID</th><th>Name</th><th>PPID</th>
          <th>Executable Path</th><th>User</th><th>Status</th>
        </tr>
      </thead>
      <tbody>{proc_rows}</tbody>
    </table>
  </div>

  {svc_section}

</div>

<script>
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[+] HTML dashboard saved -> {filename}")
    return filename
