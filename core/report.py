#!/usr/bin/env python3
"""
HTML report generator — produce a self-contained, styled HTML report
from scan results.  Uses a dark theme with colour-coded severity.
"""

import os
import datetime
import webbrowser
import html as html_lib

from core.config import EVIE_HOME, REPORT_DIR, FRAMEWORK_VERSION


def generate_report(results, targets_str="", duration_s=0, auto_open=True):
    """Generate and save an HTML report.

    Args:
        results: The scan results dict.
        targets_str: Comma-separated target string for the header.
        duration_s: Scan duration in seconds.
        auto_open: Whether to open the report in the default browser.

    Returns:
        The absolute path to the generated HTML file.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(REPORT_DIR, f"evie_report_{ts}.html")

    html = _build_html(results, targets_str, duration_s)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    if auto_open:
        try:
            import subprocess, platform
            url = f"file://{os.path.abspath(filepath)}"
            system = platform.system().lower()
            if system == "darwin":
                subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "windows":
                os.startfile(os.path.abspath(filepath))
            else:
                # Linux / WSL — try xdg-open silently, ignore failures
                subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass  # no browser available — user has the file path

    return filepath


def _esc(text):
    """HTML-escape a string."""
    return html_lib.escape(str(text)) if text else ""


def _build_html(results, targets_str, duration_s):
    """Build the full HTML document."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Aggregate stats ───────────────────────────────────────────
    total_targets = len(results)
    total_ports = 0
    total_vulns = 0
    for data in results.values():
        if isinstance(data, dict):
            total_ports += len(data.get("open_ports", []))
            vulns = data.get("vulnerabilities", [])
            total_vulns += len([v for v in vulns if "error" not in v])

    duration_str = f"{duration_s:.1f}s" if duration_s else "N/A"

    # ── Target sections ───────────────────────────────────────────
    target_sections = ""
    for target, data in results.items():
        target_sections += _render_target_section(target, data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVIE Scan Report — {_esc(targets_str)}</title>
<style>
{_css()}
</style>
</head>
<body>
<div class="container">

  <header class="header">
    <div class="logo">
      <span class="logo-text">EVIE</span>
      <span class="version">v{FRAMEWORK_VERSION}</span>
    </div>
    <h1>Scan Report</h1>
    <p class="meta">Generated: {now} &nbsp;|&nbsp; Targets: {_esc(targets_str)} &nbsp;|&nbsp; Duration: {duration_str}</p>
  </header>

  <section class="dashboard">
    <div class="stat-card">
      <div class="stat-value">{total_targets}</div>
      <div class="stat-label">Targets</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{total_ports}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card stat-vuln">
      <div class="stat-value">{total_vulns}</div>
      <div class="stat-label">CVEs Found</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{duration_str}</div>
      <div class="stat-label">Duration</div>
    </div>
  </section>

  {target_sections}

  <footer class="footer">
    EVIE v{FRAMEWORK_VERSION} — Network Reconnaissance Tool Framework &nbsp;|&nbsp; github.com/Xdzy-TD
  </footer>

</div>
</body>
</html>"""


def _render_target_section(target, data):
    """Render one target's results as an HTML section."""
    if not isinstance(data, dict):
        return f"""
  <section class="target">
    <h2 class="target-title">{_esc(target)}</h2>
    <p>{_esc(str(data))}</p>
  </section>"""

    sections = []

    # ── Open Ports ────────────────────────────────────────────────
    ports = data.get("open_ports", [])
    if ports:
        rows = "".join(f"<tr><td>{_esc(p)}</td></tr>" for p in ports)
        sections.append(f"""
    <div class="module">
      <h3>🔌 Open Ports</h3>
      <table><thead><tr><th>Port / Service</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── Banners ───────────────────────────────────────────────────
    banners = data.get("banners", {})
    if banners:
        rows = "".join(
            f"<tr><td>{_esc(p)}</td><td><code>{_esc(b[:120])}</code></td></tr>"
            for p, b in banners.items()
        )
        sections.append(f"""
    <div class="module">
      <h3>📡 Service Banners</h3>
      <table><thead><tr><th>Port</th><th>Banner</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── DNS ────────────────────────────────────────────────────────
    dns_info = data.get("dns")
    if dns_info:
        rows = f"<tr><td>Reverse</td><td>{_esc(dns_info.get('reverse', 'N/A'))}</td></tr>"
        for rtype, vals in dns_info.get("records", {}).items():
            rows += f"<tr><td>{_esc(rtype)}</td><td>{_esc(', '.join(vals))}</td></tr>"
        sections.append(f"""
    <div class="module">
      <h3>🌐 DNS</h3>
      <table><thead><tr><th>Type</th><th>Value</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── HTTP/HTTPS Headers ────────────────────────────────────────
    for key in ("http_headers", "https_headers"):
        hdr = data.get(key)
        if not hdr:
            continue
        proto = "HTTPS" if "https" in key else "HTTP"
        rows = ""
        for k, v in hdr.get("server_info", {}).items():
            rows += f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        sec = hdr.get("security", {})
        present = sec.get("present", [])
        missing = sec.get("missing", [])
        if present:
            rows += f'<tr><td>✅ Present</td><td class="ok">{_esc(", ".join(present))}</td></tr>'
        if missing:
            rows += f'<tr><td>❌ Missing</td><td class="warn">{_esc(", ".join(missing))}</td></tr>'
        sections.append(f"""
    <div class="module">
      <h3>📋 {proto} Headers</h3>
      <table><thead><tr><th>Header</th><th>Value</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── WHOIS ─────────────────────────────────────────────────────
    whois_data = data.get("whois")
    if whois_data and "error" not in whois_data:
        rows = ""
        for k, v in whois_data.items():
            val = ", ".join(v) if isinstance(v, list) else str(v)
            rows += f"<tr><td>{_esc(k)}</td><td>{_esc(val)}</td></tr>"
        sections.append(f"""
    <div class="module">
      <h3>📄 WHOIS</h3>
      <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── SSL/TLS ───────────────────────────────────────────────────
    ssl_data = data.get("ssl")
    if ssl_data and "error" not in ssl_data:
        rows = ""
        for k, v in ssl_data.items():
            if k == "san":
                val = ", ".join(v[:5]) + (" …" if len(v) > 5 else "")
            else:
                val = str(v)
            rows += f"<tr><td>{_esc(k)}</td><td>{_esc(val)}</td></tr>"
        sections.append(f"""
    <div class="module">
      <h3>🔒 SSL / TLS</h3>
      <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── OS Detection ──────────────────────────────────────────────
    os_data = data.get("os")
    if os_data:
        conf = os_data.get("confidence", "N/A")
        conf_cls = "ok" if conf == "high" else "mid" if conf == "medium" else "warn"
        sections.append(f"""
    <div class="module">
      <h3>💻 OS Detection</h3>
      <table>
      <tr><td>OS Guess</td><td><strong>{_esc(os_data.get('os_guess', 'Unknown'))}</strong></td></tr>
      <tr><td>Confidence</td><td class="{conf_cls}">{_esc(conf)}</td></tr>
      <tr><td>TTL</td><td>{_esc(os_data.get('ttl', '?'))} → initial {_esc(os_data.get('initial_ttl', '?'))}</td></tr>
      <tr><td>Window</td><td>{_esc(os_data.get('window', '?'))}</td></tr>
      </table>
    </div>""")

    # ── GeoIP ─────────────────────────────────────────────────────
    geo = data.get("geoip")
    if geo and "error" not in geo:
        rows = ""
        for k in ("country", "city", "region", "isp", "org", "as_number",
                   "timezone", "latitude", "longitude", "is_proxy", "is_hosting"):
            v = geo.get(k)
            if v is not None:
                rows += f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        sections.append(f"""
    <div class="module">
      <h3>🌍 GeoIP</h3>
      <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── Subdomains ────────────────────────────────────────────────
    subs = data.get("subdomains", [])
    if subs:
        rows = "".join(
            f"<tr><td>{_esc(s['subdomain'])}</td><td>{_esc(s['ip'])}</td></tr>"
            for s in subs[:50]
        )
        sections.append(f"""
    <div class="module">
      <h3>🔎 Subdomains ({len(subs)} found)</h3>
      <table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── Technologies ──────────────────────────────────────────────
    tech = data.get("technologies")
    if tech and tech.get("technologies"):
        techs = tech["technologies"]
        badges = " ".join(f'<span class="badge">{_esc(t)}</span>' for t in techs)
        sections.append(f"""
    <div class="module">
      <h3>⚙️ Technologies</h3>
      <div class="badges">{badges}</div>
    </div>""")

    # ── Traceroute ────────────────────────────────────────────────
    trace = data.get("traceroute", [])
    if trace and not (len(trace) == 1 and "error" in trace[0]):
        rows = "".join(
            f"<tr><td>{h.get('hop')}</td><td>{_esc(h.get('ip'))}</td>"
            f"<td>{_esc(h.get('host'))}</td><td>{_esc(h.get('rtt'))}</td></tr>"
            for h in trace
        )
        sections.append(f"""
    <div class="module">
      <h3>🛤️ Traceroute</h3>
      <table><thead><tr><th>#</th><th>IP</th><th>Host</th><th>RTT</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    # ── Vulnerabilities ───────────────────────────────────────────
    vulns = data.get("vulnerabilities", [])
    valid_vulns = [v for v in vulns if "error" not in v]
    if valid_vulns:
        rows = ""
        for v in valid_vulns:
            sev = v.get("severity", "UNKNOWN").upper()
            sev_cls = "crit" if sev in ("CRITICAL", "HIGH") else "mid" if sev == "MEDIUM" else "ok"
            rows += (
                f'<tr><td><a href="{_esc(v.get("url", "#"))}" target="_blank">'
                f'{_esc(v["cve_id"])}</a></td>'
                f'<td class="{sev_cls}">{_esc(sev)}</td>'
                f'<td>{_esc(v.get("score", "N/A"))}</td>'
                f'<td>{_esc(v.get("description", ""))}</td></tr>'
            )
        sections.append(f"""
    <div class="module module-vuln">
      <h3>🛡️ Vulnerabilities ({len(valid_vulns)} CVEs)</h3>
      <table><thead><tr><th>CVE</th><th>Severity</th><th>Score</th><th>Description</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>""")

    inner = "\n".join(sections) if sections else "<p>No data collected.</p>"

    return f"""
  <section class="target">
    <h2 class="target-title">🎯 {_esc(target)}</h2>
    {inner}
  </section>"""


def _css():
    """Return the embedded CSS for the report."""
    return """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #1c2333;
  --border: #30363d;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --accent2: #bc8cff;
  --green: #3fb950;
  --yellow: #d29922;
  --red: #f85149;
  --cyan: #79c0ff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif;
  line-height: 1.6;
}

.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }

.header {
  text-align: center;
  margin-bottom: 2.5rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}
.logo { margin-bottom: 0.5rem; }
.logo-text {
  font-size: 2.5rem;
  font-weight: 800;
  background: linear-gradient(135deg, var(--cyan), var(--accent2));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: 4px;
}
.version { color: var(--text-dim); font-size: 0.85rem; margin-left: 0.5rem; }
.header h1 { font-size: 1.3rem; font-weight: 400; color: var(--text-dim); margin-top: 0.3rem; }
.meta { color: var(--text-dim); font-size: 0.85rem; margin-top: 0.5rem; }

.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 2.5rem;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  text-align: center;
}
.stat-value { font-size: 2rem; font-weight: 700; color: var(--accent); }
.stat-label { color: var(--text-dim); font-size: 0.85rem; margin-top: 0.25rem; }
.stat-vuln .stat-value { color: var(--red); }

.target {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem 2rem;
  margin-bottom: 1.5rem;
}
.target-title {
  font-size: 1.3rem;
  color: var(--green);
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
}

.module {
  margin-bottom: 1.25rem;
  padding: 1rem;
  background: var(--surface2);
  border-radius: 8px;
}
.module h3 {
  font-size: 1rem;
  color: var(--cyan);
  margin-bottom: 0.75rem;
}
.module-vuln { border-left: 3px solid var(--red); }

table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th {
  text-align: left;
  padding: 0.5rem 0.75rem;
  background: var(--bg);
  color: var(--text-dim);
  font-weight: 600;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 0.4rem 0.75rem;
  border-bottom: 1px solid var(--border);
  word-break: break-word;
}
code { background: var(--bg); padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }

.ok { color: var(--green); }
.mid { color: var(--yellow); }
.warn { color: var(--red); }
.crit { color: var(--red); font-weight: 700; }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.badges { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.badge {
  background: var(--bg);
  color: var(--accent2);
  border: 1px solid var(--border);
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 600;
}

.footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 0.8rem;
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
}

@media (max-width: 600px) {
  .container { padding: 1rem; }
  .target { padding: 1rem; }
  .dashboard { grid-template-columns: repeat(2, 1fr); }
}
"""
