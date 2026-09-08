#!/usr/bin/env python3
"""
OSINTALL - Report Generation Module (Enhanced)
Exports reconnaissance findings to structured JSON and modern dark-mode HTML executive dashboards.
"""

import os
import json
import datetime
import html
from modules.banner import console, print_info, print_success, print_error

def ensure_reports_dir() -> str:
    """Ensures reports directory exists and returns its absolute path."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def save_json_report(data: dict, target_name: str) -> str:
    """Saves raw structured intelligence data into a JSON file."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"osint_report_{clean_target}_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        print_success(f"JSON Report exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save JSON report: {e}")
        return ""

def generate_dashboard_html(data: dict, target_name: str) -> str:
    """Generates the full HTML markup for the executive dark-mode reconnaissance report."""
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Calculate key metrics
    subdomains = data.get("subdomains", [])
    live_subdomains = data.get("subdomains_live", [])
    takeover_warnings = data.get("takeover_warnings", [])
    social_profiles = data.get("found_profiles", [])
    if not social_profiles and "username_scan" in data:
        social_profiles = data["username_scan"].get("found_profiles", [])
    
    # Security header count
    http_headers = data.get("http_headers", {})
    sec_headers = {}
    for proto in ["https", "http"]:
        if proto in http_headers:
            sec_headers = http_headers[proto].get("security_headers", {})
            break
    
    present_sec = sum(1 for v in sec_headers.values() if v not in ["Missing", None])
    total_sec = len(sec_headers) if sec_headers else 6

    # IP Geolocation
    ip_geos = data.get("ip_geolocation", [])

    # DNS records
    dns_records = data.get("dns", {})

    # Email security
    email_sec = data.get("email_security", {})

    # SSL Certificate
    ssl_cert = data.get("ssl_certificate", {})

    # Infostealer / Breach data
    infostealer = data.get("infostealer", {}) or data.get("infostealer_exposure", {})
    if not infostealer and "breach_search" in data:
        infostealer = data["breach_search"].get("infostealer", {})

    html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINTALL Executive Report - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg-main: #0d1117;
            --bg-card: #161b22;
            --bg-subtle: #21262d;
            --border: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #bc8cff;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .header-title h1 {{
            margin: 0;
            font-size: 1.8rem;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header-title .meta {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-blue {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
        .badge-green {{ background: rgba(63, 185, 80, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-red {{ background: rgba(248, 81, 73, 0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-yellow {{ background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}

        /* Stat Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}
        .stat-card .label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-main);
            margin: 10px 0;
        }}
        .stat-card .sub {{
            font-size: 0.85rem;
            color: var(--accent-blue);
        }}

        /* Section Cards */
        .section-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        .section-card h2 {{
            margin-top: 0;
            font-size: 1.25rem;
            color: var(--accent-blue);
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.95rem;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: var(--bg-subtle);
            color: var(--text-muted);
            font-weight: 600;
        }}
        tr:hover td {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        /* Social Profiles Grid */
        .profiles-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .profile-pill {{
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            text-decoration: none;
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s ease;
        }}
        .profile-pill:hover {{
            border-color: var(--accent-blue);
            transform: translateY(-2px);
        }}
        .profile-name {{ font-weight: 600; font-size: 0.95rem; }}

        /* Security Alert Box */
        .alert-box {{
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }}
        .alert-danger {{
            background: rgba(248, 81, 73, 0.1);
            border-color: var(--accent-red);
            color: #ff7b72;
        }}
        .alert-success {{
            background: rgba(63, 185, 80, 0.1);
            border-color: var(--accent-green);
            color: #7ee787;
        }}

        /* Raw JSON Collapsible */
        details {{
            margin-top: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-subtle);
        }}
        summary {{
            padding: 12px 18px;
            cursor: pointer;
            font-weight: 600;
            color: var(--accent-blue);
            outline: none;
        }}
        pre {{
            margin: 0;
            padding: 20px;
            background: #090d13;
            overflow-x: auto;
            color: #79c0ff;
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
        }}
        a {{ color: var(--accent-blue); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="header-title">
                <h1>🕵️ OSINTALL Reconnaissance Report</h1>
                <div class="meta">Target: <strong>{html.escape(target_name)}</strong> | Generated: {now_str} | Platform: Kali Linux</div>
            </div>
            <div>
                <span class="badge badge-blue">OSINTALL v2.0</span>
            </div>
        </header>

        <!-- Stat Metrics -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="label">Discovered Subdomains</span>
                <span class="value">{len(subdomains)}</span>
                <span class="sub">{len(live_subdomains)} confirmed live hosts</span>
            </div>
            <div class="stat-card">
                <span class="label">Social & Dev Profiles</span>
                <span class="value">{len(social_profiles)}</span>
                <span class="sub">Active account footprints</span>
            </div>
            <div class="stat-card">
                <span class="label">HTTP Security Score</span>
                <span class="value">{present_sec} / {total_sec}</span>
                <span class="sub">Headers implemented</span>
            </div>
            <div class="stat-card">
                <span class="label">Takeover Risks</span>
                <span class="value" style="color: {'var(--accent-red)' if takeover_warnings else 'var(--accent-green)'}">{len(takeover_warnings)}</span>
                <span class="sub">Dangling CNAME warnings</span>
            </div>
        </div>
"""

    # Infostealer Alert if detected
    if infostealer.get("found"):
        stealers = infostealer.get("stealers", [])
        html_code += f"""
        <div class="alert-box alert-danger">
            <strong>🚨 Cybercrime Telemetry Alert:</strong> Infostealer malware compromised credentials were identified for this target ({len(stealers)} compromised devices recorded in Hudson Rock intelligence).
        </div>
        """

    # Takeover alerts if detected
    if takeover_warnings:
        html_code += '<div class="alert-box alert-danger"><strong>⚠️ Subdomain Takeover Warning:</strong> One or more subdomains point to third-party services with dangling CNAME records:<ul>'
        for tw in takeover_warnings:
            html_code += f"<li><strong>{html.escape(tw['subdomain'])}</strong> &rarr; {html.escape(str(tw.get('takeover_risk')))}</li>"
        html_code += "</ul></div>"

    # 1. Network Infrastructure & IP Geolocation
    if ip_geos:
        html_code += """
        <div class="section-card">
            <h2>🌐 Network Infrastructure & IP Geolocation</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>ISP / Hosting Organization</th>
                        <th>ASN</th>
                    </tr>
                </thead>
                <tbody>
        """
        for g in ip_geos:
            loc = f"{html.escape(g.get('city', ''))}, {html.escape(g.get('country', ''))}"
            html_code += f"""
                <tr>
                    <td><code>{html.escape(g.get('ip', ''))}</code></td>
                    <td>{loc}</td>
                    <td>{html.escape(g.get('isp', ''))} ({html.escape(g.get('org', ''))})</td>
                    <td><code>{html.escape(str(g.get('asn', '')))}</code></td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # 2. Email & Domain Spoofing Security
    if email_sec:
        spf_status = email_sec.get("spf_status", "N/A")
        dmarc_policy = email_sec.get("dmarc_policy", "N/A")
        html_code += f"""
        <div class="section-card">
            <h2>📧 Email Spoofing & Authentication Security</h2>
            <table>
                <tbody>
                    <tr>
                        <td style="width: 25%;"><strong>SPF Authentication</strong></td>
                        <td>{html.escape(spf_status)}</td>
                    </tr>
                    <tr>
                        <td><strong>SPF Record</strong></td>
                        <td><code>{html.escape(email_sec.get("spf_record", "Missing"))}</code></td>
                    </tr>
                    <tr>
                        <td><strong>DMARC Policy</strong></td>
                        <td>Policy: <code>{html.escape(dmarc_policy)}</code></td>
                    </tr>
                    <tr>
                        <td><strong>DMARC Record</strong></td>
                        <td><code>{html.escape(email_sec.get("dmarc_record", "Missing"))}</code></td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    # 3. Discovered Subdomains
    if subdomains:
        sample_subs = live_subdomains if live_subdomains else [{"subdomain": s, "ips": [], "live": False} for s in subdomains[:20]]
        html_code += f"""
        <div class="section-card">
            <h2>📡 Discovered Subdomains ({len(subdomains)} Total)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>IP Address(es)</th>
                        <th>CNAME Details</th>
                    </tr>
                </thead>
                <tbody>
        """
        for sub_item in sample_subs[:25]:
            is_live = sub_item.get("live", False)
            badge_class = "badge-green" if is_live else "badge-blue"
            status_label = "LIVE" if is_live else "Passive"
            ips_str = ", ".join(sub_item.get("ips", [])) or "-"
            cname_str = sub_item.get("cname") or "-"
            if sub_item.get("takeover_risk"):
                cname_str = f"<span style='color:var(--accent-red); font-weight:bold;'>⚠️ {html.escape(sub_item['takeover_risk'])}</span>"
            html_code += f"""
                <tr>
                    <td><code>{html.escape(sub_item.get('subdomain', ''))}</code></td>
                    <td><span class="badge {badge_class}">{status_label}</span></td>
                    <td>{html.escape(ips_str)}</td>
                    <td>{cname_str}</td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # 4. HTTP Security Headers
    if sec_headers:
        html_code += """
        <div class="section-card">
            <h2>🛡️ HTTP Security Protections</h2>
            <table>
                <thead>
                    <tr>
                        <th>Header Name</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        """
        for hname, hval in sec_headers.items():
            is_present = hval not in ["Missing", None]
            badge_class = "badge-green" if is_present else "badge-red"
            val_text = "PRESENT" if is_present else "MISSING"
            html_code += f"""
                <tr>
                    <td><code>{html.escape(hname)}</code></td>
                    <td><span class="badge {badge_class}">{val_text}</span></td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # 5. SOCMINT & Discovered Profiles
    if social_profiles:
        html_code += f"""
        <div class="section-card">
            <h2>👤 Verified Social & Developer Footprints ({len(social_profiles)} Found)</h2>
            <div class="profiles-grid">
        """
        for p in social_profiles:
            html_code += f"""
                <a href="{html.escape(p['url'])}" target="_blank" class="profile-pill">
                    <span class="profile-name">{html.escape(p['platform'])}</span>
                    <span style="color: var(--accent-green); font-size: 0.8rem;">Active &rarr;</span>
                </a>
            """
        html_code += """
            </div>
        </div>
        """

    # 6. Raw JSON Inspection Section
    html_code += f"""
        <details>
            <summary>📦 Full Raw Intelligence JSON Data (Expand)</summary>
            <pre><code>{html.escape(json.dumps(data, indent=4, default=str))}</code></pre>
        </details>
    </div>
</body>
</html>
"""
    return html_code

def save_html_report(data: dict, target_name: str) -> str:
    """Generates a styled, executive dark-mode HTML reconnaissance dashboard."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"osint_report_{clean_target}_{timestamp}.html"
    filepath = os.path.join(reports_dir, filename)

    try:
        html_content = generate_dashboard_html(data, target_name)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print_success(f"Executive HTML Dashboard exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save HTML report: {e}")
        return ""
