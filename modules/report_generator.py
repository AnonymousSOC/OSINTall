#!/usr/bin/env python3
"""
OSINTALL - Report Generation Module (Enhanced v2.2)
Exports reconnaissance findings to structured JSON, flat CSV, Maltego-compatible CSV,
and modern dark-mode HTML executive dashboards featuring an interactive Vis.js Node Relationship Graph,
Cloud Storage Buckets, Threat Intelligence, and Search Dorks.
"""

import os
import csv
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

def build_graph_elements(data: dict, target_name: str) -> tuple:
    """Builds nodes and edges datasets for the interactive Vis.js relationship graph."""
    nodes = [{
        "id": "target",
        "label": f"TARGET\n{target_name}",
        "color": "#1f6feb",
        "shape": "box",
        "font": {"color": "#ffffff", "size": 16, "bold": True}
    }]
    edges = []

    # 1. IP Geolocation & ASN Nodes
    ip_geos = data.get("ip_geolocation", [])
    for idx, g in enumerate(ip_geos):
        ip_id = f"ip_{idx}"
        ip_addr = g.get("ip", f"IP-{idx}")
        loc_str = f"{g.get('city', '')}, {g.get('country', '')}".strip(", ")
        nodes.append({
            "id": ip_id,
            "label": f"IP: {ip_addr}\n{loc_str}",
            "color": "#238636",
            "shape": "box",
            "font": {"color": "#ffffff", "size": 13}
        })
        edges.append({"from": "target", "to": ip_id, "label": "resolves to"})

        # ASN node
        if g.get("asn"):
            asn_id = f"asn_{idx}"
            nodes.append({
                "id": asn_id,
                "label": f"ASN: {g.get('asn')}\n{g.get('isp', '')}",
                "color": "#8957e5",
                "shape": "ellipse",
                "font": {"color": "#ffffff", "size": 11}
            })
            edges.append({"from": ip_id, "to": asn_id})

    # 2. InternetDB Ports & CVE Nodes
    internetdb = data.get("internetdb", [])
    for idx, idb in enumerate(internetdb):
        parent_ip = f"ip_{idx}" if idx < len(ip_geos) else "target"
        ports = idb.get("ports", [])
        if ports:
            ports_id = f"ports_{idx}"
            nodes.append({
                "id": ports_id,
                "label": f"Open Ports ({len(ports)})\n{', '.join(map(str, sorted(ports)[:6]))}",
                "color": "#d29922",
                "shape": "box",
                "font": {"color": "#ffffff", "size": 12}
            })
            edges.append({"from": parent_ip, "to": ports_id, "label": "listens on"})

        vulns = idb.get("vulns", [])
        if vulns:
            vuln_id = f"vuln_{idx}"
            nodes.append({
                "id": vuln_id,
                "label": f"CVEs ({len(vulns)})\n{', '.join(vulns[:3])}",
                "color": "#da3633",
                "shape": "diamond",
                "font": {"color": "#ffffff", "size": 12, "bold": True}
            })
            edges.append({"from": parent_ip, "to": vuln_id, "label": "vulnerable"})

    # 3. Subdomains & Takeover Nodes
    subdomains = data.get("subdomains", [])
    live_subdomains = data.get("subdomains_live", [])
    sample_subs = live_subdomains[:8] if live_subdomains else [{"subdomain": s} for s in subdomains[:6]]
    for idx, s in enumerate(sample_subs):
        sub_id = f"sub_{idx}"
        sub_name = s.get("subdomain", "")
        nodes.append({
            "id": sub_id,
            "label": f"Subdomain:\n{sub_name}",
            "color": "#2ea043" if s.get("live") else "#388bfd",
            "shape": "ellipse",
            "font": {"color": "#ffffff", "size": 11}
        })
        edges.append({"from": "target", "to": sub_id})

        if s.get("takeover_risk"):
            to_id = f"takeover_{idx}"
            nodes.append({
                "id": to_id,
                "label": f"⚠️ Takeover:\n{s.get('takeover_risk')}",
                "color": "#da3633",
                "shape": "box",
                "font": {"color": "#ffffff", "size": 11, "bold": True}
            })
            edges.append({"from": sub_id, "to": to_id, "label": "dangling CNAME"})

    # 4. Tech Stack Nodes
    tech_stack = data.get("tech_stack", [])
    for idx, t in enumerate(tech_stack[:8]):
        t_id = f"tech_{idx}"
        nodes.append({
            "id": t_id,
            "label": f"{t.get('category')}\n{t.get('name')}",
            "color": "#58a6ff",
            "shape": "ellipse",
            "font": {"color": "#ffffff", "size": 11}
        })
        edges.append({"from": "target", "to": t_id, "label": "running"})

    # 5. Social & Developer Profiles
    social_profiles = data.get("found_profiles", [])
    if not social_profiles and "username_scan" in data:
        social_profiles = data["username_scan"].get("found_profiles", [])
    for idx, p in enumerate(social_profiles[:10]):
        sp_id = f"soc_{idx}"
        nodes.append({
            "id": sp_id,
            "label": f"Account:\n{p.get('platform')}",
            "color": "#238636",
            "shape": "box",
            "font": {"color": "#ffffff", "size": 11}
        })
        edges.append({"from": "target", "to": sp_id, "label": "profile"})

    # 6. Phone Intelligence Nodes
    if data.get("e164"):
        nodes.append({
            "id": "phone_country",
            "label": f"Country: {data.get('country_name')}\nDial: +{data.get('country_code')}",
            "color": "#d29922",
            "shape": "box",
            "font": {"color": "#ffffff", "size": 12}
        })
        edges.append({"from": "target", "to": "phone_country"})
        nodes.append({
            "id": "phone_type",
            "label": f"Line Type:\n{data.get('line_type')}",
            "color": "#8957e5",
            "shape": "ellipse",
            "font": {"color": "#ffffff", "size": 11}
        })
        edges.append({"from": "target", "to": "phone_type"})

    # 7. Infostealer Alert Node
    infostealer = data.get("infostealer", {}) or data.get("infostealer_exposure", {})
    if infostealer.get("found"):
        stealers = infostealer.get("stealers", [])
        nodes.append({
            "id": "malware_alert",
            "label": f"🚨 INFOSTEALER\n{len(stealers)} Compromises",
            "color": "#da3633",
            "shape": "diamond",
            "font": {"color": "#ffffff", "size": 13, "bold": True}
        })
        edges.append({"from": "target", "to": "malware_alert", "label": "compromised by"})

    # 8. Cloud Storage Bucket Nodes
    cloud_buckets = data.get("cloud_buckets", []) or data.get("buckets", [])
    for idx, b in enumerate(cloud_buckets[:8]):
        b_id = f"cloud_{idx}"
        b_open = b.get("status") == "OPEN"
        nodes.append({
            "id": b_id,
            "label": f"Cloud: {b.get('provider')}\n{b.get('bucket')}\n{'[PUBLIC LEAK]' if b_open else '[PROTECTED]'}",
            "color": "#da3633" if b_open else "#d29922",
            "shape": "box",
            "font": {"color": "#ffffff", "size": 11, "bold": b_open}
        })
        edges.append({"from": "target", "to": b_id, "label": "cloud storage"})

    # 9. Threat Intelligence Nodes
    threat_data = data.get("threat_intel", {}) or data.get("assessment", {})
    t_score = threat_data.get("threat_score") or threat_data.get("score") or data.get("threat_score", 0)
    if t_score > 0:
        nodes.append({
            "id": "threat_reputation",
            "label": f"⚠️ Threat Score: {t_score}/100\n{threat_data.get('threat_label', 'Abuse.ch Flagged')}",
            "color": "#da3633" if t_score >= 50 else "#d29922",
            "shape": "diamond",
            "font": {"color": "#ffffff", "size": 12, "bold": True}
        })
        edges.append({"from": "target", "to": "threat_reputation", "label": "threat reputation"})

    return nodes, edges

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

    # Tech Stack & InternetDB
    tech_stack = data.get("tech_stack", [])
    internetdb = data.get("internetdb", [])

    # Phone Recon data
    is_phone_recon = bool(data.get("e164"))

    # Infostealer / Breach data
    infostealer = data.get("infostealer", {}) or data.get("infostealer_exposure", {})
    if not infostealer and "breach_search" in data:
        infostealer = data["breach_search"].get("infostealer", {})

    # Cloud Buckets
    cloud_buckets = data.get("cloud_buckets", []) or data.get("buckets", [])
    open_buckets = [b for b in cloud_buckets if b.get("status") == "OPEN"]

    # Threat Intelligence & IoCs
    threat_intel = data.get("threat_intel", {}) or data.get("assessment", {})
    threat_score = threat_intel.get("score") if threat_intel.get("score") is not None else threat_intel.get("threat_score", data.get("threat_score"))
    urlhaus = data.get("urlhaus", {}) or threat_intel.get("urlhaus", {})
    threatfox = data.get("threatfox", {}) or threat_intel.get("threatfox", {})

    # Reverse IP & Search Dorks
    reverse_ip = data.get("reverse_ip", [])
    search_dorks = data.get("search_dorks", [])

    # Graph elements
    nodes, edges = build_graph_elements(data, target_name)
    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINTALL Executive Report - {html.escape(target_name)}</title>
    <!-- Vis.js Network for Maltego-style Interactive Graph -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
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
        .badge-purple {{ background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); border: 1px solid var(--accent-purple); }}

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

        /* Graph Canvas */
        #network-graph {{
            width: 100%;
            height: 520px;
            background-color: #090d13;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-top: 15px;
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

        /* Profiles & Tech Pills */
        .grid-pills {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .pill-card {{
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
        .pill-card:hover {{
            border-color: var(--accent-blue);
            transform: translateY(-2px);
        }}

        /* Alert Box */
        .alert-box {{
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }}
        .alert-danger {{ background: rgba(248, 81, 73, 0.1); border-color: var(--accent-red); color: #ff7b72; }}
        .alert-success {{ background: rgba(63, 185, 80, 0.1); border-color: var(--accent-green); color: #7ee787; }}

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
                <h1>🕵️ OSINTALL Executive Intelligence Report</h1>
                <div class="meta">Target: <strong>{html.escape(target_name)}</strong> | Generated: {now_str} | Platform: Kali Linux</div>
            </div>
            <div>
                <span class="badge badge-blue">OSINTALL v2.1</span>
            </div>
        </header>

        <!-- Stat Metrics -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="label">Subdomains Discovered</span>
                <span class="value">{len(subdomains)}</span>
                <span class="sub">{len(live_subdomains)} confirmed live hosts</span>
            </div>
            <div class="stat-card">
                <span class="label">Identified Profiles / Telecom</span>
                <span class="value">{len(social_profiles) if not is_phone_recon else 1}</span>
                <span class="sub">{"Identity footprints" if not is_phone_recon else data.get("line_type", "Telecom")}</span>
            </div>
            <div class="stat-card">
                <span class="label">Detected Technologies</span>
                <span class="value">{len(tech_stack)}</span>
                <span class="sub">CMS, Servers & Frameworks</span>
            </div>
            <div class="stat-card">
                <span class="label">Takeover / CVE Warnings</span>
                <span class="value" style="color: {'var(--accent-red)' if takeover_warnings else 'var(--accent-green)'}">{len(takeover_warnings)}</span>
                <span class="sub">Infrastructure risks</span>
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

    # Critical Public Cloud Leak Alert
    if open_buckets:
        html_code += f"""
        <div class="alert-box alert-danger">
            <strong>🚨 Critical Cloud Exposure Alert:</strong> {len(open_buckets)} public cloud storage bucket(s) identified with unauthenticated read/listing enabled. Immediate remediation required.
        </div>
        """

    # Threat Reputation Alert
    if threat_score is not None and threat_score > 0:
        level_class = "alert-danger" if threat_score >= 50 else "alert-warning"
        html_code += f"""
        <div class="alert-box {level_class}">
            <strong>⚠️ Threat Intelligence Alert:</strong> Target scored {threat_score}/100 on cybercrime threat reputation databases (Abuse.ch URLhaus / ThreatFox).
        </div>
        """

    # Takeover alerts if detected
    if takeover_warnings:
        html_code += '<div class="alert-box alert-danger"><strong>⚠️ Subdomain Takeover Warning:</strong> One or more subdomains point to third-party services with dangling CNAME records:<ul>'
        for tw in takeover_warnings:
            html_code += f"<li><strong>{html.escape(tw['subdomain'])}</strong> &rarr; {html.escape(str(tw.get('takeover_risk')))}</li>"
        html_code += "</ul></div>"

    # VIS.JS INTERACTIVE NODE GRAPH CARD
    html_code += f"""
        <div class="section-card">
            <h2>🕸️ Interactive Intelligence Relationship Graph</h2>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 8px;">
                Drag, zoom, and pan to explore entities, network links, open ports, and infrastructure topology.
            </div>
            <div id="network-graph"></div>
        </div>
    """

    # PHONE NUMBER RECONNAISSANCE CARD (If TELINT was run)
    if is_phone_recon:
        html_code += f"""
        <div class="section-card">
            <h2>📱 Phone Number Intelligence (TELINT)</h2>
            <table>
                <tbody>
                    <tr><td><strong>E.164 Standard</strong></td><td><code>{html.escape(data.get("e164", ""))}</code></td></tr>
                    <tr><td><strong>International Format</strong></td><td>{html.escape(data.get("international_format", ""))}</td></tr>
                    <tr><td><strong>Country / Dial Code</strong></td><td>{html.escape(data.get("country_name", ""))} (+{html.escape(data.get("country_code", ""))})</td></tr>
                    <tr><td><strong>Estimated Line Type</strong></td><td><span class="badge badge-green">{html.escape(data.get("line_type", "Cellular / Fixed"))}</span></td></tr>
                </tbody>
            </table>
            <h3 style="color: var(--accent-blue); font-size: 1.05rem; margin-top: 20px;">Messaging App Profiles & Direct Lookups</h3>
            <div class="grid-pills">
                <a href="{html.escape(data.get('messaging_links', {}).get('whatsapp', '#'))}" target="_blank" class="pill-card">
                    <span><strong>WhatsApp Direct</strong></span>
                    <span style="color: var(--accent-green);">Chat &rarr;</span>
                </a>
                <a href="{html.escape(data.get('messaging_links', {}).get('telegram', '#'))}" target="_blank" class="pill-card">
                    <span><strong>Telegram Direct</strong></span>
                    <span style="color: var(--accent-blue);">Open &rarr;</span>
                </a>
                <a href="{html.escape(data.get('reputation_links', {}).get('truecaller', '#'))}" target="_blank" class="pill-card">
                    <span><strong>Truecaller Lookup</strong></span>
                    <span style="color: var(--accent-yellow);">Search &rarr;</span>
                </a>
            </div>
        </div>
        """

    # CLOUD STORAGE BUCKET AUDIT CARD (CLOUDINT)
    if cloud_buckets:
        html_code += """
        <div class="section-card">
            <h2>☁️ Multi-Cloud Storage Buckets & Exposure (CLOUDINT)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Cloud Provider</th>
                        <th>Bucket / Container Name</th>
                        <th>Exposure Status</th>
                        <th>Details & Direct Link</th>
                    </tr>
                </thead>
                <tbody>
        """
        for b in cloud_buckets:
            b_open = b.get("status") == "OPEN"
            status_badge = "<span class='badge badge-red'>🚨 PUBLIC LEAK (200)</span>" if b_open else "<span class='badge badge-yellow'>🔒 PROTECTED (403)</span>"
            url_link = f"<a href='{html.escape(b.get('url', ''))}' target='_blank' style='color:var(--accent-blue);'>{html.escape(b.get('url', ''))}</a>" if b.get('url') else html.escape(b.get("details", ""))
            html_code += f"""
                <tr>
                    <td><strong>{html.escape(b.get("provider", ""))}</strong></td>
                    <td><code>{html.escape(b.get("bucket", ""))}</code></td>
                    <td>{status_badge}</td>
                    <td>{url_link}</td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # THREAT INTELLIGENCE & REPUTATION CARD
    if threat_score is not None or urlhaus.get("url_count", 0) > 0 or threatfox.get("ioc_count", 0) > 0:
        score_val = threat_score if threat_score is not None else 0
        score_color = "var(--accent-red)" if score_val >= 50 else ("var(--accent-yellow)" if score_val > 0 else "var(--accent-green)")
        html_code += f"""
        <div class="section-card">
            <h2>🛡️ Threat Intelligence & Malware Reputation</h2>
            <div style="margin-bottom: 16px; padding: 12px; background: var(--bg-subtle); border-radius: 6px; border-left: 4px solid {score_color};">
                <div style="font-size: 1.1rem; font-weight: 600; color: {score_color};">
                    Threat Severity Score: {score_val} / 100
                </div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;">
                    Aggregated across Abuse.ch URLhaus malware repository and ThreatFox Indicators of Compromise.
                </div>
            </div>
        """
        if urlhaus.get("urls"):
            html_code += """
            <h3 style="font-size: 1rem; color: var(--accent-red); margin-top: 15px;">🦠 Active / Historical Malware URLs (URLhaus)</h3>
            <table>
                <thead><tr><th>Malicious URL</th><th>Status</th><th>Threat</th></tr></thead>
                <tbody>
            """
            for u in urlhaus.get("urls", [])[:6]:
                u_stat = "<span class='badge badge-red'>Online</span>" if u.get("url_status") == "online" else "<span class='badge badge-green'>Offline</span>"
                html_code += f"<tr><td><code>{html.escape(u.get('url', ''))}</code></td><td>{u_stat}</td><td>{html.escape(u.get('threat', 'Malware'))}</td></tr>"
            html_code += "</tbody></table>"

        if threatfox.get("iocs"):
            html_code += """
            <h3 style="font-size: 1rem; color: var(--accent-yellow); margin-top: 15px;">🎯 ThreatFox IoC Signatures & Malware Families</h3>
            <table>
                <thead><tr><th>Indicator (IoC)</th><th>Threat Type</th><th>Malware Family</th><th>Confidence</th></tr></thead>
                <tbody>
            """
            for ioc in threatfox.get("iocs", [])[:6]:
                html_code += f"<tr><td><code>{html.escape(ioc.get('ioc', ''))}</code></td><td>{html.escape(ioc.get('threat_type_desc', ioc.get('threat_type', '')))}</td><td><span class='badge badge-red'>{html.escape(ioc.get('malware_printable', 'Unknown'))}</span></td><td>{ioc.get('confidence_level', 0)}%</td></tr>"
            html_code += "</tbody></table>"
        html_code += "</div>"

    # SHODAN INTERNETDB TELEMETRY CARD (Zero-Key Port & CVE Discovery)
    if internetdb:
        html_code += """
        <div class="section-card">
            <h2>⚡ Shodan InternetDB Open Ports & CVE Telemetry</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target IP</th>
                        <th>Open Ports</th>
                        <th>Software (CPEs)</th>
                        <th>CVE Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idb in internetdb:
            ports_str = ", ".join(map(str, sorted(idb.get("ports", [])))) or "None detected"
            cpes_list = idb.get("cpes", [])
            cpes_str = "<br>".join(map(html.escape, cpes_list[:4])) or "-"
            vulns_list = idb.get("vulns", [])
            vulns_str = ", ".join(vulns_list[:6]) or "None detected"
            vuln_badge = f"<span class='badge badge-red'>{len(vulns_list)} CVEs</span> {html.escape(vulns_str)}" if vulns_list else "<span class='badge badge-green'>No Known CVEs</span>"
            html_code += f"""
                <tr>
                    <td><code>{html.escape(idb.get("ip", ""))}</code></td>
                    <td><code>{html.escape(ports_str)}</code></td>
                    <td>{cpes_str}</td>
                    <td>{vuln_badge}</td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # WEB TECHNOLOGIES & CMS FINGERPRINTING
    if tech_stack:
        html_code += """
        <div class="section-card">
            <h2>🛠️ Detected Web Technologies & Infrastructure</h2>
            <div class="grid-pills">
        """
        for t in tech_stack:
            html_code += f"""
                <div class="pill-card">
                    <div>
                        <div style="font-weight: 600; color: var(--accent-green);">{html.escape(t.get('name', ''))}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted);">{html.escape(t.get('category', ''))}</div>
                    </div>
                    <span class="badge badge-blue">Active</span>
                </div>
            """
        html_code += """
            </div>
        </div>
        """

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
            <div class="grid-pills">
        """
        for p in social_profiles:
            html_code += f"""
                <a href="{html.escape(p['url'])}" target="_blank" class="pill-card">
                    <span style="font-weight:600;">{html.escape(p['platform'])}</span>
                    <span style="color: var(--accent-green); font-size: 0.8rem;">Active &rarr;</span>
                </a>
            """
        html_code += """
            </div>
        </div>
        """

    # 6. REVERSE IP CO-HOSTING CARD
    if reverse_ip:
        html_code += """
        <div class="section-card">
            <h2>🔄 Reverse IP Co-Hosting (Adjacent Server Domains)</h2>
        """
        for item in reverse_ip:
            html_code += f"""
            <h3 style="font-size: 0.95rem; color: var(--accent-cyan);">Server IP: <code>{html.escape(item.get('ip', ''))}</code></h3>
            <div class="grid-pills" style="margin-bottom: 15px;">
            """
            for d in item.get("co_hosted_domains", [])[:15]:
                html_code += f"<div class='pill-card'><span style='font-family:monospace;'>{html.escape(d)}</span></div>"
            html_code += "</div>"
        html_code += "</div>"

    # 7. AUTOMATED SEARCH DORKS CARD (DORKINT)
    if search_dorks:
        html_code += """
        <div class="section-card">
            <h2>🔎 Targeted Search Dorks & Intelligence Queries (DORKINT)</h2>
            <div class="grid-pills">
        """
        for d in search_dorks:
            html_code += f"""
                <a href="{html.escape(d.get('url', '#'))}" target="_blank" class="pill-card" style="flex-direction: column; align-items: flex-start; gap: 4px;">
                    <div style="font-weight: 600; color: var(--accent-yellow);">{html.escape(d.get('category', ''))}</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); font-family: monospace;">{html.escape(d.get('dork', ''))}</div>
                    <span style="color: var(--accent-blue); font-size: 0.8rem; align-self: flex-end;">Open Dork &rarr;</span>
                </a>
            """
        html_code += """
            </div>
        </div>
        """

    # 8. Raw JSON Inspection Section
    html_code += f"""
        <details>
            <summary>📦 Full Raw Intelligence JSON Data (Expand)</summary>
            <pre><code>{html.escape(json.dumps(data, indent=4, default=str))}</code></pre>
        </details>
    </div>

    <!-- Vis.js Initialization Script -->
    <script type="text/javascript">
        try {{
            const nodesData = {nodes_json};
            const edgesData = {edges_json};
            const container = document.getElementById('network-graph');
            if (container && nodesData.length > 0) {{
                const data = {{
                    nodes: new vis.DataSet(nodesData),
                    edges: new vis.DataSet(edgesData)
                }};
                const options = {{
                    nodes: {{
                        shape: 'box',
                        margin: 10,
                        shadow: true,
                        font: {{ face: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto', color: '#ffffff' }}
                    }},
                    edges: {{
                        smooth: {{ type: 'continuous' }},
                        color: {{ color: '#30363d', highlight: '#58a6ff' }},
                        width: 1.5,
                        font: {{ size: 10, color: '#8b949e', align: 'top' }}
                    }},
                    physics: {{
                        stabilization: true,
                        barnesHut: {{
                            gravitationalConstant: -2500,
                            centralGravity: 0.3,
                            springLength: 110,
                            springConstant: 0.04
                        }}
                    }},
                    interaction: {{
                        hover: true,
                        navigationButtons: true,
                        keyboard: true
                    }}
                }};
                new vis.Network(container, data, options);
            }}
        }} catch(e) {{
            console.error("Vis.js initialization error:", e);
        }}
    </script>
</body>
</html>
"""
    return html_code

def save_html_report(data: dict, target_name: str) -> str:
    """Generates a styled, executive dark-mode HTML reconnaissance dashboard with Vis.js graph."""
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

def save_csv_report(data: dict, target_name: str) -> str:
    """Exports structured findings to a flat CSV spreadsheet."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"osint_report_{clean_target}_{timestamp}.csv"
    filepath = os.path.join(reports_dir, filename)

    rows = [["Category", "Entity_Type", "Value", "Status_Or_Details", "Additional_Info"]]

    # DNS
    dns_records = data.get("dns", {})
    for rtype, rlist in dns_records.items():
        for r in rlist:
            rows.append(["DNS", rtype, str(r), "Active", ""])

    # IP Geolocation
    for geo in data.get("ip_geolocation", []):
        loc = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(", ")
        isp_asn = f"ASN: {geo.get('asn', '')} ({geo.get('isp', '')})"
        rows.append(["Network", "IPv4Address", geo.get("ip", ""), loc, isp_asn])

    # InternetDB
    for idb in data.get("internetdb", []):
        ip = idb.get("ip", "")
        for port in idb.get("ports", []):
            rows.append(["Network", "Port", f"{ip}:{port}", "Open", "Shodan InternetDB"])
        for vuln in idb.get("vulns", []):
            rows.append(["Vulnerability", "CVE", vuln, ip, "Shodan InternetDB"])

    # Subdomains
    for sub in data.get("subdomains", []):
        rows.append(["Subdomain", "DNSName", sub, "Discovered", ""])
    for s in data.get("subdomains_live", []):
        cname = s.get("cname", "")
        risk = s.get("takeover_risk", "")
        rows.append(["Subdomain", "Live_DNSName", s.get("subdomain", ""), f"CNAME: {cname}", f"Takeover: {risk}" if risk else "Safe"])

    # Tech Stack
    for t in data.get("tech_stack", []):
        rows.append(["Technology", t.get("category", "Software"), t.get("name", ""), t.get("evidence", ""), ""])

    # Social Profiles
    for p in data.get("found_profiles", []):
        rows.append(["SOCMINT", "Profile", p.get("platform", ""), p.get("url", ""), ""])

    # Cloud Buckets
    cloud_buckets = data.get("cloud_buckets", []) or data.get("buckets", [])
    for b in cloud_buckets:
        rows.append(["CLOUDINT", b.get("provider", "Cloud Storage"), b.get("bucket", ""), b.get("status", ""), b.get("url", "")])

    # Threat Intel
    threat = data.get("threat_intel", {}) or data.get("assessment", {})
    if threat:
        rows.append(["ThreatIntel", "ThreatScore", f"{threat.get('score', data.get('threat_score', 0))}/100", threat.get("label", ""), ""])
    for u in data.get("urlhaus", {}).get("urls", []):
        rows.append(["ThreatIntel", "MalwareURL", u.get("url", ""), u.get("url_status", ""), u.get("threat", "")])
    for ioc in data.get("threatfox", {}).get("iocs", []):
        rows.append(["ThreatIntel", "ThreatFox_IoC", ioc.get("ioc", ""), ioc.get("malware_printable", ""), f"{ioc.get('confidence_level')}% confidence"])

    # Phone Intel
    if data.get("e164"):
        rows.append(["TELINT", "PhoneNumber", data.get("e164", ""), data.get("country_name", ""), data.get("line_type", "")])

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)
        print_success(f"Flat CSV Report exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save CSV report: {e}")
        return ""

def save_maltego_csv(data: dict, target_name: str) -> str:
    """Exports findings into a Maltego-compatible Entity CSV file for Kali Linux."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"maltego_entities_{clean_target}_{timestamp}.csv"
    filepath = os.path.join(reports_dir, filename)

    entities = [["Entity_Type", "Value", "Source", "Property_Notes"]]
    # Target
    entities.append(["maltego.Domain", target_name, "OSINTALL", "Primary Target"])

    # IPs
    for geo in data.get("ip_geolocation", []):
        entities.append(["maltego.IPv4Address", geo.get("ip", ""), target_name, f"{geo.get('city')}, {geo.get('country')} (ASN: {geo.get('asn')})"])

    # Subdomains
    for sub in data.get("subdomains", []):
        entities.append(["maltego.DNSName", sub, target_name, "Subdomain"])

    # DNS NS & MX
    for ns in data.get("dns", {}).get("NS", []):
        entities.append(["maltego.NSRecord", ns, target_name, "Name Server"])
    for mx in data.get("dns", {}).get("MX", []):
        entities.append(["maltego.MXRecord", mx, target_name, "Mail Exchange"])

    # Social Profiles
    for p in data.get("found_profiles", []):
        entities.append(["maltego.URL", p.get("url", ""), target_name, p.get("platform", "Social Profile")])

    # Phone Number
    if data.get("e164"):
        entities.append(["maltego.PhoneNumber", data.get("e164", ""), target_name, data.get("country_name", "")])

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(entities)
        print_success(f"Maltego Entity CSV exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save Maltego CSV: {e}")
        return ""
