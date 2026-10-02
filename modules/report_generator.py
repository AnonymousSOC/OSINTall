#!/usr/bin/env python3
"""
OSINTALL - Report Generation Module (Enhanced v2.2 - Movie Hacker Terminal Edition)
Exports reconnaissance findings to structured JSON, flat CSV, Maltego-compatible CSV,
and cinematic Hollywood Movie Hacker Terminal HTML executive dashboards featuring
interactive Vis.js Node Relationship Graph, dynamic Matrix digital rain, CRT scanlines,
cyber synthesizer audio feedback, and live telemetry filtering.
"""

import os
import csv
import json
import datetime
import html
import hashlib
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
    """Builds nodes and edges datasets for the interactive Vis.js relationship graph with cyber aesthetics."""
    nodes = [{
        "id": "target",
        "label": f"🎯 TARGET\n{target_name}",
        "color": {
            "background": "#002b36",
            "border": "#00f3ff",
            "highlight": {"background": "#003d4d", "border": "#00ff88"}
        },
        "shape": "box",
        "font": {"color": "#00f3ff", "size": 15, "bold": True, "face": "monospace"},
        "borderWidth": 2,
        "shadow": {"enabled": True, "color": "rgba(0, 243, 255, 0.4)", "size": 12}
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
            "color": {
                "background": "#022b1c",
                "border": "#00ff88",
                "highlight": {"background": "#04402a", "border": "#39ff14"}
            },
            "shape": "box",
            "font": {"color": "#00ff88", "size": 12, "face": "monospace"},
            "borderWidth": 1.5,
            "shadow": {"enabled": True, "color": "rgba(0, 255, 136, 0.3)", "size": 8}
        })
        edges.append({
            "from": "target", "to": ip_id, "label": "resolves to",
            "color": {"color": "#00f3ff", "highlight": "#00ff88"},
            "font": {"color": "#00f3ff", "size": 10, "face": "monospace"}
        })

        # ASN node
        if g.get("asn"):
            asn_id = f"asn_{idx}"
            nodes.append({
                "id": asn_id,
                "label": f"ASN: {g.get('asn')}\n{g.get('isp', '')}",
                "color": {
                    "background": "#1a0b2e",
                    "border": "#bd93f9",
                    "highlight": {"background": "#2a124a", "border": "#d6b4fc"}
                },
                "shape": "ellipse",
                "font": {"color": "#bd93f9", "size": 11, "face": "monospace"},
                "borderWidth": 1.5
            })
            edges.append({
                "from": ip_id, "to": asn_id,
                "color": {"color": "#bd93f9", "highlight": "#d6b4fc"},
                "font": {"color": "#bd93f9", "size": 9, "face": "monospace"}
            })

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
                "color": {
                    "background": "#332200",
                    "border": "#ffb800",
                    "highlight": {"background": "#4d3300", "border": "#ffd166"}
                },
                "shape": "box",
                "font": {"color": "#ffb800", "size": 11, "face": "monospace"},
                "borderWidth": 1.5
            })
            edges.append({
                "from": parent_ip, "to": ports_id, "label": "listens on",
                "color": {"color": "#ffb800", "highlight": "#ffd166"},
                "font": {"color": "#ffb800", "size": 9, "face": "monospace"}
            })

        vulns = idb.get("vulns", [])
        if vulns:
            vuln_id = f"vuln_{idx}"
            nodes.append({
                "id": vuln_id,
                "label": f"⚠️ CVEs ({len(vulns)})\n{', '.join(vulns[:3])}",
                "color": {
                    "background": "#380611",
                    "border": "#ff0055",
                    "highlight": {"background": "#520919", "border": "#ff3377"}
                },
                "shape": "diamond",
                "font": {"color": "#ff0055", "size": 12, "bold": True, "face": "monospace"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(255, 0, 85, 0.5)", "size": 10}
            })
            edges.append({
                "from": parent_ip, "to": vuln_id, "label": "vulnerable",
                "color": {"color": "#ff0055", "highlight": "#ff3377"},
                "font": {"color": "#ff0055", "size": 9, "face": "monospace"}
            })

    # 3. Subdomains & Takeover Nodes
    subdomains = data.get("subdomains", [])
    live_subdomains = data.get("subdomains_live", [])
    sample_subs = live_subdomains[:8] if live_subdomains else [{"subdomain": s} for s in subdomains[:6]]
    for idx, s in enumerate(sample_subs):
        sub_id = f"sub_{idx}"
        sub_name = s.get("subdomain", "")
        is_live = s.get("live", False)
        nodes.append({
            "id": sub_id,
            "label": f"Subdomain:\n{sub_name}",
            "color": {
                "background": "#022b1c" if is_live else "#081b33",
                "border": "#00ff88" if is_live else "#00c8ff",
                "highlight": {"background": "#04402a", "border": "#39ff14"}
            },
            "shape": "ellipse",
            "font": {"color": "#00ff88" if is_live else "#00c8ff", "size": 11, "face": "monospace"},
            "borderWidth": 1.5
        })
        edges.append({
            "from": "target", "to": sub_id,
            "color": {"color": "#00c8ff", "highlight": "#00ff88"}
        })

        if s.get("takeover_risk"):
            to_id = f"takeover_{idx}"
            nodes.append({
                "id": to_id,
                "label": f"🚨 Takeover:\n{s.get('takeover_risk')}",
                "color": {
                    "background": "#380611",
                    "border": "#ff0055",
                    "highlight": {"background": "#520919", "border": "#ff3377"}
                },
                "shape": "box",
                "font": {"color": "#ff0055", "size": 11, "bold": True, "face": "monospace"},
                "borderWidth": 2
            })
            edges.append({
                "from": sub_id, "to": to_id, "label": "dangling CNAME",
                "color": {"color": "#ff0055"}
            })

    # 4. Tech Stack Nodes
    tech_stack = data.get("tech_stack", [])
    for idx, t in enumerate(tech_stack[:8]):
        t_id = f"tech_{idx}"
        nodes.append({
            "id": t_id,
            "label": f"{t.get('category')}\n{t.get('name')}",
            "color": {
                "background": "#140b2b",
                "border": "#bd93f9",
                "highlight": {"background": "#221245", "border": "#d6b4fc"}
            },
            "shape": "ellipse",
            "font": {"color": "#bd93f9", "size": 11, "face": "monospace"},
            "borderWidth": 1.5
        })
        edges.append({
            "from": "target", "to": t_id, "label": "running",
            "color": {"color": "#bd93f9"}
        })

    # 5. Social & Developer Profiles
    social_profiles = data.get("found_profiles", [])
    if not social_profiles and "username_scan" in data:
        social_profiles = data["username_scan"].get("found_profiles", [])
    for idx, p in enumerate(social_profiles[:10]):
        sp_id = f"soc_{idx}"
        nodes.append({
            "id": sp_id,
            "label": f"Profile:\n{p.get('platform')}",
            "color": {
                "background": "#022b1c",
                "border": "#00ff88",
                "highlight": {"background": "#04402a", "border": "#39ff14"}
            },
            "shape": "box",
            "font": {"color": "#00ff88", "size": 11, "face": "monospace"},
            "borderWidth": 1.5
        })
        edges.append({
            "from": "target", "to": sp_id, "label": "account",
            "color": {"color": "#00ff88"}
        })

    # 6. Phone Intelligence Nodes
    if data.get("e164"):
        nodes.append({
            "id": "phone_country",
            "label": f"Country: {data.get('country_name')}\nDial: +{data.get('country_code')}",
            "color": {
                "background": "#332200",
                "border": "#ffb800",
                "highlight": {"background": "#4d3300", "border": "#ffd166"}
            },
            "shape": "box",
            "font": {"color": "#ffb800", "size": 12, "face": "monospace"},
            "borderWidth": 1.5
        })
        edges.append({"from": "target", "to": "phone_country", "color": {"color": "#ffb800"}})
        nodes.append({
            "id": "phone_type",
            "label": f"Line Type:\n{data.get('line_type')}",
            "color": {
                "background": "#140b2b",
                "border": "#bd93f9",
                "highlight": {"background": "#221245", "border": "#d6b4fc"}
            },
            "shape": "ellipse",
            "font": {"color": "#bd93f9", "size": 11, "face": "monospace"},
            "borderWidth": 1.5
        })
        edges.append({"from": "target", "to": "phone_type", "color": {"color": "#bd93f9"}})

    # 7. Infostealer Alert Node
    infostealer = data.get("infostealer", {}) or data.get("infostealer_exposure", {})
    if infostealer.get("found"):
        stealers = infostealer.get("stealers", [])
        nodes.append({
            "id": "malware_alert",
            "label": f"🚨 INFOSTEALER\n{len(stealers)} Compromises",
            "color": {
                "background": "#4a0412",
                "border": "#ff0055",
                "highlight": {"background": "#6b061a", "border": "#ff3377"}
            },
            "shape": "diamond",
            "font": {"color": "#ff0055", "size": 13, "bold": True, "face": "monospace"},
            "borderWidth": 2,
            "shadow": {"enabled": True, "color": "rgba(255, 0, 85, 0.6)", "size": 14}
        })
        edges.append({
            "from": "target", "to": "malware_alert", "label": "compromised by",
            "color": {"color": "#ff0055"}
        })

    # 8. Cloud Storage Bucket Nodes
    cloud_buckets = data.get("cloud_buckets", []) or data.get("buckets", [])
    for idx, b in enumerate(cloud_buckets[:8]):
        b_id = f"cloud_{idx}"
        b_open = b.get("status") == "OPEN"
        nodes.append({
            "id": b_id,
            "label": f"Cloud: {b.get('provider')}\n{b.get('bucket')}\n{'[PUBLIC LEAK]' if b_open else '[PROTECTED]'}",
            "color": {
                "background": "#4a0412" if b_open else "#332200",
                "border": "#ff0055" if b_open else "#ffb800",
                "highlight": {"background": "#6b061a" if b_open else "#4d3300", "border": "#ff3377" if b_open else "#ffd166"}
            },
            "shape": "box",
            "font": {"color": "#ff0055" if b_open else "#ffb800", "size": 11, "bold": b_open, "face": "monospace"},
            "borderWidth": 2 if b_open else 1.5,
            "shadow": {"enabled": b_open, "color": "rgba(255, 0, 85, 0.6)", "size": 12}
        })
        edges.append({
            "from": "target", "to": b_id, "label": "cloud storage",
            "color": {"color": "#ff0055" if b_open else "#ffb800"}
        })

    # 9. Threat Intelligence Nodes
    threat_data = data.get("threat_intel", {}) or data.get("assessment", {})
    t_score = threat_data.get("threat_score") or threat_data.get("score") or data.get("threat_score", 0)
    if t_score > 0:
        nodes.append({
            "id": "threat_reputation",
            "label": f"⚠️ Threat Score: {t_score}/100\n{threat_data.get('threat_label', 'Abuse.ch Flagged')}",
            "color": {
                "background": "#4a0412" if t_score >= 50 else "#332200",
                "border": "#ff0055" if t_score >= 50 else "#ffb800",
                "highlight": {"background": "#6b061a", "border": "#ff3377"}
            },
            "shape": "diamond",
            "font": {"color": "#ffffff", "size": 12, "bold": True, "face": "monospace"},
            "borderWidth": 2,
            "shadow": {"enabled": True, "color": "rgba(255, 0, 85, 0.5)", "size": 12}
        })
        edges.append({
            "from": "target", "to": "threat_reputation", "label": "threat reputation",
            "color": {"color": "#ff0055" if t_score >= 50 else "#ffb800"}
        })

    return nodes, edges

def generate_dashboard_html(data: dict, target_name: str) -> str:
    """Generates the full HTML markup for the Hollywood movie-hacker terminal reconnaissance report."""
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    target_hash = hashlib.sha256(target_name.encode("utf-8")).hexdigest()[:24]

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

    # IP Geolocation & DNS records
    ip_geos = data.get("ip_geolocation", [])
    dns_records = data.get("dns", {})
    email_sec = data.get("email_security", {})
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

    # Threat level label & class
    if threat_score is not None and threat_score >= 50:
        threat_defcon = "DEFCON-1 : CRITICAL THREAT"
        threat_badge_class = "cyber-badge-red"
    elif threat_score is not None and threat_score > 0:
        threat_defcon = "DEFCON-3 : ELEVATED HAZARD"
        threat_badge_class = "cyber-badge-yellow"
    else:
        threat_defcon = "DEFCON-5 : NOMINAL STATUS"
        threat_badge_class = "cyber-badge-green"

    # Graph elements
    nodes, edges = build_graph_elements(data, target_name)
    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>[TOP SECRET] OSINTALL Tactical Dossier - {html.escape(target_name)}</title>
    <!-- Google Fonts for authentic Hollywood Hacker Terminal Look -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet">
    <!-- Vis.js Network for Maltego-style Interactive Graph -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {{
            --cyber-bg: #03070d;
            --cyber-card: #080f1a;
            --cyber-subtle: #0d1829;
            --cyber-border: #13304a;
            --cyber-border-glow: #00f3ff;
            --neon-green: #00ff88;
            --neon-cyan: #00f3ff;
            --neon-amber: #ffb800;
            --neon-red: #ff0055;
            --neon-purple: #bd93f9;
            --neon-text: #e6f1ff;
            --neon-dim: #799bbb;
            --font-mono: 'Share Tech Mono', Consolas, Monaco, 'Courier New', monospace;
            --font-display: 'Orbitron', 'Share Tech Mono', sans-serif;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: var(--font-mono);
            background-color: var(--cyber-bg);
            background-image: 
                radial-gradient(circle at 50% 0%, rgba(0, 243, 255, 0.08) 0%, rgba(3, 7, 13, 0.98) 75%),
                linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
            background-size: 100% 100%, 32px 32px, 32px 32px;
            color: var(--neon-text);
            margin: 0;
            padding: 24px 20px 60px;
            line-height: 1.5;
            overflow-x: hidden;
            position: relative;
            min-height: 100vh;
        }}

        /* Subtle CRT Monitor Vignette & Scanlines */
        body::before {{
            content: " ";
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            box-shadow: inset 0 0 120px rgba(0, 0, 0, 0.95);
            pointer-events: none;
            z-index: 9998;
        }}
        .crt-scanlines {{
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.35) 50%);
            background-size: 100% 4px;
            pointer-events: none;
            z-index: 9997;
            opacity: 0.75;
            transition: opacity 0.3s ease;
        }}
        .crt-scanlines.disabled {{
            opacity: 0;
        }}

        /* Matrix Digital Rain Canvas */
        #matrix-canvas {{
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            pointer-events: none;
            z-index: 1;
            opacity: 0.14;
            transition: opacity 0.4s ease;
        }}
        #matrix-canvas.disabled {{
            opacity: 0;
        }}

        /* Main Container */
        .container {{
            max-width: 1280px;
            margin: 0 auto;
            position: relative;
            z-index: 10;
        }}

        /* Scrollbar Styling */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: #03070d;
            border-left: 1px solid var(--cyber-border);
        }}
        ::-webkit-scrollbar-thumb {{
            background: #13304a;
            border: 1px solid var(--neon-cyan);
            border-radius: 2px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--neon-cyan);
            box-shadow: 0 0 10px var(--neon-cyan);
        }}

        /* Top Secret Clearance Header */
        .top-clearance-bar {{
            background: rgba(8, 15, 26, 0.92);
            border: 1px solid var(--cyber-border);
            border-bottom: 2px solid var(--neon-red);
            padding: 8px 16px;
            font-size: 0.75rem;
            color: var(--neon-dim);
            letter-spacing: 1.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 18px;
            backdrop-filter: blur(8px);
        }}
        .top-clearance-bar .status-tag {{
            color: var(--neon-green);
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--neon-green);
            box-shadow: 0 0 8px var(--neon-green);
            animation: pulse-dot 1.4s infinite ease-in-out;
        }}
        @keyframes pulse-dot {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.3; transform: scale(0.8); }}
        }}

        /* Tactical Header HUD */
        header {{
            background: rgba(8, 15, 26, 0.88);
            border: 1px solid var(--cyber-border);
            border-left: 4px solid var(--neon-cyan);
            box-shadow: 0 0 25px rgba(0, 243, 255, 0.08);
            padding: 24px 28px;
            margin-bottom: 22px;
            backdrop-filter: blur(12px);
            position: relative;
        }}
        .classified-stamp {{
            position: absolute;
            top: 20px;
            right: 28px;
            border: 2px solid var(--neon-red);
            color: var(--neon-red);
            padding: 4px 14px;
            font-family: var(--font-display);
            font-size: 0.75rem;
            font-weight: 900;
            letter-spacing: 2px;
            transform: rotate(-3deg);
            box-shadow: 0 0 12px rgba(255, 0, 85, 0.3);
            text-transform: uppercase;
            pointer-events: none;
        }}
        .header-title h1 {{
            margin: 0;
            font-family: var(--font-display);
            font-size: 1.85rem;
            letter-spacing: 1px;
            color: #ffffff;
            text-shadow: 0 0 10px rgba(0, 243, 255, 0.5), 0 0 20px rgba(0, 243, 255, 0.2);
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .cursor-blink {{
            display: inline-block;
            width: 12px;
            height: 1.4rem;
            background: var(--neon-cyan);
            box-shadow: 0 0 8px var(--neon-cyan);
            animation: cursor-blink 0.8s infinite;
            vertical-align: middle;
        }}
        @keyframes cursor-blink {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0; }}
        }}
        .telemetry-strip {{
            display: flex;
            flex-wrap: wrap;
            gap: 18px;
            margin-top: 14px;
            font-size: 0.82rem;
            color: var(--neon-dim);
            border-top: 1px dashed var(--cyber-border);
            padding-top: 12px;
        }}
        .telemetry-item strong {{
            color: var(--neon-cyan);
        }}
        .telemetry-item code {{
            background: rgba(0, 243, 255, 0.1);
            color: var(--neon-green);
            padding: 2px 6px;
            border-radius: 2px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }}

        /* HUD Quick Action Deck */
        .hud-actions {{
            display: flex;
            gap: 10px;
            margin-top: 16px;
            flex-wrap: wrap;
        }}
        .hud-btn {{
            background: rgba(13, 24, 41, 0.9);
            border: 1px solid var(--cyber-border);
            color: var(--neon-cyan);
            font-family: var(--font-mono);
            font-size: 0.78rem;
            padding: 6px 14px;
            cursor: pointer;
            letter-spacing: 1px;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border-radius: 2px;
        }}
        .hud-btn:hover {{
            background: rgba(0, 243, 255, 0.15);
            border-color: var(--neon-cyan);
            color: #ffffff;
            box-shadow: 0 0 10px rgba(0, 243, 255, 0.4);
            transform: translateY(-1px);
        }}
        .hud-btn.active {{
            background: rgba(0, 255, 136, 0.15);
            border-color: var(--neon-green);
            color: var(--neon-green);
            box-shadow: 0 0 8px rgba(0, 255, 136, 0.3);
        }}

        /* Interactive Terminal Command / Live Filter Bar */
        .terminal-bar {{
            background: #050a12;
            border: 1px solid var(--cyber-border);
            border-left: 4px solid var(--neon-green);
            padding: 10px 18px;
            margin-bottom: 22px;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.06);
        }}
        .terminal-prompt {{
            font-size: 0.85rem;
            color: var(--neon-green);
            font-weight: 700;
            white-space: nowrap;
        }}
        .terminal-input {{
            background: transparent;
            border: none;
            outline: none;
            color: #ffffff;
            font-family: var(--font-mono);
            font-size: 0.92rem;
            width: 100%;
            letter-spacing: 0.5px;
        }}
        .terminal-input::placeholder {{
            color: #436382;
            font-style: italic;
        }}
        .terminal-counter {{
            font-size: 0.75rem;
            color: var(--neon-cyan);
            white-space: nowrap;
            background: rgba(0, 243, 255, 0.1);
            padding: 3px 8px;
            border-radius: 2px;
            border: 1px solid rgba(0, 243, 255, 0.3);
        }}

        /* Cyber Badges */
        .cyber-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 2px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            border: 1px solid transparent;
        }}
        .cyber-badge-cyan {{ background: rgba(0, 243, 255, 0.12); color: var(--neon-cyan); border-color: var(--neon-cyan); }}
        .cyber-badge-green {{ background: rgba(0, 255, 136, 0.12); color: var(--neon-green); border-color: var(--neon-green); }}
        .cyber-badge-red {{ background: rgba(255, 0, 85, 0.15); color: var(--neon-red); border-color: var(--neon-red); box-shadow: 0 0 8px rgba(255,0,85,0.3); }}
        .cyber-badge-yellow {{ background: rgba(255, 184, 0, 0.15); color: var(--neon-amber); border-color: var(--neon-amber); }}
        .cyber-badge-purple {{ background: rgba(189, 147, 249, 0.15); color: var(--neon-purple); border-color: var(--neon-purple); }}

        /* Stat Metrics Grid (Tactical Radar Gauges) */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 18px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: rgba(8, 15, 26, 0.85);
            border: 1px solid var(--cyber-border);
            border-radius: 2px;
            padding: 18px 22px;
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: all 0.25s ease;
            backdrop-filter: blur(8px);
        }}
        .stat-card::after {{
            content: " ";
            position: absolute;
            top: 0; right: 0;
            width: 14px; height: 14px;
            border-top: 2px solid var(--neon-cyan);
            border-right: 2px solid var(--neon-cyan);
        }}
        .stat-card::before {{
            content: " ";
            position: absolute;
            bottom: 0; left: 0;
            width: 14px; height: 14px;
            border-bottom: 2px solid var(--neon-cyan);
            border-left: 2px solid var(--neon-cyan);
        }}
        .stat-card:hover {{
            border-color: var(--neon-cyan);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 243, 255, 0.15);
        }}
        .stat-card .label {{
            font-size: 0.76rem;
            color: var(--neon-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .stat-card .value {{
            font-family: var(--font-display);
            font-size: 2.3rem;
            font-weight: 900;
            color: #ffffff;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.6);
            margin: 10px 0 6px;
        }}
        .stat-card .sub {{
            font-size: 0.8rem;
            color: var(--neon-cyan);
        }}

        /* Section Card Container */
        .section-card {{
            background: rgba(8, 15, 26, 0.85);
            border: 1px solid var(--cyber-border);
            padding: 24px 28px;
            margin-bottom: 24px;
            position: relative;
            backdrop-filter: blur(10px);
            transition: border-color 0.2s ease;
        }}
        .section-card:hover {{
            border-color: rgba(0, 243, 255, 0.4);
        }}
        .section-card h2 {{
            margin-top: 0;
            margin-bottom: 16px;
            font-family: var(--font-display);
            font-size: 1.15rem;
            letter-spacing: 1px;
            color: #ffffff;
            border-bottom: 1px solid var(--cyber-border);
            padding-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }}
        .section-card h2 span.title-text {{
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--neon-cyan);
            text-shadow: 0 0 8px rgba(0, 243, 255, 0.4);
        }}
        .section-tag {{
            font-size: 0.72rem;
            color: var(--neon-dim);
            font-family: var(--font-mono);
            letter-spacing: 1.5px;
        }}

        /* Vis.js Network Graph Card */
        #network-graph {{
            width: 100%;
            height: 540px;
            background: #040810;
            border: 1px solid var(--cyber-border);
            position: relative;
            margin-top: 14px;
        }}
        .graph-toolbar {{
            display: flex;
            gap: 8px;
            margin-top: 10px;
            justify-content: flex-end;
        }}
        .graph-toolbar button {{
            background: #0d1829;
            border: 1px solid var(--cyber-border);
            color: var(--neon-cyan);
            font-family: var(--font-mono);
            font-size: 0.75rem;
            padding: 4px 10px;
            cursor: pointer;
            border-radius: 2px;
        }}
        .graph-toolbar button:hover {{
            border-color: var(--neon-cyan);
            background: rgba(0, 243, 255, 0.15);
        }}

        /* Decrypted Telemetry Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.88rem;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid rgba(19, 48, 74, 0.7);
        }}
        th {{
            background-color: rgba(13, 24, 41, 0.95);
            color: var(--neon-cyan);
            font-family: var(--font-display);
            font-size: 0.76rem;
            letter-spacing: 1px;
            text-transform: uppercase;
            border-top: 1px solid var(--cyber-border);
        }}
        tr:hover td {{
            background-color: rgba(0, 243, 255, 0.04);
            color: #ffffff;
        }}
        .offset-col {{
            color: #4b6b8b;
            font-family: var(--font-mono);
            font-size: 0.78rem;
            width: 70px;
        }}
        code {{
            font-family: var(--font-mono);
            color: var(--neon-green);
            background: rgba(0, 255, 136, 0.06);
            padding: 2px 6px;
            border-radius: 2px;
        }}

        /* Threat & Breach Alert Banners */
        .alert-box {{
            padding: 16px 20px;
            margin-bottom: 22px;
            border-left: 4px solid;
            background: rgba(8, 15, 26, 0.95);
            display: flex;
            align-items: flex-start;
            gap: 12px;
            position: relative;
            backdrop-filter: blur(8px);
        }}
        .alert-danger {{
            border-color: var(--neon-red);
            background: rgba(255, 0, 85, 0.07);
            color: #ff99b8;
            box-shadow: 0 0 20px rgba(255, 0, 85, 0.15);
            animation: pulse-border 2s infinite ease-in-out;
        }}
        @keyframes pulse-border {{
            0%, 100% {{ border-left-color: var(--neon-red); }}
            50% {{ border-left-color: #ff80a6; }}
        }}
        .alert-warning {{
            border-color: var(--neon-amber);
            background: rgba(255, 184, 0, 0.08);
            color: #ffe082;
            box-shadow: 0 0 15px rgba(255, 184, 0, 0.12);
        }}

        /* Profiles & Tech Pills */
        .grid-pills {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 14px;
            margin-top: 15px;
        }}
        .pill-card {{
            background: rgba(13, 24, 41, 0.7);
            border: 1px solid var(--cyber-border);
            padding: 12px 16px;
            text-decoration: none;
            color: var(--neon-text);
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s ease;
            position: relative;
        }}
        .pill-card:hover {{
            border-color: var(--neon-cyan);
            background: rgba(0, 243, 255, 0.08);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 243, 255, 0.15);
        }}

        /* Raw JSON Inspection Accordion */
        details {{
            margin-top: 24px;
            border: 1px solid var(--cyber-border);
            background: rgba(8, 15, 26, 0.8);
        }}
        summary {{
            padding: 14px 20px;
            cursor: pointer;
            font-family: var(--font-display);
            font-size: 0.9rem;
            color: var(--neon-cyan);
            outline: none;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        summary:hover {{
            background: rgba(0, 243, 255, 0.05);
        }}
        pre {{
            margin: 0;
            padding: 20px;
            background: #02050a;
            overflow-x: auto;
            color: #7ee787;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            border-top: 1px solid var(--cyber-border);
            max-height: 480px;
        }}
        a {{ color: var(--neon-cyan); text-decoration: none; }}
        a:hover {{ color: var(--neon-green); text-shadow: 0 0 6px var(--neon-green); }}

        /* Print Media Styling */
        @media print {{
            body {{
                background: #ffffff !important;
                color: #000000 !important;
                padding: 10px !important;
            }}
            #matrix-canvas, .crt-scanlines, .hud-actions, .terminal-bar, .graph-toolbar {{
                display: none !important;
            }}
            .section-card, header, .stat-card {{
                background: #ffffff !important;
                border: 1px solid #cccccc !important;
                color: #000000 !important;
                box-shadow: none !important;
            }}
            .header-title h1, .stat-card .value {{
                color: #000000 !important;
                text-shadow: none !important;
            }}
        }}
    </style>
</head>
<body>
    <!-- Background Matrix Digital Rain Stream -->
    <canvas id="matrix-canvas"></canvas>

    <!-- CRT Scanline Shader Overlay -->
    <div id="crt-scanlines" class="crt-scanlines"></div>

    <div class="container">
        <!-- Top Clearance Agency Banner -->
        <div class="top-clearance-bar">
            <div>
                <span style="color: var(--neon-red); font-weight: bold;">[ CLASSIFIED ]</span>
                TOP SECRET // SPECIAL ACCESS PROGRAM // EYES ONLY
            </div>
            <div class="status-tag">
                <span class="status-dot"></span>
                <span>SYSTEM: {threat_defcon}</span>
                <span style="color: var(--neon-dim);">| NODE: KALI-CYBER-0x7F</span>
            </div>
        </div>

        <!-- Tactical Recon Header -->
        <header>
            <div class="classified-stamp">TOP SECRET</div>
            <div class="header-title">
                <h1>
                    <span>⚡ OSINTALL // RECONNAISSANCE DOSSIER</span>
                    <span class="cursor-blink"></span>
                </h1>
            </div>
            <div class="telemetry-strip">
                <div class="telemetry-item">TARGET: <strong class="decrypt-text" data-original="{html.escape(target_name)}">{html.escape(target_name)}</strong></div>
                <div class="telemetry-item">SHA256: <code>{target_hash}...</code></div>
                <div class="telemetry-item">ACQUISITION: <span>{now_str}</span></div>
                <div class="telemetry-item">FRAMEWORK: <span style="color:var(--neon-green);">OSINTALL v2.2 [CYBER-DECK]</span></div>
                <div class="telemetry-item">THREAT RATING: <span class="cyber-badge {threat_badge_class}">{threat_defcon.split(':')[0]}</span></div>
            </div>

            <!-- HUD Quick Controls -->
            <div class="hud-actions">
                <button class="hud-btn active" id="btn-matrix" onclick="toggleMatrixRain()">
                    <span>🟢</span> <span>MATRIX RAIN: <strong id="lbl-matrix">ON</strong></span>
                </button>
                <button class="hud-btn active" id="btn-scanlines" onclick="toggleScanlines()">
                    <span>📺</span> <span>CRT SCANLINES: <strong id="lbl-scanlines">ON</strong></span>
                </button>
                <button class="hud-btn active" id="btn-sound" onclick="toggleCyberSound()">
                    <span>🔊</span> <span>CYBER AUDIO: <strong id="lbl-sound">ON</strong></span>
                </button>
                <button class="hud-btn" onclick="window.print()">
                    <span>🖨️</span> <span>EXPORT / PRINT PDF</span>
                </button>
                <button class="hud-btn" onclick="copyIntelJson()">
                    <span>📋</span> <span>COPY RAW INTEL</span>
                </button>
            </div>
        </header>

        <!-- Interactive Hollywood Hacker Terminal Command Prompt / Filter -->
        <div class="terminal-bar">
            <span class="terminal-prompt">root@osintall:~/recon-dossier#</span>
            <input type="text" id="terminal-input" class="terminal-input" placeholder="Live filter intelligence (e.g. cve, dns, open, port, admin) or /matrix, /crt, /audio, /print, /clear..." onkeyup="handleTerminalInput(event)" autocomplete="off" spellcheck="false">
            <span id="terminal-matches" class="terminal-counter">READY</span>
        </div>

        <!-- Stat Metrics Radar HUD -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="label">
                    <span>Subdomains Discovered</span>
                    <span>📡</span>
                </span>
                <span class="value">{len(subdomains)}</span>
                <span class="sub">{len(live_subdomains)} confirmed active host nodes</span>
            </div>
            <div class="stat-card">
                <span class="label">
                    <span>Identified Footprints / Telecom</span>
                    <span>👤</span>
                </span>
                <span class="value">{len(social_profiles) if not is_phone_recon else 1}</span>
                <span class="sub">{"Verified identity footprints" if not is_phone_recon else data.get("line_type", "Telecom Carrier")}</span>
            </div>
            <div class="stat-card">
                <span class="label">
                    <span>Detected Tech Stacks</span>
                    <span>🛠️</span>
                </span>
                <span class="value">{len(tech_stack)}</span>
                <span class="sub">Servers, Frameworks & CMS</span>
            </div>
            <div class="stat-card">
                <span class="label">
                    <span>Takeover & CVE Hazards</span>
                    <span>⚠️</span>
                </span>
                <span class="value" style="color: {'var(--neon-red)' if takeover_warnings else 'var(--neon-green)'}">{len(takeover_warnings)}</span>
                <span class="sub">Critical infrastructure exposure</span>
            </div>
        </div>
"""

    # Infostealer Compromise Alert (Hudson Rock)
    if infostealer.get("found"):
        stealers = infostealer.get("stealers", [])
        html_code += f"""
        <div class="alert-box alert-danger">
            <div style="font-size: 1.5rem; line-height: 1;">🚨</div>
            <div>
                <strong style="color: var(--neon-red); font-family: var(--font-display);">CYBERCRIME TELEMETRY ALERT:</strong>
                <div>Infostealer malware compromised credentials were identified for this target ({len(stealers)} compromised devices recorded in Hudson Rock cybercrime intelligence).</div>
            </div>
        </div>
        """

    # Critical Public Cloud Leak Alert
    if open_buckets:
        html_code += f"""
        <div class="alert-box alert-danger">
            <div style="font-size: 1.5rem; line-height: 1;">🚨</div>
            <div>
                <strong style="color: var(--neon-red); font-family: var(--font-display);">CRITICAL CLOUD STORAGE LEAK:</strong>
                <div>{len(open_buckets)} public cloud storage bucket(s) identified with unauthenticated read/listing enabled. Unrestricted public data leak active.</div>
            </div>
        </div>
        """

    # Threat Reputation Alert
    if threat_score is not None and threat_score > 0:
        level_class = "alert-danger" if threat_score >= 50 else "alert-warning"
        score_color = "var(--neon-red)" if threat_score >= 50 else "var(--neon-amber)"
        html_code += f"""
        <div class="alert-box {level_class}">
            <div style="font-size: 1.5rem; line-height: 1;">⚠️</div>
            <div>
                <strong style="color: {score_color}; font-family: var(--font-display);">THREAT INTELLIGENCE REPUTATION:</strong>
                <div>Target scored <strong>{threat_score}/100</strong> across cybercrime threat databases (Abuse.ch URLhaus / ThreatFox Indicators of Compromise).</div>
            </div>
        </div>
        """

    # Subdomain Takeover Warning
    if takeover_warnings:
        html_code += """
        <div class="alert-box alert-danger">
            <div style="font-size: 1.5rem; line-height: 1;">⚠️</div>
            <div>
                <strong style="color: var(--neon-red); font-family: var(--font-display);">SUBDOMAIN TAKEOVER HAZARDS DETECTED:</strong>
                <ul style="margin: 6px 0 0 16px; padding: 0;">
        """
        for tw in takeover_warnings:
            html_code += f"<li><code>{html.escape(tw['subdomain'])}</code> &rarr; <span style='color:var(--neon-red);'>{html.escape(str(tw.get('takeover_risk')))}</span></li>"
        html_code += "</ul></div></div>"

    # VIS.JS INTERACTIVE NODE RELATIONSHIP GRAPH (Movie Hacker Radar Edition)
    html_code += f"""
        <div class="section-card" data-section="graph">
            <h2>
                <span class="title-text"><span>🕸️</span> INTERACTIVE RECONNAISSANCE RELATIONSHIP RADAR</span>
                <span class="section-tag">[ 0x01 // LINK_ANALYSIS ]</span>
            </h2>
            <div style="font-size: 0.82rem; color: var(--neon-dim); margin-bottom: 6px;">
                Tactical link graph: drag, pan, zoom, and select nodes to inspect infrastructure connections, subdomains, open ports, and threat nodes.
            </div>
            <div id="network-graph"></div>
            <div class="graph-toolbar">
                <button onclick="zoomGraph(0.7)">[ 🔍- ZOOM OUT ]</button>
                <button onclick="zoomGraph(1.4)">[ 🔍+ ZOOM IN ]</button>
                <button onclick="resetGraph()">[ 🎯 RE-CENTER ]</button>
                <button onclick="toggleGraphFullscreen()">[ ⛶ FULLSCREEN ]</button>
            </div>
        </div>
    """

    # PHONE NUMBER RECONNAISSANCE CARD (If TELINT was run)
    if is_phone_recon:
        html_code += f"""
        <div class="section-card filter-target" data-section="telint">
            <h2>
                <span class="title-text"><span>📱</span> TELEPHONE INTELLIGENCE (TELINT)</span>
                <span class="section-tag">[ 0x02 // TELECOM_RECON ]</span>
            </h2>
            <table>
                <thead>
                    <tr><th class="offset-col">OFFSET</th><th>PROPERTY</th><th>DECRYPTED TELECOM TELEMETRY</th></tr>
                </thead>
                <tbody>
                    <tr><td class="offset-col">0x000</td><td><strong>E.164 Standard</strong></td><td><code>{html.escape(data.get("e164", ""))}</code></td></tr>
                    <tr><td class="offset-col">0x008</td><td><strong>International Format</strong></td><td>{html.escape(data.get("international_format", ""))}</td></tr>
                    <tr><td class="offset-col">0x010</td><td><strong>Country / Dial Code</strong></td><td>{html.escape(data.get("country_name", ""))} (+{html.escape(data.get("country_code", ""))})</td></tr>
                    <tr><td class="offset-col">0x018</td><td><strong>Estimated Line Type</strong></td><td><span class="cyber-badge cyber-badge-green">{html.escape(data.get("line_type", "Cellular / Fixed"))}</span></td></tr>
                </tbody>
            </table>
            <h3 style="color: var(--neon-cyan); font-size: 0.95rem; margin-top: 20px; font-family: var(--font-display);">Direct Messaging Footprints & Telemetry Lookups</h3>
            <div class="grid-pills">
                <a href="{html.escape(data.get('messaging_links', {}).get('whatsapp', '#'))}" target="_blank" class="pill-card">
                    <span><strong>WhatsApp Endpoint</strong></span>
                    <span style="color: var(--neon-green);">Direct Chat &rarr;</span>
                </a>
                <a href="{html.escape(data.get('messaging_links', {}).get('telegram', '#'))}" target="_blank" class="pill-card">
                    <span><strong>Telegram Endpoint</strong></span>
                    <span style="color: var(--neon-cyan);">Direct Open &rarr;</span>
                </a>
                <a href="{html.escape(data.get('reputation_links', {}).get('truecaller', '#'))}" target="_blank" class="pill-card">
                    <span><strong>Truecaller Telecom</strong></span>
                    <span style="color: var(--neon-amber);">Search Record &rarr;</span>
                </a>
            </div>
        </div>
        """

    # CLOUD STORAGE BUCKET AUDIT CARD (CLOUDINT)
    if cloud_buckets:
        html_code += """
        <div class="section-card filter-target" data-section="cloud">
            <h2>
                <span class="title-text"><span>☁️</span> MULTI-CLOUD STORAGE BUCKET AUDITOR (CLOUDINT)</span>
                <span class="section-tag">[ 0x03 // CLOUD_STORAGE ]</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th class="offset-col">OFFSET</th>
                        <th>CLOUD PROVIDER</th>
                        <th>BUCKET / CONTAINER NAME</th>
                        <th>EXPOSURE STATUS</th>
                        <th>ENDPOINT URL / DETAILS</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idx, b in enumerate(cloud_buckets):
            b_open = b.get("status") == "OPEN"
            status_badge = "<span class='cyber-badge cyber-badge-red'>🚨 PUBLIC LEAK (200)</span>" if b_open else "<span class='cyber-badge cyber-badge-yellow'>🔒 PROTECTED (403)</span>"
            url_link = f"<a href='{html.escape(b.get('url', ''))}' target='_blank'><code>{html.escape(b.get('url', ''))}</code></a>" if b.get('url') else html.escape(b.get("details", ""))
            html_code += f"""
                <tr>
                    <td class="offset-col">0x{idx*8:03X}</td>
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
        score_color = "var(--neon-red)" if score_val >= 50 else ("var(--neon-amber)" if score_val > 0 else "var(--neon-green)")
        html_code += f"""
        <div class="section-card filter-target" data-section="threat">
            <h2>
                <span class="title-text"><span>🛡️</span> THREAT INTELLIGENCE & MALWARE TELEMETRY</span>
                <span class="section-tag">[ 0x04 // THREAT_INTEL ]</span>
            </h2>
            <div style="margin-bottom: 16px; padding: 14px 18px; background: rgba(13, 24, 41, 0.9); border-left: 4px solid {score_color}; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <div style="font-family: var(--font-display); font-size: 1.1rem; font-weight: 700; color: {score_color};">
                        THREAT SEVERITY SCORE: {score_val} / 100
                    </div>
                    <div style="font-size: 0.8rem; color: var(--neon-dim); margin-top: 4px;">
                        Aggregated across Abuse.ch URLhaus malware repository and ThreatFox Indicators of Compromise.
                    </div>
                </div>
                <div>
                    <span class="cyber-badge {threat_badge_class}">{threat_defcon}</span>
                </div>
            </div>
        """
        if urlhaus.get("urls"):
            html_code += """
            <h3 style="font-size: 0.95rem; color: var(--neon-red); margin-top: 18px; font-family: var(--font-display);">Active & Historical Malware Distribution URLs (URLhaus)</h3>
            <table>
                <thead><tr><th class="offset-col">OFFSET</th><th>MALICIOUS URL</th><th>STATUS</th><th>THREAT TYPE</th></tr></thead>
                <tbody>
            """
            for idx, u in enumerate(urlhaus.get("urls", [])[:8]):
                u_stat = "<span class='cyber-badge cyber-badge-red'>ONLINE</span>" if u.get("url_status") == "online" else "<span class='cyber-badge cyber-badge-green'>OFFLINE</span>"
                html_code += f"<tr><td class='offset-col'>0x{idx*8:03X}</td><td><code>{html.escape(u.get('url', ''))}</code></td><td>{u_stat}</td><td>{html.escape(u.get('threat', 'Malware'))}</td></tr>"
            html_code += "</tbody></table>"

        if threatfox.get("iocs"):
            html_code += """
            <h3 style="font-size: 0.95rem; color: var(--neon-amber); margin-top: 20px; font-family: var(--font-display);">ThreatFox Indicators of Compromise (IoCs) & Signatures</h3>
            <table>
                <thead><tr><th class="offset-col">OFFSET</th><th>INDICATOR (IOC)</th><th>THREAT TYPE</th><th>MALWARE FAMILY</th><th>CONFIDENCE</th></tr></thead>
                <tbody>
            """
            for idx, ioc in enumerate(threatfox.get("iocs", [])[:8]):
                html_code += f"<tr><td class='offset-col'>0x{idx*8:03X}</td><td><code>{html.escape(ioc.get('ioc', ''))}</code></td><td>{html.escape(ioc.get('threat_type_desc', ioc.get('threat_type', '')))}</td><td><span class='cyber-badge cyber-badge-red'>{html.escape(ioc.get('malware_printable', 'Unknown'))}</span></td><td>{ioc.get('confidence_level', 0)}%</td></tr>"
            html_code += "</tbody></table>"
        html_code += "</div>"

    # SHODAN INTERNETDB TELEMETRY CARD (Zero-Key Port & CVE Discovery)
    if internetdb:
        html_code += """
        <div class="section-card filter-target" data-section="ports">
            <h2>
                <span class="title-text"><span>⚡</span> SHODAN INTERNETDB OPEN PORTS & CVE TELEMETRY</span>
                <span class="section-tag">[ 0x05 // SHODAN_INTDB ]</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th class="offset-col">OFFSET</th>
                        <th>TARGET IP</th>
                        <th>OPEN PORTS</th>
                        <th>DETECTED CPES</th>
                        <th>CVE VULNERABILITIES</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idx, idb in enumerate(internetdb):
            ports_str = ", ".join(map(str, sorted(idb.get("ports", [])))) or "None detected"
            cpes_list = idb.get("cpes", [])
            cpes_str = "<br>".join(map(html.escape, cpes_list[:4])) or "-"
            vulns_list = idb.get("vulns", [])
            vulns_str = ", ".join(vulns_list[:6]) or "None detected"
            vuln_badge = f"<span class='cyber-badge cyber-badge-red'>{len(vulns_list)} CVEs</span> {html.escape(vulns_str)}" if vulns_list else "<span class='cyber-badge cyber-badge-green'>NO KNOWN CVES</span>"
            html_code += f"""
                <tr>
                    <td class="offset-col">0x{idx*8:03X}</td>
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
        <div class="section-card filter-target" data-section="tech">
            <h2>
                <span class="title-text"><span>🛠️</span> DETECTED WEB TECHNOLOGIES & INFRASTRUCTURE</span>
                <span class="section-tag">[ 0x06 // TECH_STACK ]</span>
            </h2>
            <div class="grid-pills">
        """
        for t in tech_stack:
            html_code += f"""
                <div class="pill-card">
                    <div>
                        <div style="font-weight: 700; color: var(--neon-green);">{html.escape(t.get('name', ''))}</div>
                        <div style="font-size: 0.75rem; color: var(--neon-dim);">{html.escape(t.get('category', ''))}</div>
                    </div>
                    <span class="cyber-badge cyber-badge-cyan">ACTIVE</span>
                </div>
            """
        html_code += """
            </div>
        </div>
        """

    # NETWORK INFRASTRUCTURE & IP GEOLOCATION
    if ip_geos:
        html_code += """
        <div class="section-card filter-target" data-section="network">
            <h2>
                <span class="title-text"><span>🌐</span> NETWORK INFRASTRUCTURE & IP GEOLOCATION</span>
                <span class="section-tag">[ 0x07 // IP_GEOINT ]</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th class="offset-col">OFFSET</th>
                        <th>IP ADDRESS</th>
                        <th>GEOGRAPHIC LOCATION</th>
                        <th>ISP / HOSTING ORGANIZATION</th>
                        <th>ASN NUMBER</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idx, g in enumerate(ip_geos):
            loc = f"{html.escape(g.get('city', ''))}, {html.escape(g.get('country', ''))}"
            html_code += f"""
                <tr>
                    <td class="offset-col">0x{idx*8:03X}</td>
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

    # EMAIL SECURITY (SPF / DMARC)
    if email_sec:
        spf_status = email_sec.get("spf_status", "N/A")
        dmarc_policy = email_sec.get("dmarc_policy", "N/A")
        html_code += f"""
        <div class="section-card filter-target" data-section="email">
            <h2>
                <span class="title-text"><span>📧</span> EMAIL SPOOFING & AUTHENTICATION SECURITY</span>
                <span class="section-tag">[ 0x08 // MAIL_SECURITY ]</span>
            </h2>
            <table>
                <thead>
                    <tr><th class="offset-col">OFFSET</th><th>SECURITY PROTOCOL</th><th>CONFIGURED RECORD / TELEMETRY</th></tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="offset-col">0x000</td>
                        <td><strong>SPF Authentication</strong></td>
                        <td><span class="cyber-badge cyber-badge-cyan">{html.escape(spf_status)}</span></td>
                    </tr>
                    <tr>
                        <td class="offset-col">0x008</td>
                        <td><strong>SPF Record</strong></td>
                        <td><code>{html.escape(email_sec.get("spf_record", "Missing"))}</code></td>
                    </tr>
                    <tr>
                        <td class="offset-col">0x010</td>
                        <td><strong>DMARC Policy</strong></td>
                        <td><span class="cyber-badge cyber-badge-green">POLICY: {html.escape(dmarc_policy)}</span></td>
                    </tr>
                    <tr>
                        <td class="offset-col">0x018</td>
                        <td><strong>DMARC Record</strong></td>
                        <td><code>{html.escape(email_sec.get("dmarc_record", "Missing"))}</code></td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    # DISCOVERED SUBDOMAINS
    if subdomains:
        sample_subs = live_subdomains if live_subdomains else [{"subdomain": s, "ips": [], "live": False} for s in subdomains[:25]]
        html_code += f"""
        <div class="section-card filter-target" data-section="subdomains">
            <h2>
                <span class="title-text"><span>📡</span> DISCOVERED SUBDOMAINS ({len(subdomains)} TOTAL DISCOVERED)</span>
                <span class="section-tag">[ 0x09 // SUBDOMAINS ]</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th class="offset-col">OFFSET</th>
                        <th>SUBDOMAIN FQDN</th>
                        <th>STATUS</th>
                        <th>RESOLVED IP(S)</th>
                        <th>CNAME / TAKEOVER AUDIT</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idx, sub_item in enumerate(sample_subs[:30]):
            is_live = sub_item.get("live", False)
            badge_class = "cyber-badge-green" if is_live else "cyber-badge-cyan"
            status_label = "LIVE" if is_live else "PASSIVE"
            ips_str = ", ".join(sub_item.get("ips", [])) or "-"
            cname_str = sub_item.get("cname") or "-"
            if sub_item.get("takeover_risk"):
                cname_str = f"<span style='color:var(--neon-red); font-weight:bold;'>⚠️ TAKEOVER: {html.escape(sub_item['takeover_risk'])}</span>"
            html_code += f"""
                <tr>
                    <td class="offset-col">0x{idx*8:03X}</td>
                    <td><code>{html.escape(sub_item.get('subdomain', ''))}</code></td>
                    <td><span class="cyber-badge {badge_class}">{status_label}</span></td>
                    <td>{html.escape(ips_str)}</td>
                    <td>{cname_str}</td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # HTTP SECURITY HEADERS
    if sec_headers:
        html_code += """
        <div class="section-card filter-target" data-section="headers">
            <h2>
                <span class="title-text"><span>🛡️</span> HTTP DEFENSIVE SECURITY HEADERS</span>
                <span class="section-tag">[ 0x0A // HTTP_HEADERS ]</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th class="offset-col">OFFSET</th>
                        <th>SECURITY HEADER NAME</th>
                        <th>DEFENSIVE STATUS</th>
                    </tr>
                </thead>
                <tbody>
        """
        for idx, (hname, hval) in enumerate(sec_headers.items()):
            is_present = hval not in ["Missing", None]
            badge_class = "cyber-badge-green" if is_present else "cyber-badge-red"
            val_text = "PRESENT" if is_present else "MISSING"
            html_code += f"""
                <tr>
                    <td class="offset-col">0x{idx*8:03X}</td>
                    <td><code>{html.escape(hname)}</code></td>
                    <td><span class="cyber-badge {badge_class}">{val_text}</span></td>
                </tr>
            """
        html_code += """
                </tbody>
            </table>
        </div>
        """

    # SOCMINT & SOCIAL FOOTPRINTS
    if social_profiles:
        html_code += f"""
        <div class="section-card filter-target" data-section="socmint">
            <h2>
                <span class="title-text"><span>👤</span> VERIFIED SOCMINT & DEVELOPER FOOTPRINTS ({len(social_profiles)} FOUND)</span>
                <span class="section-tag">[ 0x0B // IDENTITY_INTEL ]</span>
            </h2>
            <div class="grid-pills">
        """
        for p in social_profiles:
            html_code += f"""
                <a href="{html.escape(p['url'])}" target="_blank" class="pill-card">
                    <span style="font-weight:700;">{html.escape(p['platform'])}</span>
                    <span style="color: var(--neon-green); font-size: 0.8rem;">CONFIRMED &rarr;</span>
                </a>
            """
        html_code += """
            </div>
        </div>
        """

    # REVERSE IP CO-HOSTING
    if reverse_ip:
        html_code += """
        <div class="section-card filter-target" data-section="reverseip">
            <h2>
                <span class="title-text"><span>🔄</span> REVERSE IP CO-HOSTING (SHARED SERVER DOMAINS)</span>
                <span class="section-tag">[ 0x0C // REVERSE_IP ]</span>
            </h2>
        """
        for item in reverse_ip:
            html_code += f"""
            <h3 style="font-size: 0.95rem; color: var(--neon-cyan); font-family: var(--font-display);">Server IP: <code>{html.escape(item.get('ip', ''))}</code></h3>
            <div class="grid-pills" style="margin-bottom: 18px;">
            """
            for d in item.get("co_hosted_domains", [])[:18]:
                html_code += f"<div class='pill-card'><code>{html.escape(d)}</code></div>"
            html_code += "</div>"
        html_code += "</div>"

    # TARGETED SEARCH DORKS CARD (DORKINT)
    if search_dorks:
        html_code += """
        <div class="section-card filter-target" data-section="dorks">
            <h2>
                <span class="title-text"><span>🔎</span> TARGETED SEARCH DORKS & EXPOSURE QUERIES (DORKINT)</span>
                <span class="section-tag">[ 0x0D // GOOGLE_DORKS ]</span>
            </h2>
            <div class="grid-pills">
        """
        for d in search_dorks:
            html_code += f"""
                <a href="{html.escape(d.get('url', '#'))}" target="_blank" class="pill-card" style="flex-direction: column; align-items: flex-start; gap: 4px;">
                    <div style="font-weight: 700; color: var(--neon-amber);">{html.escape(d.get('category', ''))}</div>
                    <div style="font-size: 0.78rem; color: var(--neon-dim); font-family: var(--font-mono);">{html.escape(d.get('dork', ''))}</div>
                    <span style="color: var(--neon-cyan); font-size: 0.78rem; align-self: flex-end;">EXECUTE DORK &rarr;</span>
                </a>
            """
        html_code += """
            </div>
        </div>
        """

    # RAW JSON INSPECTION
    html_code += f"""
        <details>
            <summary>
                <span>📦 DECRYPTED RAW INTEL PAYLOAD STREAM (EXPAND JSON)</span>
                <span style="font-size: 0.8rem; color: var(--neon-green);">[ CLICK TO DECRYPT ]</span>
            </summary>
            <pre id="raw-json-block"><code>{html.escape(json.dumps(data, indent=4, default=str))}</code></pre>
        </details>
    </div>

    <!-- Client-side Interactive Engine: Matrix Rain, Vis.js, Web Audio Synth & Terminal Search -->
    <script type="text/javascript">
        // 1. Web Audio Synthesizer (Retro Sci-Fi Cyber Sound Effects)
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        let audioCtx = null;
        let soundEnabled = true;

        function getAudioContext() {{
            if (!audioCtx) {{
                audioCtx = new AudioContext();
            }}
            if (audioCtx.state === 'suspended') {{
                audioCtx.resume();
            }}
            return audioCtx;
        }}

        function playCyberSound(freq = 880, type = 'sine', duration = 0.06, gain = 0.04) {{
            if (!soundEnabled) return;
            try {{
                const ctx = getAudioContext();
                const osc = ctx.createOscillator();
                const g = ctx.createGain();
                osc.type = type;
                osc.frequency.setValueAtTime(freq, ctx.currentTime);
                g.gain.setValueAtTime(gain, ctx.currentTime);
                g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
                osc.connect(g);
                g.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + duration);
            }} catch(e) {{}}
        }}

        function toggleCyberSound() {{
            soundEnabled = !soundEnabled;
            const lbl = document.getElementById('lbl-sound');
            const btn = document.getElementById('btn-sound');
            if (lbl) lbl.textContent = soundEnabled ? 'ON' : 'OFF';
            if (btn) btn.classList.toggle('active', soundEnabled);
            if (soundEnabled) playCyberSound(1200, 'square', 0.08);
        }}

        // 2. Matrix Digital Rain Canvas
        const canvas = document.getElementById('matrix-canvas');
        let ctx = null;
        let rainInterval = null;
        let matrixEnabled = true;

        if (canvas) {{
            ctx = canvas.getContext('2d');
            let width = canvas.width = window.innerWidth;
            let height = canvas.height = window.innerHeight;

            window.addEventListener('resize', () => {{
                width = canvas.width = window.innerWidth;
                height = canvas.height = window.innerHeight;
            }});

            const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF<>/*-+{{}}[]~_';
            const fontSize = 14;
            const columns = Math.floor(width / fontSize);
            const drops = Array(columns).fill(1);

            function drawMatrix() {{
                ctx.fillStyle = 'rgba(3, 7, 13, 0.05)';
                ctx.fillRect(0, 0, width, height);
                ctx.fillStyle = '#00ff88';
                ctx.font = fontSize + 'px monospace';

                for (let i = 0; i < drops.length; i++) {{
                    const text = chars.charAt(Math.floor(Math.random() * chars.length));
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                    if (drops[i] * fontSize > height && Math.random() > 0.975) {{
                        drops[i] = 0;
                    }}
                    drops[i]++;
                }}
            }}

            rainInterval = setInterval(drawMatrix, 35);
        }}

        function toggleMatrixRain() {{
            matrixEnabled = !matrixEnabled;
            if (canvas) canvas.classList.toggle('disabled', !matrixEnabled);
            const lbl = document.getElementById('lbl-matrix');
            const btn = document.getElementById('btn-matrix');
            if (lbl) lbl.textContent = matrixEnabled ? 'ON' : 'OFF';
            if (btn) btn.classList.toggle('active', matrixEnabled);
            playCyberSound(950, 'sine', 0.05);
        }}

        // 3. CRT Scanline Toggle
        let scanlinesEnabled = true;
        function toggleScanlines() {{
            scanlinesEnabled = !scanlinesEnabled;
            const overlay = document.getElementById('crt-scanlines');
            if (overlay) overlay.classList.toggle('disabled', !scanlinesEnabled);
            const lbl = document.getElementById('lbl-scanlines');
            const btn = document.getElementById('btn-scanlines');
            if (lbl) lbl.textContent = scanlinesEnabled ? 'ON' : 'OFF';
            if (btn) btn.classList.toggle('active', scanlinesEnabled);
            playCyberSound(750, 'triangle', 0.06);
        }}

        // 4. Interactive Terminal Command & Live Filter
        function handleTerminalInput(e) {{
            const input = document.getElementById('terminal-input');
            const query = input.value.trim().toLowerCase();
            const counter = document.getElementById('terminal-matches');

            // Handle special commands
            if (e.key === 'Enter') {{
                if (query === '/matrix') {{ toggleMatrixRain(); input.value = ''; return; }}
                if (query === '/crt' || query === '/scanlines') {{ toggleScanlines(); input.value = ''; return; }}
                if (query === '/audio' || query === '/sound') {{ toggleCyberSound(); input.value = ''; return; }}
                if (query === '/print' || query === '/export') {{ window.print(); return; }}
                if (query === '/clear') {{ input.value = ''; resetFilter(); return; }}
            }}

            playCyberSound(1400 + Math.random() * 400, 'sine', 0.03, 0.015);

            if (!query) {{
                resetFilter();
                if (counter) counter.textContent = 'READY';
                return;
            }}

            let matchCount = 0;
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(r => {{
                const text = r.textContent.toLowerCase();
                if (text.includes(query)) {{
                    r.style.display = '';
                    matchCount++;
                }} else {{
                    r.style.display = 'none';
                }}
            }});

            const pills = document.querySelectorAll('.pill-card');
            pills.forEach(p => {{
                const text = p.textContent.toLowerCase();
                if (text.includes(query)) {{
                    p.style.display = '';
                    matchCount++;
                }} else {{
                    p.style.display = 'none';
                }}
            }});

            if (counter) {{
                counter.textContent = matchCount + ' MATCH' + (matchCount === 1 ? '' : 'ES');
            }}
        }}

        function resetFilter() {{
            document.querySelectorAll('tbody tr, .pill-card').forEach(el => {{
                el.style.display = '';
            }});
        }}

        // 5. Copy Intel to Clipboard
        function copyIntelJson() {{
            const pre = document.getElementById('raw-json-block');
            if (pre) {{
                navigator.clipboard.writeText(pre.textContent).then(() => {{
                    playCyberSound(1600, 'sine', 0.1);
                    alert("Intelligence JSON payload successfully copied to clipboard.");
                }}).catch(() => {{
                    alert("Copy failed. Please manually select from the bottom accordion.");
                }});
            }}
        }}

        // 6. Vis.js Network Graph Initialization
        let networkInstance = null;
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
                        font: {{ face: 'monospace', color: '#ffffff' }}
                    }},
                    edges: {{
                        smooth: {{ type: 'continuous' }},
                        width: 1.5,
                        font: {{ size: 9, color: '#799bbb', align: 'top', face: 'monospace' }}
                    }},
                    physics: {{
                        stabilization: true,
                        barnesHut: {{
                            gravitationalConstant: -2800,
                            centralGravity: 0.28,
                            springLength: 120,
                            springConstant: 0.04
                        }}
                    }},
                    interaction: {{
                        hover: true,
                        navigationButtons: false,
                        keyboard: true
                    }}
                }};
                networkInstance = new vis.Network(container, data, options);
                networkInstance.on("click", () => playCyberSound(1100, 'sine', 0.05));
            }}
        }} catch(e) {{
            console.error("Vis.js initialization error:", e);
        }}

        function zoomGraph(factor) {{
            if (networkInstance) {{
                const scale = networkInstance.getScale();
                networkInstance.moveTo({{ scale: scale * factor }});
                playCyberSound(900, 'sine', 0.05);
            }}
        }}

        function resetGraph() {{
            if (networkInstance) {{
                networkInstance.fit();
                playCyberSound(800, 'sine', 0.05);
            }}
        }}

        function toggleGraphFullscreen() {{
            const graphDiv = document.getElementById('network-graph');
            if (graphDiv) {{
                if (!document.fullscreenElement) {{
                    graphDiv.requestFullscreen().catch(() => {{}});
                }} else {{
                    document.exitFullscreen().catch(() => {{}});
                }}
            }}
        }}

        // 7. Hollywood Decrypt Character Scramble on Page Load
        function runDecryptAnimation() {{
            const elements = document.querySelectorAll('.decrypt-text');
            const glyphs = '!<>-_\\\\/[]{{}}—=+*^?#________';
            elements.forEach(el => {{
                const target = el.getAttribute('data-original') || el.textContent;
                let iteration = 0;
                const interval = setInterval(() => {{
                    el.textContent = target.split('').map((char, idx) => {{
                        if (idx < iteration) return target[idx];
                        return glyphs[Math.floor(Math.random() * glyphs.length)];
                    }}).join('');
                    if (iteration >= target.length) {{
                        clearInterval(interval);
                    }}
                    iteration += 1 / 2;
                }}, 30);
            }});
        }}

        // Add hover sound to cards
        document.addEventListener('DOMContentLoaded', () => {{
            runDecryptAnimation();
            document.querySelectorAll('.stat-card, .pill-card, .hud-btn').forEach(item => {{
                item.addEventListener('mouseenter', () => playCyberSound(650, 'sine', 0.03, 0.01));
            }});
        }});
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
