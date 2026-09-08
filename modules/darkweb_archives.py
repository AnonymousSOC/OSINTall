#!/usr/bin/env python3
"""
OSINTALL - Dark Web, Web Archives & Frameworks Module (Enhanced)
Covers: Wayback Machine CDX API Historical Snapshots (with Sensitive File Filtering),
Local Tor SOCKS5 Service Detection, Dark Web Search Engines, and OSINT Framework Directories.
"""

import socket
import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, get_requests_session
)

def is_tor_running(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Checks if a local Tor SOCKS5 proxy is listening."""
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except Exception:
        return False

def check_wayback_history(target_url: str, filter_sensitive: bool = False, limit: int = 15) -> list:
    """Queries Wayback Machine CDX API for historical snapshots with optional sensitive file filtering."""
    print_section(f"Web Archives: Historical Snapshots ({target_url})", icon="🏛️")
    print_info(f"Querying Archive.org CDX API for snapshots of: [bold cyan]{target_url}[/]")

    session = get_requests_session()
    snapshots = []
    
    clean_target = target_url.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={clean_target}/*&output=json&limit={limit*3}&collapse=timestamp:6"
    
    try:
        resp = session.get(cdx_url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                sensitive_exts = (".env", ".sql", ".bak", ".pdf", ".xls", ".xlsx", ".config", ".log", ".json", ".backup")
                filtered_rows = []
                for row in data[1:]:
                    ts = row[1]
                    orig = row[2]
                    snap_link = f"https://web.archive.org/web/{ts}/{orig}"
                    is_sensitive = orig.lower().endswith(sensitive_exts)
                    
                    if filter_sensitive and not is_sensitive:
                        continue
                    
                    filtered_rows.append((ts, orig, snap_link, is_sensitive))
                    snapshots.append({"timestamp": ts, "url": orig, "wayback_url": snap_link, "sensitive": is_sensitive})
                    if len(filtered_rows) >= limit:
                        break

                if filtered_rows:
                    table = Table(title=f"Archive.org Historical Snapshots ({len(filtered_rows)} displayed)", border_style="cyan")
                    table.add_column("Timestamp", style="bold yellow", width=16)
                    table.add_column("Original URL", style="white")
                    table.add_column("Type", style="magenta", width=12)
                    table.add_column("Snapshot Wayback Link", style="underline blue")

                    for ts, orig, snap_link, is_sens in filtered_rows:
                        type_str = "[bold red]SENSITIVE[/]" if is_sens else "Page"
                        table.add_row(ts, orig[:45], type_str, snap_link)

                    console.print(table)

                    # Parameter & Sensitive Path Mining
                    mined_params = set()
                    mined_admin_paths = set()
                    for row in data[1:]:
                        orig_url = row[2]
                        if "?" in orig_url:
                            query_part = orig_url.split("?", 1)[1]
                            for param_pair in query_part.split("&"):
                                if "=" in param_pair:
                                    mined_params.add(param_pair.split("=")[0].strip())
                        url_lower = orig_url.lower()
                        for trigger in ["/admin", "/login", "/api/", "/swagger", "/graphql", "/actuator", "/dashboard"]:
                            if trigger in url_lower:
                                mined_admin_paths.add(orig_url.split("?")[0])

                    if mined_params or mined_admin_paths:
                        mine_table = Table(title="Mined Wayback Endpoints & Parameters (Bug Bounty Audit)", border_style="yellow")
                        mine_table.add_column("Category", style="bold yellow", width=22)
                        mine_table.add_column("Discovered Assets", style="white")
                        if mined_admin_paths:
                            mine_table.add_row("Admin / API Endpoints", "\n".join(list(mined_admin_paths)[:6]))
                        if mined_params:
                            mine_table.add_row("Discovered Parameters", ", ".join(sorted(list(mined_params))[:15]))
                        console.print(mine_table)

                    return snapshots
                else:
                    print_info("No snapshots matching sensitive file extension criteria found.")
    except Exception as e:
        print_warning(f"Archive.org CDX API query note: {e}")

    # Fallback search link
    fallback_link = f"https://web.archive.org/web/*/{clean_target}"
    print_info(f"Direct Wayback Machine browser view: [underline cyan]{fallback_link}[/]")
    return snapshots

def search_darkweb(query: str):
    """Generates direct dark web search queries and tests for active Tor SOCKS proxy."""
    print_section(f"Dark Web Intelligence: Hidden Services ({query})", icon="🧅")
    
    # 1. Tor Proxy Status Check on Kali Linux
    tor_active = is_tor_running("127.0.0.1", 9050) or is_tor_running("127.0.0.1", 9150)
    if tor_active:
        print_success("Local Tor SOCKS5 proxy detected! (127.0.0.1:9050 active)")
    else:
        print_info("Local Tor daemon not detected. To start Tor on Kali: [bold cyan]sudo systemctl start tor[/]")

    # 2. Dark Web Search Engines
    table = Table(title=f"Dark Web & .onion Search Engines for: '{query}'", border_style="purple")
    table.add_column("Search Engine / Gateway", style="bold magenta", width=25)
    table.add_column("Search Link (Clearnet Mirror / Tor)", style="underline white")

    table.add_row("Ahmia (Clearnet Gateway)", f"https://ahmia.fi/search/?q={query}")
    table.add_row("Ahmia (.onion service)", f"http://juhanurmih5wuwwiobtmsdahrmudamnnoxqa5nv7i6a3eguniofqlad.onion/search/?q={query}")
    table.add_row("Torry Search Engine", f"https://www.torry.io/search/?q={query}")
    table.add_row("DuckDuckGo Onion", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
    table.add_row("OnionSearch CLI", f"Run in Kali: onionsearch '{query}'")
    console.print(table)

def show_osint_frameworks():
    """Displays links and launch commands for major OSINT frameworks."""
    print_section("Link Analysis & Automated Recon Frameworks", icon="🕸️")

    table = Table(title="OSINT Reconnaissance Frameworks & Visual Graph Tools", border_style="blue")
    table.add_column("Framework", style="bold yellow", width=18)
    table.add_column("Description", style="white", width=35)
    table.add_column("Launch / Access Command", style="underline cyan")

    table.add_row(
        "Maltego",
        "Visual Link-Analysis & Graph Transforms",
        "Run in Kali: maltego (or visit https://www.maltego.com/)"
    )
    table.add_row(
        "SpiderFoot",
        "Automated Recon Aggregator (200+ sources)",
        "Run in Kali: spiderfoot (or visit https://spiderfoot.net)"
    )
    table.add_row(
        "Recon-ng",
        "Modular Recon CLI (Metasploit style)",
        "Run in Kali: recon-ng"
    )
    table.add_row(
        "OSINT Framework",
        "Directory tree categorizing OSINT tools",
        "https://osintframework.com/"
    )
    console.print(table)
