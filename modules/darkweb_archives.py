#!/usr/bin/env python3
"""
OSINTALL - Dark Web, Web Archives & Frameworks Module
Covers: Wayback Machine CDX API historical snapshots, Archive.today,
Dark Web search engines (Ahmia, OnionSearch, Torry), and Link Analysis Frameworks (Maltego, SpiderFoot, Recon-ng).
"""

import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error

def check_wayback_history(target_url: str, limit: int = 10) -> list:
    """Queries Wayback Machine CDX API for historical snapshots."""
    print_section(f"Web Archives: Historical Snapshots ({target_url})", icon="🏛️")
    print_info(f"Querying Archive.org CDX API for snapshots of: [bold cyan]{target_url}[/]")

    snapshots = []
    try:
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={target_url}/*&output=json&limit={limit}&collapse=timestamp:6"
        resp = requests.get(cdx_url, timeout=10, headers={"User-Agent": "OSINTALL/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                headers = data[0]
                table = Table(title=f"Archive.org Historical Snapshots (Found {len(data)-1})", border_style="cyan")
                table.add_column("Timestamp", style="bold yellow", width=16)
                table.add_column("Original URL", style="white")
                table.add_column("Snapshot Wayback Link", style="underline blue")

                for row in data[1:]:
                    ts = row[1]
                    orig = row[2]
                    snap_link = f"https://web.archive.org/web/{ts}/{orig}"
                    snapshots.append({"timestamp": ts, "url": orig, "wayback_url": snap_link})
                    table.add_row(ts, orig[:40], snap_link)

                console.print(table)
                return snapshots
    except Exception as e:
        print_warning(f"Archive.org CDX API query note: {e}")

    # Fallback search link
    fallback_link = f"https://web.archive.org/web/*/{target_url}"
    print_info(f"Direct Wayback Machine view: [underline cyan]{fallback_link}[/]")
    return snapshots

def search_darkweb(query: str):
    """Generates direct dark web search queries for Tor and Onion search engines."""
    print_section(f"Dark Web Intelligence: Hidden Services Search ({query})", icon="🧅")
    print_info(f"Querying search parameters for: [bold cyan]{query}[/]")

    table = Table(title="Dark Web & .onion Search Engines", border_style="purple")
    table.add_column("Dark Web Search Engine", style="bold magenta", width=25)
    table.add_column("Search Link (Clearnet / Tor Gateway)", style="underline white")

    table.add_row("Ahmia (Clearnet Gateway)", f"https://ahmia.fi/search/?q={query}")
    table.add_row("Ahmia (.onion service)", f"http://juhanurmih5wuwwiobtmsdahrmudamnnoxqa5nv7i6a3eguniofqlad.onion/search/?q={query}")
    table.add_row("Torry Search", f"https://www.torry.io/search/?q={query}")
    table.add_row("OnionSearch CLI", "Run in Kali: onionsearch '{query}'")
    table.add_row("DuckDuckGo Onion", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
    console.print(table)

def show_osint_frameworks():
    """Displays links and launch commands for major OSINT frameworks."""
    print_section("Link Analysis & Automated Recon Frameworks", icon="🕸️")

    table = Table(title="OSINT Reconnaissance Frameworks & Visual Graph Tools", border_style="blue")
    table.add_column("Framework", style="bold yellow", width=18)
    table.add_column("Description", style="white", width=35)
    table.add_column("Launch / Access Link", style="underline cyan")

    table.add_row(
        "Maltego",
        "Visual Link-Analysis & Graph Transforms",
        "Run in Kali: maltego (or visit https://www.maltego.com/)"
    )
    table.add_row(
        "SpiderFoot",
        "Automated Recon Aggregator (200+ sources)",
        "Run in Kali: spiderfoot (or visit https://github.com/smicallef/spiderfoot)"
    )
    table.add_row(
        "Recon-ng",
        "Modular Recon CLI (Metasploit style)",
        "Run in Kali: recon-ng"
    )
    table.add_row(
        "OSINT Framework",
        "Directory tree categorizing OSINT by data type",
        "https://osintframework.com/"
    )
    console.print(table)
