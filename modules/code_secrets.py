#!/usr/bin/env python3
"""
OSINTALL - Code Repositories & Secret Leak Detection Module
Covers: grep.app, Sourcegraph, PublicWWW, and Gitleaks / TruffleHog wrappers.
"""

import subprocess
import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error

def search_code_engines(query: str):
    """Generates direct code footprint search queries across public repositories and web footprints."""
    print_section(f"Code & Secret Search: Public Repositories ({query})", icon="💻")
    print_info(f"Target query / string: [bold cyan]{query}[/]")

    table = Table(title="Source Code Search Engines & Footprint Trackers", border_style="cyan")
    table.add_column("Engine", style="bold yellow", width=18)
    table.add_column("Capability", style="white", width=32)
    table.add_column("Direct Search Link", style="underline blue")

    table.add_row(
        "grep.app",
        "Fast search across 500k+ GitHub public repos",
        f"https://grep.app/search?q={query}"
    )
    table.add_row(
        "Sourcegraph",
        "Universal code search across millions of repos",
        f"https://sourcegraph.com/search?q=context:global+{query}"
    )
    table.add_row(
        "PublicWWW",
        "Source code & HTML/JS signature search",
        f"https://publicwww.com/websites/{query}/"
    )
    table.add_row(
        "GitHub Code Search",
        "Official GitHub global code index",
        f"https://github.com/search?q={query}&type=code"
    )
    table.add_row(
        "GitLab Code Search",
        "Public GitLab snippets and code search",
        f"https://gitlab.com/search?search={query}&nav_source=navbar"
    )

    console.print(table)

def scan_repo_secrets(repo_path_or_url: str):
    """Wraps Gitleaks or TruffleHog to scan a git repository for exposed secrets."""
    print_section(f"Secret Scanner: Scanning Repository ({repo_path_or_url})", icon="🔑")

    gitleaks_found = subprocess.run(["which", "gitleaks"], capture_output=True).returncode == 0
    trufflehog_found = subprocess.run(["which", "trufflehog"], capture_output=True).returncode == 0

    if not gitleaks_found and not trufflehog_found:
        print_warning("Neither 'gitleaks' nor 'trufflehog' binary found in system PATH.")
        print_info("Install them on Kali with:")
        console.print("[bold cyan]sudo apt install gitleaks[/]")
        console.print("[bold cyan]pip install trufflehog3[/]")
        return

    if gitleaks_found:
        print_info("Running [bold green]gitleaks[/] scan...")
        try:
            cmd = ["gitleaks", "detect", "--source", repo_path_or_url, "-v"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                print_success("No leaked secrets detected by Gitleaks!")
            else:
                print_error(f"Gitleaks detected potential secret leaks:\n{res.stdout}")
        except Exception as e:
            print_error(f"Error running gitleaks: {e}")

    if trufflehog_found:
        print_info("Running [bold green]trufflehog[/] scan...")
        try:
            cmd = ["trufflehog", "git", repo_path_or_url]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            console.print(res.stdout[:1000])
        except Exception as e:
            print_error(f"Error running trufflehog: {e}")
