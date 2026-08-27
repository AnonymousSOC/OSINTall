#!/usr/bin/env python3
"""
OSINTALL - Banner & UI Styling Module
Powered by Rich Terminal Formatting
"""

import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

console = Console()

BANNER_ART = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗ ██╗     ██╗     
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██║     ██║     
██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║     ██║     
██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║     ██║     
╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║███████╗███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
"""

TAGLINE = "Universal Open Source Intelligence Reconnaissance Framework | Kali Linux"
VERSION = "v1.0.0"

def show_banner():
    """Prints the styled ASCII banner with author and version information."""
    text_banner = Text(BANNER_ART, style="bold cyan")
    panel = Panel(
        text_banner,
        subtitle=f"[bold yellow]{TAGLINE}[/] [bold magenta]({VERSION})[/]",
        subtitle_align="center",
        border_style="bright_blue",
        padding=(0, 2)
    )
    console.print(panel)
    console.print("[dim white]Author: OSINTALL Team | Target OS: Kali Linux / Linux / Multi-Platform[/dim white]\n")

def print_section(title: str, icon: str = "🔍"):
    """Prints a styled section header."""
    console.print(f"\n[bold green]{icon} ─── [bold white]{title.upper()}[/] ──────────────────────────────[/]")

def print_info(msg: str):
    """Prints an informational message."""
    console.print(f"[bold blue][*][/] {msg}")

def print_success(msg: str):
    """Prints a success message."""
    console.print(f"[bold green][+][/] {msg}")

def print_warning(msg: str):
    """Prints a warning message."""
    console.print(f"[bold yellow][!][/] {msg}")

def print_error(msg: str):
    """Prints an error message."""
    console.print(f"[bold red][-][/] {msg}")

def load_config() -> dict:
    """Loads configuration from config/config.json with safe defaults."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "settings": {
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) OSINTALL/1.0",
            "request_timeout_seconds": 8,
            "max_threads": 20,
            "save_reports_by_default": True,
            "reports_directory": "reports"
        },
        "api_keys": {},
        "service_links": {}
    }
