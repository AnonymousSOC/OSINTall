#!/usr/bin/env python3
"""
OSINTALL - Banner & UI Styling Module
Powered by Rich Terminal Formatting
"""

import sys
import os
import json
import shutil
import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

# Ensure UTF-8 encoding across Windows, Linux, and non-UTF-8 terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False if sys.platform == "win32" else None)

BANNER_ART = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗ ██╗     ██╗     
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██║     ██║     
██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║     ██║     
██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║     ██║     
╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║███████╗███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
"""

TAGLINE = "Universal Open Source Intelligence Reconnaissance Framework"
VERSION = "v2.3.0 [ZERO-FALSE-ALARM]"

# Global proxy setting (can be set via CLI --proxy)
GLOBAL_PROXY = None

def set_global_proxy(proxy_url: str):
    """Sets the global proxy URL for outgoing HTTP/HTTPS requests."""
    global GLOBAL_PROXY
    GLOBAL_PROXY = proxy_url

def get_requests_session() -> requests.Session:
    """Creates a configured requests.Session with default headers and optional proxy."""
    config = load_config()
    session = requests.Session()
    user_agent = config.get("settings", {}).get(
        "user_agent",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 OSINTALL/2.0"
    )
    session.headers.update({"User-Agent": user_agent})
    if GLOBAL_PROXY:
        session.proxies.update({
            "http": GLOBAL_PROXY,
            "https": GLOBAL_PROXY
        })
    return session

def show_banner():
    """Prints the styled ASCII banner with Hollywood movie-hacker terminal aesthetics."""
    text_banner = Text(BANNER_ART, style="bold #00f3ff")

    panel = Panel(
        text_banner,
        title="[bold #00ff88]╔══[ [bold #00f3ff]TOP SECRET // CYBER RECON HUD[/] [bold #00ff88]]══╗[/]",
        title_align="center",
        subtitle=f"[bold #00ff88]● DEFCON-1: ARMED[/]  [bold #ffb800]⚡ {TAGLINE} ⚡[/]  [bold #00f3ff]SYS: {VERSION}[/]",
        subtitle_align="center",
        border_style="bold #00ff88",
        padding=(0, 2)
    )
    console.print(panel)

    # Cyber diagnostics telemetry bar
    telemetry = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    telemetry.add_column(style="dim #00f3ff")
    telemetry.add_column(style="dim #00ff88")
    telemetry.add_column(style="dim #ffb800")
    telemetry.add_column(style="dim #bd93f9")
    telemetry.add_row(
        "▸ PLATFORM: KALI/MULTI-OS",
        "▸ CLEARANCE: LEVEL-5 (TOP SECRET)",
        "▸ CIPHER: AES-256-GCM",
        "▸ RADAR: MULTI-VECTOR OSINT"
    )
    console.print(telemetry)
    console.print()

def print_section(title: str, icon: str = "◈"):
    """Prints an elite movie-hacker styled cyber HUD section header."""
    clean_title = title.upper()
    console.print()
    line_len = max(4, 60 - len(clean_title) - len(icon))
    console.print(f"[bold #00ff88]╔══[ [bold #00f3ff]{icon}[/] [bold #ffffff]{clean_title}[/] [bold #00ff88]]" + ("═" * line_len) + "╗[/]")

def print_info(msg: str):
    """Prints an informational message."""
    console.print(f"[bold #00f3ff]⟨◈ SCAN ⟩[/] [bright_white]{msg}[/]")

def print_success(msg: str):
    """Prints a success message."""
    console.print(f"[bold #00ff88]⟨✔ FOUND⟩[/] [bright_white]{msg}[/]")

def print_warning(msg: str):
    """Prints a warning message."""
    console.print(f"[bold #ffb800]⟨⚡ ALERT⟩[/] [bright_white]{msg}[/]")

def print_error(msg: str):
    """Prints an error message."""
    console.print(f"[bold #ff0055]⟨✘ ERROR⟩[/] [bright_white]{msg}[/]")

def is_tool_available(tool_name: str) -> bool:
    """Cross-platform check for binary availability in system PATH."""
    return shutil.which(tool_name) is not None

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
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 OSINTALL/2.0",
            "request_timeout_seconds": 8,
            "max_threads": 25,
            "save_reports_by_default": True,
            "reports_directory": "reports"
        },
        "api_keys": {},
        "service_links": {}
    }
