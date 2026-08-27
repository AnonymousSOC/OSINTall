#!/usr/bin/env python3
"""
OSINTALL - Breach Intelligence & Compromised Data Module
Covers: Have I Been Pwned (HIBP) k-anonymity API, DeHashed, LeakCheck, Intelligence X,
Snusbase, and BreachDirectory lookup interfaces.
"""

import hashlib
import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error, load_config

def check_hibp_password_hash(password: str) -> dict:
    """
    Checks password against Have I Been Pwned (HIBP) using k-anonymity.
    Only the first 5 characters of SHA-1 hash are sent to the API.
    """
    print_section("Breach Intelligence: Password Exposure Check", icon="🔐")
    
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "OSINTALL/1.0 (Kali Linux Privacy Checker)"}
    
    try:
        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            hashes = [line.split(":") for line in resp.text.splitlines()]
            for h, count in hashes:
                if h == suffix:
                    print_error(f"WARNING: This password was found [bold red]{int(count):,}[/] times in known public data breaches!")
                    return {"exposed": True, "count": int(count), "sha1": sha1_hash}
            print_success("GOOD NEWS: This password was NOT found in HIBP public leak databases.")
            return {"exposed": False, "count": 0, "sha1": sha1_hash}
        else:
            print_warning(f"HIBP API returned status {resp.status_code}")
    except Exception as e:
        print_error(f"Error querying HIBP API: {e}")
    return {"exposed": False, "error": True}

def check_email_breaches(email: str) -> dict:
    """Generates breach intelligence queries for a specific email or domain."""
    print_section(f"Breach Intelligence: Exposure Directory ({email})", icon="🛡️")
    print_info(f"Cross-referencing leak databases & indices for: [bold cyan]{email}[/]")

    table = Table(title="Compromised Credential & Breach Intelligence Engines", border_style="red")
    table.add_column("Service", style="bold yellow", width=18)
    table.add_column("Type", style="cyan", width=22)
    table.add_column("Query Link / Endpoint", style="underline white")

    table.add_row(
        "Have I Been Pwned",
        "Public Breach Aggregator",
        f"https://haveibeenpwned.com/account/{email}"
    )
    table.add_row(
        "DeHashed",
        "Raw Database / Pastes",
        f"https://dehashed.com/search?query={email}"
    )
    table.add_row(
        "LeakCheck.io",
        "Credential Combos",
        f"https://leakcheck.io/search?query={email}"
    )
    table.add_row(
        "Intelligence X (intelx)",
        "Deep Darkweb Pastes",
        f"https://intelx.io/?s={email}"
    )
    table.add_row(
        "BreachDirectory",
        "API Hash & Combo Search",
        f"https://breachdirectory.org/"
    )
    table.add_row(
        "Snusbase",
        "Indexed Historical Leaks",
        f"https://snusbase.com/search"
    )

    console.print(table)

    print_info("[dim]Tip: For automated DeHashed/LeakCheck API queries, configure your API keys in config/config.json[/dim]")

    return {
        "email": email,
        "services": [
            "Have I Been Pwned",
            "DeHashed",
            "LeakCheck",
            "Intelligence X",
            "BreachDirectory",
            "Snusbase"
        ]
    }
