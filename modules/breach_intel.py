#!/usr/bin/env python3
"""
OSINTALL - Breach Intelligence & Compromised Data Module (Enhanced)
Covers: Have I Been Pwned (HIBP) k-anonymity SHA-1 Privacy Check,
Hudson Rock Cavalier API (Free Infostealer Malware Breach Intelligence),
and DeHashed / LeakCheck / Snusbase Correlation.
"""

import hashlib
import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, load_config, get_requests_session
)

def check_hibp_password_hash(password: str) -> dict:
    """
    Checks password against Have I Been Pwned (HIBP) using k-anonymity.
    Only the first 5 characters of the SHA-1 hash are sent to the API.
    """
    print_section("Breach Intelligence: Password Exposure Check", icon="🔐")
    
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    session = get_requests_session()
    
    try:
        resp = session.get(url, timeout=7)
        if resp.status_code == 200:
            hashes = [line.split(":") for line in resp.text.splitlines()]
            for h, count in hashes:
                if h.strip() == suffix:
                    exposure_count = int(count.strip())
                    print_error(f"WARNING: This password was found [bold red]{exposure_count:,}[/] times in known public data breaches!")
                    return {"exposed": True, "count": exposure_count, "sha1": sha1_hash}
            print_success("GOOD NEWS: This password was NOT found in HIBP public leak databases.")
            return {"exposed": False, "count": 0, "sha1": sha1_hash}
        else:
            print_warning(f"HIBP API returned HTTP status {resp.status_code}")
    except Exception as e:
        print_error(f"Error querying HIBP API: {e}")
    return {"exposed": False, "error": True}

def check_infostealer_exposure(email_or_domain: str) -> dict:
    """
    Queries Hudson Rock Cavalier API for free infostealer compromise data.
    Identifies if computers or credentials were stolen by malware (RedLine, Vidar, Lumma, etc.).
    """
    session = get_requests_session()
    is_domain = "@" not in email_or_domain
    param = f"domain={email_or_domain}" if is_domain else f"email={email_or_domain}"
    endpoint = "search-by-domain" if is_domain else "search-by-email"
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint}?{param}"

    intel = {"found": False, "stealers": [], "details": {}}
    try:
        resp = session.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            # If search-by-email
            if not is_domain:
                stealers = data.get("stealers", [])
                if stealers:
                    intel["found"] = True
                    intel["stealers"] = stealers
                    intel["details"] = {
                        "total_compromises": len(stealers),
                        "sample_malware": [s.get("malware_family", "Unknown") for s in stealers[:5]]
                    }
                    print_error(f"🚨 INFOSTEALER ALERT: Found [bold red]{len(stealers)}[/] infostealer infection(s) associated with {email_or_domain}!")
                    for idx, s in enumerate(stealers[:3], 1):
                        print_warning(f"  [{idx}] Computer: {s.get('computer_name', 'N/A')} | Malware: {s.get('malware_family', 'Unknown')} | Date: {s.get('date_compromised', 'N/A')}")
                else:
                    print_success("No infostealer malware compromises found in Hudson Rock database.")
            # If search-by-domain
            else:
                employees = data.get("employees", 0)
                users = data.get("users", 0)
                if employees > 0 or users > 0:
                    intel["found"] = True
                    intel["details"] = {"employees_compromised": employees, "users_compromised": users}
                    print_error(f"🚨 DOMAIN COMPROMISE: Hudson Rock reports [bold red]{employees}[/] compromised employee computers and [bold red]{users}[/] client accounts!")
    except Exception:
        pass
    return intel

def check_email_breaches(email: str) -> dict:
    """Generates comprehensive breach intelligence queries and checks live telemetry."""
    print_section(f"Breach Intelligence: Exposure Directory ({email})", icon="🛡️")
    print_info(f"Cross-referencing leak databases & indices for: [bold cyan]{email}[/]")

    results = {
        "email": email,
        "infostealer": {},
        "hibp_account": {},
        "services": []
    }

    # 1. Live Infostealer Check (Hudson Rock)
    print_info("Querying Hudson Rock Cybercrime / Infostealer API...")
    results["infostealer"] = check_infostealer_exposure(email)

    # 2. Check HIBP Account API (if user configured key in config.json)
    config = load_config()
    hibp_key = config.get("api_keys", {}).get("haveibeenpwned", "")
    if hibp_key:
        print_info("Querying Have I Been Pwned v3 API for account breaches...")
        session = get_requests_session()
        try:
            hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
            resp = session.get(hibp_url, headers={"hibp-api-key": hibp_key}, timeout=8)
            if resp.status_code == 200:
                breaches = resp.json()
                results["hibp_account"] = breaches
                print_error(f"Found [bold red]{len(breaches)}[/] confirmed breaches in HIBP:")
                for b in breaches[:5]:
                    print_warning(f"  - {b.get('Name')} (Date: {b.get('BreachDate')})")
            elif resp.status_code == 404:
                print_success("No public breaches found for this email in HIBP.")
        except Exception as e:
            print_warning(f"HIBP account query failed: {e}")

    # 3. Breach Intelligence Engine Directory
    table = Table(title="Compromised Credential & Breach Intelligence Engines", border_style="red")
    table.add_column("Service", style="bold yellow", width=20)
    table.add_column("Type", style="cyan", width=22)
    table.add_column("Direct Query Link / Endpoint", style="underline white")

    engines = [
        ("Have I Been Pwned", "Public Breach Aggregator", f"https://haveibeenpwned.com/account/{email}"),
        ("Hudson Rock Cavalier", "Infostealer Malware Telemetry", f"https://cavalier.hudsonrock.com/"),
        ("DeHashed", "Raw Pastes & Dumps", f"https://dehashed.com/search?query={email}"),
        ("LeakCheck.io", "Credential Combos", f"https://leakcheck.io/search?query={email}"),
        ("Intelligence X (intelx)", "Darkweb Dumps & Pastes", f"https://intelx.io/?s={email}"),
        ("BreachDirectory", "Hash & Password Directory", "https://breachdirectory.org/"),
        ("Snusbase", "Indexed Historical Leaks", "https://snusbase.com/search")
    ]

    for name, stype, link in engines:
        table.add_row(name, stype, link)
        results["services"].append({"name": name, "type": stype, "link": link})

    console.print(table)
    return results
