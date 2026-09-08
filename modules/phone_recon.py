#!/usr/bin/env python3
"""
OSINTALL - Phone Number Intelligence (TELINT) Module
Covers: International Number Parsing, E.164 Formatting, Country / Carrier Detection,
Messaging App Profiles (WhatsApp / Telegram / Viber), and Online Reputation Lookups.
"""

import re
import requests
from rich.table import Table
from rich.panel import Panel
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, is_tool_available, get_requests_session
)

# Comprehensive International Country Calling Codes
COUNTRY_CALLING_CODES = [
    ("1", "US/CA", "United States / Canada"),
    ("7", "RU/KZ", "Russia / Kazakhstan"),
    ("20", "EG", "Egypt"),
    ("27", "ZA", "South Africa"),
    ("30", "GR", "Greece"),
    ("31", "NL", "Netherlands"),
    ("32", "BE", "Belgium"),
    ("33", "FR", "France"),
    ("34", "ES", "Spain"),
    ("36", "HU", "Hungary"),
    ("39", "IT", "Italy"),
    ("40", "RO", "Romania"),
    ("41", "CH", "Switzerland"),
    ("43", "AT", "Austria"),
    ("44", "GB", "United Kingdom"),
    ("45", "DK", "Denmark"),
    ("46", "SE", "Sweden"),
    ("47", "NO", "Norway"),
    ("48", "PL", "Poland"),
    ("49", "DE", "Germany"),
    ("52", "MX", "Mexico"),
    ("54", "AR", "Argentina"),
    ("55", "BR", "Brazil"),
    ("60", "MY", "Malaysia"),
    ("61", "AU", "Australia"),
    ("62", "ID", "Indonesia"),
    ("63", "PH", "Philippines"),
    ("64", "NZ", "New Zealand"),
    ("65", "SG", "Singapore"),
    ("66", "TH", "Thailand"),
    ("81", "JP", "Japan"),
    ("82", "KR", "South Korea"),
    ("84", "VN", "Vietnam"),
    ("86", "CN", "China"),
    ("90", "TR", "Turkey"),
    ("91", "IN", "India"),
    ("92", "PK", "Pakistan"),
    ("94", "LK", "Sri Lanka"),
    ("95", "MM", "Myanmar"),
    ("98", "IR", "Iran"),
    ("212", "MA", "Morocco"),
    ("234", "NG", "Nigeria"),
    ("254", "KE", "Kenya"),
    ("351", "PT", "Portugal"),
    ("353", "IE", "Ireland"),
    ("358", "FI", "Finland"),
    ("380", "UA", "Ukraine"),
    ("971", "AE", "United Arab Emirates"),
    ("972", "IL", "Israel"),
    ("966", "SA", "Saudi Arabia")
]

def parse_phone_number(raw_input: str) -> dict:
    """Parses raw telephone input into international format and country data."""
    # Normalize by stripping spaces, hyphens, parenthesis, dots
    digits_only = re.sub(r"[^\d+]", "", raw_input.strip())
    if digits_only.startswith("00"):
        digits_only = "+" + digits_only[2:]
    elif not digits_only.startswith("+"):
        digits_only = "+" + digits_only

    pure_digits = digits_only.lstrip("+")
    
    # Identify Country Code
    country_code = "Unknown"
    country_iso = "Unknown"
    country_name = "Unknown"
    national_number = pure_digits

    # Match longest prefix first
    for code, iso, name in sorted(COUNTRY_CALLING_CODES, key=lambda x: len(x[0]), reverse=True):
        if pure_digits.startswith(code):
            country_code = code
            country_iso = iso
            country_name = name
            national_number = pure_digits[len(code):]
            break

    # Format styles
    e164 = f"+{pure_digits}"
    intl_fmt = f"+{country_code} {national_number}" if country_code != "Unknown" else e164
    rfc3966 = f"tel:{e164}"

    # Line type heuristics
    line_type = "Mobile / Cellular or Fixed"
    if country_code == "1":
        # Toll-free in US/CA: 800, 888, 877, 866, 855, 844, 833
        if national_number[:3] in ["800", "888", "877", "866", "855", "844", "833"]:
            line_type = "Toll-Free"
    elif country_code == "44":
        if national_number.startswith("7"):
            line_type = "Mobile / Cellular"
        elif national_number.startswith("1") or national_number.startswith("2"):
            line_type = "Landline / Geographic"

    return {
        "raw": raw_input,
        "pure_digits": pure_digits,
        "e164": e164,
        "international_format": intl_fmt,
        "rfc3966": rfc3966,
        "country_code": country_code,
        "country_iso": country_iso,
        "country_name": country_name,
        "national_number": national_number,
        "line_type": line_type
    }

def scan_phone_number(phone_input: str) -> dict:
    """Main telephone intelligence orchestrator."""
    print_section(f"TELINT: Phone Number Reconnaissance ({phone_input})", icon="📱")
    
    data = parse_phone_number(phone_input)
    if len(data["pure_digits"]) < 7 or len(data["pure_digits"]) > 16:
        print_error(f"Invalid phone number length: {phone_input} ({len(data['pure_digits'])} digits)")
        return {"error": "Invalid length", "raw": phone_input}

    print_info(f"Target Number:       [bold cyan]{data['e164']}[/]")
    print_info(f"Detected Country:    [bold yellow]{data['country_name']} ({data['country_iso']})[/] [dim](+{data['country_code']})[/dim]")
    print_info(f"National Identifier: [bold white]{data['national_number']}[/]")
    print_info(f"Estimated Type:      [bold green]{data['line_type']}[/]")

    # 1. Format details panel
    fmt_panel = (
        f"[bold cyan]E.164 Format:[/]        {data['e164']}\n"
        f"[bold cyan]International:[/]       {data['international_format']}\n"
        f"[bold cyan]RFC 3966 URI:[/]        {data['rfc3966']}\n"
        f"[bold cyan]Country & Dial Code:[/] {data['country_name']} (+{data['country_code']})\n"
        f"[bold cyan]Line Type Indicator:[/] {data['line_type']}"
    )
    console.print(Panel(fmt_panel, title="[bold yellow]📞 Telephony Standards & Formatting[/]", border_style="yellow"))

    # 2. Messaging App Footprints & Direct Links
    wa_link = f"https://wa.me/{data['pure_digits']}"
    tg_link = f"https://t.me/+{data['pure_digits']}"
    viber_link = f"viber://chat?number=%2B{data['pure_digits']}"
    truecaller_link = f"https://www.truecaller.com/search/{data['country_iso'].lower()}/{data['national_number']}"
    syncme_link = f"https://sync.me/search/?number={data['e164']}"
    numverify_link = f"https://numverify.com/"
    freecarrier_link = f"https://freecarrierlookup.com/"

    data["messaging_links"] = {
        "whatsapp": wa_link,
        "telegram": tg_link,
        "viber": viber_link
    }
    data["reputation_links"] = {
        "truecaller": truecaller_link,
        "syncme": syncme_link,
        "numverify": numverify_link,
        "freecarrier": freecarrier_link
    }

    # Messaging Profiles Table
    msg_table = Table(title="Messaging Apps & Social Footprints", border_style="green")
    msg_table.add_column("Service", style="bold green", width=20)
    msg_table.add_column("Direct Profile / Chat Link", style="underline cyan")
    msg_table.add_row("WhatsApp Direct", wa_link)
    msg_table.add_row("Telegram Direct", tg_link)
    msg_table.add_row("Viber Chat", viber_link)
    console.print(msg_table)

    # Telecom & Caller ID Directories
    dir_table = Table(title="Caller ID & Carrier Lookup Engines", border_style="cyan")
    dir_table.add_column("Directory / Engine", style="bold yellow", width=24)
    dir_table.add_column("Capability / Search Link", style="white")
    dir_table.add_row("Truecaller Directory", truecaller_link)
    dir_table.add_row("Sync.me Caller ID", syncme_link)
    dir_table.add_row("Free Carrier Lookup", freecarrier_link)
    dir_table.add_row("NumVerify API Demo", numverify_link)
    console.print(dir_table)

    # 3. Check Kali PhoneInfoga tool
    if is_tool_available("phoneinfoga"):
        print_info("Detected [bold green]phoneinfoga[/] installed on Kali Linux! Run:")
        console.print(f"[bold cyan]phoneinfoga scan -n {data['e164']}[/]")

    return data
