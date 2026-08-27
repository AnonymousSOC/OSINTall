#!/usr/bin/env python3
"""
OSINTALL - Identity, Usernames & Social Media (SOCMINT) Module
Covers: Multi-Platform Username Scanner (Sherlock/WhatsMyName style), Email Pattern Finder & Validator,
Holehe registration checker, Hunter.io / Clearbit links, and SocialBlade / TweetDeck analytics.
"""

import re
import socket
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error, load_config

PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "check": "status_code", "valid": 200},
    {"name": "Twitter / X", "url": "https://x.com/{}", "check": "status_code", "valid": 200},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "check": "status_code", "valid": 200},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/about.json", "check": "status_code", "valid": 200},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "status_code", "valid": 200},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "response_text", "not_found": "If you have <strong>Telegram</strong>, you can contact"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check": "response_text", "not_found": "The specified profile could not be found."},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "check": "status_code", "valid": 200},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status_code", "valid": 200},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "status_code", "valid": 200},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "check": "status_code", "valid": 200},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "check": "status_code", "valid": 200},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check": "status_code", "valid": 200},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "check": "status_code", "valid": 200},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{}/", "check": "status_code", "valid": 200},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "check": "status_code", "valid": 200},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status_code", "valid": 200},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": "status_code", "valid": 200},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": "response_text", "not_found": "No such user."},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "check": "status_code", "valid": 200},
    {"name": "About.me", "url": "https://about.me/{}", "check": "status_code", "valid": 200},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{}", "check": "status_code", "valid": 200},
    {"name": "Lichess", "url": "https://lichess.org/@/{}", "check": "status_code", "valid": 200},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "status_code", "valid": 200},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}/", "check": "status_code", "valid": 200},
    {"name": "BuyMeACoffee", "url": "https://www.buymeacoffee.com/{}", "check": "status_code", "valid": 200}
]

def check_platform(platform: dict, username: str, timeout: int = 5) -> dict:
    """Checks if a username exists on a single platform."""
    url = platform["url"].format(username)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if platform["check"] == "status_code":
            if resp.status_code == platform.get("valid", 200):
                return {"platform": platform["name"], "url": url, "exists": True}
        elif platform["check"] == "response_text":
            not_found = platform.get("not_found", "")
            if resp.status_code == 200 and not_found not in resp.text:
                return {"platform": platform["name"], "url": url, "exists": True}
    except Exception:
        pass
    return {"platform": platform["name"], "url": url, "exists": False}

def scan_username(username: str) -> dict:
    """Scans all supported platforms concurrently for username presence."""
    print_section(f"SOCMINT: Username Search ({username})", icon="👤")
    print_info(f"Cross-checking [bold cyan]{username}[/] across {len(PLATFORMS)} major platforms...")

    found = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning platforms...", total=len(PLATFORMS))
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_plat = {executor.submit(check_platform, plat, username): plat for plat in PLATFORMS}
            for future in as_completed(future_to_plat):
                res = future.result()
                if res.get("exists"):
                    found.append(res)
                progress.advance(task)

    if found:
        print_success(f"Discovered [bold green]{len(found)}[/] active profile(s) for '{username}':")
        table = Table(title=f"Active Social Profiles for {username}", border_style="green")
        table.add_column("Platform", style="bold yellow", width=15)
        table.add_column("Profile URL", style="underline cyan")
        for item in found:
            table.add_row(item["platform"], item["url"])
        console.print(table)
    else:
        print_warning(f"No profiles identified for '{username}' across default platform list.")

    # External SOCMINT Deep Search Engines
    links_table = Table(title="Advanced SOCMINT & Correlation Engines", border_style="yellow")
    links_table.add_column("Tool / Platform", style="bold cyan", width=20)
    links_table.add_column("Query Link / Info", style="underline blue")
    links_table.add_row("WhatsMyName", f"https://whatsmyname.app/?q={username}")
    links_table.add_row("SocialBlade Analytics", f"https://socialblade.com/search/search?query={username}")
    links_table.add_row("Maigret / Blackbird", "Run locally in Kali: maigret <username> or blackbird -u <username>")
    console.print(links_table)

    return {"username": username, "found_profiles": found}

def analyze_email(email: str) -> dict:
    """Analyzes email structure, domain MX records, and suggests SOCMINT / breach queries."""
    print_section(f"SOCMINT: Email Intelligence ({email})", icon="✉️")
    email = email.strip().lower()
    
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        print_error(f"Invalid email format: {email}")
        return {"email": email, "valid_format": False}

    username, domain = email.split("@", 1)
    print_info(f"Target Email: [bold cyan]{email}[/]")
    print_info(f"Local Part (User): [bold yellow]{username}[/]")
    print_info(f"Domain: [bold green]{domain}[/]")

    # Check MX records
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = [str(r.exchange).rstrip(".") for r in answers]
        print_success(f"Domain MX Records: {', '.join(mx_records)}")
    except Exception as e:
        print_warning(f"MX Record check failed or none found: {e}")

    # Hunter / Clearbit / Holehe links & CLI check
    table = Table(title="Email Verification & Pattern Finders", border_style="magenta")
    table.add_column("Service", style="bold yellow", width=18)
    table.add_column("Action / Direct Link", style="white")
    table.add_row("Hunter.io Domain Search", f"https://hunter.io/try/search/{domain}")
    table.add_row("Clearbit Connect", f"https://clearbit.com/platform/enrichment")
    table.add_row("Anymail Finder", f"https://anymailfinder.com/search/{domain}")
    table.add_row("Holehe CLI Check", f"Run in Kali: holehe {email}")
    table.add_row("Epieos Google Account Recon", f"https://epieos.com/?q={email}")
    console.print(table)

    # Check if holehe is installed in Kali
    if subprocess.run(["which", "holehe"], capture_output=True).returncode == 0:
        print_info("Found [bold green]holehe[/] installed on Kali! You can run:")
        console.print(f"[bold cyan]holehe {email}[/]")

    return {
        "email": email,
        "username": username,
        "domain": domain,
        "mx_records": mx_records
    }
