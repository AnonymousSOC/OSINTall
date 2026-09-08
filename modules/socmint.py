#!/usr/bin/env python3
"""
OSINTALL - Identity, Usernames & Social Media (SOCMINT) Module (Enhanced)
Covers: Multi-Platform Username Scanner with False-Positive Mitigation,
Email Validation, MX Records, Gravatar Profile Detection, Infostealer Breach Correlation,
and Kali Linux Sherlock / Holehe Tool Wrappers.
"""

import re
import hashlib
import subprocess
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, load_config, get_requests_session, is_tool_available
)

# Verified platforms with false-positive mitigation signatures
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "check": "status_code", "valid": 200},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check": "status_code", "valid": 200},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "check": "status_code", "valid": 200},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{}/", "check": "status_code", "valid": 200},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/about.json", "check": "json_key", "key": "data"},
    {"name": "Twitter / X (Syndication)", "url": "https://syndication.twitter.com/srv/timeline-profile/screen-name/{}", "check": "status_code", "valid": 200},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "response_text", "not_found": "If you have <strong>Telegram</strong>, you can contact"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check": "response_text", "not_found": "The specified profile could not be found."},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": "response_text", "not_found": "No such user."},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": "status_code", "valid": 200},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "status_code", "valid": 200},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "check": "status_code", "valid": 200},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": "response_text", "not_found": "This page isn't available"},
    {"name": "Twitch", "url": "https://m.twitch.tv/{}", "check": "status_code", "valid": 200},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "status_code", "valid": 200},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status_code", "valid": 200},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "status_code", "valid": 200},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "check": "status_code", "valid": 200},
    {"name": "Chess.com", "url": "https://api.chess.com/pub/player/{}", "check": "status_code", "valid": 200},
    {"name": "Lichess", "url": "https://lichess.org/api/user/{}", "check": "status_code", "valid": 200},
    {"name": "BuyMeACoffee", "url": "https://www.buymeacoffee.com/{}", "check": "status_code", "valid": 200},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status_code", "valid": 200},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "check": "status_code", "valid": 200},
    {"name": "About.me", "url": "https://about.me/{}", "check": "status_code", "valid": 200},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}/", "check": "status_code", "valid": 200},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "check": "status_code", "valid": 200},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "check": "status_code", "valid": 200},
    {"name": "Replit", "url": "https://replit.com/@{}", "check": "status_code", "valid": 200},
    {"name": "Codecademy", "url": "https://www.codecademy.com/profiles/{}", "check": "status_code", "valid": 200},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "check": "status_code", "valid": 200},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{}", "check": "status_code", "valid": 200},
    {"name": "HackTheBox", "url": "https://forum.hackthebox.com/u/{}/summary", "check": "status_code", "valid": 200},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "check": "status_code", "valid": 200},
    {"name": "Substack", "url": "https://{}.substack.com", "check": "status_code", "valid": 200},
    {"name": "TradingView", "url": "https://www.tradingview.com/u/{}/", "check": "status_code", "valid": 200},
    {"name": "Instructables", "url": "https://www.instructables.com/member/{}/", "check": "status_code", "valid": 200},
    {"name": "Behance", "url": "https://www.behance.net/{}", "check": "status_code", "valid": 200},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "check": "status_code", "valid": 200},
    {"name": "ProductHunt", "url": "https://www.producthunt.com/@{}", "check": "status_code", "valid": 200}
]

def check_single_platform(platform: dict, username: str, session: requests.Session, timeout: int = 6) -> dict:
    """Checks if a username exists on a single platform with false-positive handling."""
    url = platform["url"].format(username)
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        
        # 1. JSON structure check
        if platform["check"] == "json_key":
            if resp.status_code == 200:
                data = resp.json()
                if platform.get("key") in data:
                    return {"platform": platform["name"], "url": url, "exists": True}
            return {"platform": platform["name"], "url": url, "exists": False}

        # 2. Text-exclusion check
        elif platform["check"] == "response_text":
            not_found = platform.get("not_found", "")
            if resp.status_code == 200 and not_found not in resp.text:
                return {"platform": platform["name"], "url": url, "exists": True}
            return {"platform": platform["name"], "url": url, "exists": False}

        # 3. Status code check
        elif platform["check"] == "status_code":
            if resp.status_code == platform.get("valid", 200):
                # Avoid redirecting to generic login / root domain
                if resp.url.rstrip("/") != url.rstrip("/"):
                    if "login" in resp.url.lower() or "signin" in resp.url.lower():
                        return {"platform": platform["name"], "url": url, "exists": False}
                return {"platform": platform["name"], "url": url, "exists": True}
                
    except Exception:
        pass
    return {"platform": platform["name"], "url": url, "exists": False}

def scan_username(username: str) -> dict:
    """Scans verified platforms concurrently for username presence."""
    print_section(f"SOCMINT: Username Search ({username})", icon="👤")
    print_info(f"Cross-checking [bold cyan]{username}[/] across {len(PLATFORMS)} high-value platforms...")

    session = get_requests_session()
    found = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Scanning target profiles...", total=len(PLATFORMS))
        
        with ThreadPoolExecutor(max_workers=25) as executor:
            future_to_plat = {
                executor.submit(check_single_platform, plat, username, session): plat
                for plat in PLATFORMS
            }
            for future in as_completed(future_to_plat):
                res = future.result()
                if res.get("exists"):
                    found.append(res)
                progress.advance(task)

    # Sort results alphabetically
    found = sorted(found, key=lambda x: x["platform"])

    if found:
        print_success(f"Discovered [bold green]{len(found)}[/] active profile(s) for '{username}':")
        table = Table(title=f"Active Social & Developer Profiles for {username}", border_style="green")
        table.add_column("Platform", style="bold yellow", width=22)
        table.add_column("Profile URL", style="underline cyan")
        for item in found:
            table.add_row(item["platform"], item["url"])
        console.print(table)
    else:
        print_warning(f"No active profiles identified for '{username}' across built-in platforms.")

    # Check for Kali Linux Sherlock or Maigret
    if is_tool_available("sherlock"):
        print_info("Found [bold green]sherlock[/] on Kali! You can run extended deep search:")
        console.print(f"[bold cyan]sherlock {username} --timeout 5 --print-found[/]")
    if is_tool_available("maigret"):
        print_info("Found [bold green]maigret[/] on Kali! Run:")
        console.print(f"[bold cyan]maigret {username} -a[/]")

    # External SOCMINT Correlation Engines
    links_table = Table(title="Advanced SOCMINT & Correlation Engines", border_style="yellow")
    links_table.add_column("Tool / Platform", style="bold cyan", width=22)
    links_table.add_column("Query Link / Info", style="underline blue")
    links_table.add_row("WhatsMyName (600+ Sites)", f"https://whatsmyname.app/?q={username}")
    links_table.add_row("SocialBlade Analytics", f"https://socialblade.com/search/search?query={username}")
    links_table.add_row("Namechk Domain/User", f"https://namechk.com/")
    console.print(links_table)

    return {"username": username, "found_profiles": found, "total_found": len(found)}

def check_gravatar(email: str) -> dict:
    """Checks if a Gravatar profile avatar exists for the email hash."""
    email_clean = email.strip().lower()
    email_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    session = get_requests_session()
    try:
        resp = session.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            return {
                "exists": True,
                "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}",
                "profile_url": f"https://en.gravatar.com/{email_hash}.json"
            }
    except Exception:
        pass
    return {"exists": False}

def analyze_email(email: str) -> dict:
    """Analyzes email structure, domain MX records, Gravatar, and infostealer exposure."""
    print_section(f"SOCMINT: Email Intelligence ({email})", icon="✉️")
    email = email.strip().lower()
    
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        print_error(f"Invalid email format: {email}")
        return {"email": email, "valid_format": False}

    username, domain = email.split("@", 1)
    print_info(f"Target Email:     [bold cyan]{email}[/]")
    print_info(f"Local Identifier: [bold yellow]{username}[/]")
    print_info(f"Mail Domain:      [bold green]{domain}[/]")

    results = {
        "email": email,
        "username": username,
        "domain": domain,
        "valid_format": True,
        "mx_records": [],
        "gravatar": {},
        "infostealer_exposure": {}
    }

    # 1. Check MX records
    try:
        answers = dns.resolver.resolve(domain, "MX")
        results["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
        print_success(f"Domain MX Records: {', '.join(results['mx_records'])}")
    except Exception as e:
        print_warning(f"MX Record check failed or none found: {e}")

    # 2. Check Gravatar presence
    results["gravatar"] = check_gravatar(email)
    if results["gravatar"].get("exists"):
        print_success(f"Gravatar Profile Found: [underline cyan]{results['gravatar']['avatar_url']}[/]")
    else:
        print_info("Gravatar Profile: None detected")

    # 3. Check Infostealer Compromises via Hudson Rock Cavalier API
    from modules.breach_intel import check_infostealer_exposure
    results["infostealer_exposure"] = check_infostealer_exposure(email)

    # 4. Kali Tool check (Holehe)
    if is_tool_available("holehe"):
        print_info("Found [bold green]holehe[/] on Kali! You can run live account verification:")
        console.print(f"[bold cyan]holehe {email}[/]")

    # 5. External Email Intelligence links
    table = Table(title="Email Verification & Pattern Finders", border_style="magenta")
    table.add_column("Service", style="bold yellow", width=22)
    table.add_column("Action / Direct Link", style="white")
    table.add_row("Hunter.io Search", f"https://hunter.io/try/search/{domain}")
    table.add_row("Epieos Google Recon", f"https://epieos.com/?q={email}")
    table.add_row("EmailRep.io Reputation", f"https://emailrep.io/{email}")
    table.add_row("Hudson Rock Cavalier", f"https://cavalier.hudsonrock.com/")
    console.print(table)

    return results
